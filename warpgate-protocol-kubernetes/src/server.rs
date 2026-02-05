use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::{self, Engine as _};
use futures::{StreamExt, TryStreamExt};
use poem::listener::{Acceptor, Listener};
use poem::web::websocket::WebSocket;
use poem::web::{Data, LocalAddr, Path, RemoteAddr};
use poem::{handler, Addr, Body, EndpointExt, IntoResponse, Request, Response, Route, Server};
use regex::Regex;
use reqwest_websocket::Upgrade;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, ServerConfig, SignatureScheme};
use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::server::TlsStream;
use tokio_tungstenite::tungstenite;
use tracing::*;
use url::Url;
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::helpers::websocket::pump_websocket;
use warpgate_common::{
    ListenEndpoint, SessionId, Target, TargetKubernetesOptions, TargetOptions, User,
};
use warpgate_core::logging::http::{
    get_client_ip, log_request_error, log_request_result, span_for_request,
};
use warpgate_core::recordings::{SessionRecordings, TerminalRecorder, TerminalRecordingStreamId};
use warpgate_core::{AuthStateStore, ConfigProvider, Services, State};
use warpgate_db_entities::CertificateCredential;
use warpgate_tls::{
    SingleCertResolver, TlsCertificateAndPrivateKey, TlsCertificateBundle, TlsPrivateKey,
};

use crate::correlator::RequestCorrelator;
use crate::recording::KubernetesRecorder;

/// Custom client certificate verifier that accepts any client certificate
#[derive(Debug)]
struct AcceptAnyClientCert;

impl ClientCertVerifier for AcceptAnyClientCert {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        // Accept any client certificate - we'll extract and validate it later
        debug!("Client certificate received, accepting for later validation");
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
}

/// Custom TLS acceptor that captures client certificates and embeds them in remote_addr
pub struct CertificateCapturingAcceptor<T> {
    inner: T,
    tls_acceptor: tokio_rustls::TlsAcceptor,
}

impl<T> CertificateCapturingAcceptor<T> {
    pub fn new(inner: T, server_config: ServerConfig) -> Self {
        Self {
            inner,
            tls_acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(server_config)),
        }
    }
}

impl<T> Acceptor for CertificateCapturingAcceptor<T>
where
    T: Acceptor,
{
    type Io = TlsStream<T::Io>;

    fn local_addr(&self) -> Vec<LocalAddr> {
        self.inner.local_addr()
    }

    async fn accept(
        &mut self,
    ) -> std::io::Result<(Self::Io, LocalAddr, RemoteAddr, http::uri::Scheme)> {
        let (stream, local_addr, remote_addr, _) = self.inner.accept().await?;

        // Perform TLS handshake
        let tls_stream = self.tls_acceptor.accept(stream).await?;

        // Extract client certificate from the TLS connection
        let enhanced_remote_addr = if let Some(cert_der) = extract_peer_certificates(&tls_stream) {
            // Serialize certificate as base64 and embed in remote_addr
            let cert_b64 = base64::engine::general_purpose::STANDARD.encode(&cert_der);
            let original_remote_addr_str = match &remote_addr.0 {
                Addr::SocketAddr(addr) => addr.to_string(),
                Addr::Unix(_) => remote_addr.to_string(),
                Addr::Custom(_, _) => "".into(),
            };
            RemoteAddr(Addr::Custom(
                "captured-cert",
                format!("{original_remote_addr_str}|cert:{cert_b64}").into(),
            ))
        } else {
            remote_addr
        };

        Ok((
            tls_stream,
            local_addr,
            enhanced_remote_addr,
            http::uri::Scheme::HTTPS,
        ))
    }
}

/// Extract peer certificates from the TLS stream
fn extract_peer_certificates<T>(tls_stream: &TlsStream<T>) -> Option<Vec<u8>> {
    // Get the TLS connection info
    let (_, tls_conn) = tls_stream.get_ref();

    // Extract peer certificates - this gives us the certificate chain
    if let Some(peer_certs) = tls_conn.peer_certificates() {
        if let Some(end_entity_cert) = peer_certs.first() {
            debug!("Extracted client certificate from TLS stream");
            return Some(end_entity_cert.as_ref().to_vec());
        }
    }

    debug!("No client certificate found in TLS stream");
    None
}

pub async fn run_server(services: Services, address: ListenEndpoint) -> Result<()> {
    let state = services.state.clone();
    let auth_state_store = services.auth_state_store.clone();
    let recordings = services.recordings.clone();

    let correlator = RequestCorrelator::new(&services);

    let app = Route::new()
        .at("/:target_name/*path", handle_api_request)
        .with(poem::middleware::Cors::new())
        .with(CertificateExtractorMiddleware)
        .data(state)
        .data(auth_state_store)
        .data(recordings)
        .data(services.clone())
        .data(correlator);

    info!(?address, "Kubernetes protocol listening");

    let certificate_and_key = {
        let config = services.config.lock().await;
        let certificate_path = services
            .global_params
            .paths_relative_to()
            .join(&config.store.kubernetes.certificate);
        let key_path = services
            .global_params
            .paths_relative_to()
            .join(&config.store.kubernetes.key);

        TlsCertificateAndPrivateKey {
            certificate: TlsCertificateBundle::from_file(&certificate_path)
                .await
                .with_context(|| {
                    format!(
                        "reading TLS certificate from '{}'",
                        certificate_path.display()
                    )
                })?,
            private_key: TlsPrivateKey::from_file(&key_path).await.with_context(|| {
                format!("reading TLS private key from '{}'", key_path.display())
            })?,
        }
    };

    // Create TLS configuration with client certificate verification
    let tls_config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| anyhow::anyhow!("Failed to configure TLS protocol versions: {}", e))?
    .with_client_cert_verifier(Arc::new(AcceptAnyClientCert))
    .with_cert_resolver(Arc::new(SingleCertResolver::new(
        certificate_and_key.clone(),
    )));

    let tcp_acceptor = address.poem_listener().await?.into_acceptor().await?;
    let cert_capturing_acceptor = CertificateCapturingAcceptor::new(tcp_acceptor, tls_config);

    Server::new_with_acceptor(cert_capturing_acceptor)
        .run(app)
        .await
        .context("Kubernetes server error")?;

    Ok(())
}

fn deduce_exec_recording_metadata(target_url: &Url) -> Option<SessionRecordingMetadata> {
    let path = target_url.path();
    let exec_url_regex =
        Regex::new(r"^/api/v1/namespaces/([^/]+)/pods/([^/]+)/(exec|attach)$").unwrap();
    if let Some(captures) = exec_url_regex.captures(path) {
        let namespace = captures.get(1).map_or("unknown", |m| m.as_str()).into();
        let pod = captures.get(2).map_or("unknown", |m| m.as_str()).into();
        let operation = captures.get(3).map_or("unknown", |m| m.as_str());
        let query = target_url.query().unwrap_or_default();
        let parsed_query: HashMap<_, _> = url::form_urlencoded::parse(query.as_bytes()).collect();
        let command = parsed_query
            .get("command")
            .cloned()
            .unwrap_or("unknown".into())
            .into();
        let container = parsed_query
            .get("container")
            .cloned()
            .unwrap_or("unknown".into())
            .into();
        return match operation {
            "exec" => Some(SessionRecordingMetadata::Exec {
                namespace,
                pod,
                container,
                command,
            }),
            "attach" => Some(SessionRecordingMetadata::Attach {
                namespace,
                pod,
                container,
            }),
            _ => None,
        };
    }
    None
}

fn construct_target_url(
    req: &Request,
    path: &str,
    k8s_options: &TargetKubernetesOptions,
) -> Result<Url> {
    let api_path = format!("/{}", path);

    let query = req.uri().query().unwrap_or("");

    Ok(Url::parse(&if query.is_empty() {
        format!("{}{}", k8s_options.cluster_url, api_path)
    } else {
        format!("{}{}?{}", k8s_options.cluster_url, api_path, query)
    })?)
}

#[handler]
#[allow(clippy::too_many_arguments)]
async fn handle_api_request(
    ws: Option<WebSocket>,
    req: &Request,
    Path((target_name, path)): Path<(String, String)>,
    body: Body,
    state: Data<&Arc<Mutex<State>>>,
    _auth_state_store: Data<&Arc<Mutex<AuthStateStore>>>,
    recordings: Data<&Arc<Mutex<SessionRecordings>>>,
    correlator: Data<&Arc<Mutex<RequestCorrelator>>>,
    services: Data<&Services>,
) -> Result<Response, poem::Error> {
    debug!(
        target_name = target_name,
        path_param = ?path,
        full_uri = %req.uri(),
        "Handling Kubernetes API request"
    );

    let (user_info, target) =
        authenticate_and_get_target(req, &target_name, &state, &services).await?;

    let TargetOptions::Kubernetes(k8s_options) = &target.options else {
        return Err(poem::Error::from_string(
            "Invalid target type",
            poem::http::StatusCode::BAD_REQUEST,
        ));
    };

    let handle = correlator
        .lock()
        .await
        .session_for_request(req, &user_info, &target.name)
        .await?;

    let (session_id, log_span) = {
        let handle: tokio::sync::MutexGuard<'_, warpgate_core::WarpgateServerHandle> =
            handle.lock().await;
        handle.set_target(&target).await?;
        handle.set_user_info(user_info.clone()).await?;
        (handle.id(), span_for_request(req, Some(&*handle)).await?)
    };

    async {
        let response = if let Some(ws) = ws {
            _handle_websocket_request_inner(
                ws,
                req,
                k8s_options,
                &path,
                user_info,
                session_id,
                *services,
                *recordings,
            )
            .await
            .map(IntoResponse::into_response)
        } else {
            _handle_request_inner(
                req,
                body,
                k8s_options,
                &path,
                user_info,
                session_id,
                *services,
                *recordings,
            )
            .await
            .map(IntoResponse::into_response)
        };

        let client_ip = get_client_ip(req, Some(*services)).await;
        let response = response.inspect_err(|e| {
            log_request_error(req.method(), req.original_uri(), client_ip.as_deref(), e);
        })?;

        log_request_result(
            req.method(),
            req.original_uri(),
            client_ip.as_deref(),
            &response.status(),
        );

        Ok(response)
    }
    .instrument(log_span)
    .await
}

#[allow(clippy::too_many_arguments)]
async fn _handle_websocket_request_inner(
    ws: WebSocket,
    req: &Request,
    k8s_options: &TargetKubernetesOptions,
    path: &str,
    user_info: AuthStateUserInfo,
    session_id: SessionId,
    services: &Services,
    recordings: &Arc<Mutex<SessionRecordings>>,
) -> anyhow::Result<impl IntoResponse> {
    let mut full_url = construct_target_url(req, path, k8s_options)?;
    if full_url.scheme() == "https" {
        let _ = full_url.set_scheme("wss");
    } else {
        let _ = full_url.set_scheme("ws");
    }

    let client =
        create_authenticated_client(k8s_options, &Some(user_info.username.clone()), services)?
            .http1_only()
            .build()?;

    let (recorder_tx, mut recorder_rx) = mpsc::channel::<Vec<u8>>(1000);
    {
        let enabled = {
            let config = services.config.lock().await;
            config.store.recordings.enable
        };
        if enabled {
            match start_recording_exec(
                &session_id,
                recordings,
                deduce_exec_recording_metadata(&full_url),
            )
            .await
            {
                Err(e) => {
                    error!("Failed to start recording: {}", e);
                }
                Ok(mut recorder) => {
                    tokio::spawn(async move {
                        // let mut recorder_rx = recorder_rx;
                        while let Some(data) = recorder_rx.recv().await {
                            if data.is_empty() {
                                continue;
                            }
                            let msg_type = data[0];
                            let data = (&data[1..]).to_vec();

                            let result = match msg_type {
                                0..2 => {
                                    recorder
                                        .write(
                                            TerminalRecordingStreamId::from_usual_fd_number(
                                                msg_type,
                                            )
                                            .unwrap_or_default(),
                                            &data,
                                        )
                                        .await
                                }
                                4 => {
                                    #[derive(Deserialize)]
                                    struct ResizeData {
                                        #[serde(rename = "Width")]
                                        width: u32,
                                        #[serde(rename = "Height")]
                                        height: u32,
                                    }
                                    if let Ok(resize_data) =
                                        serde_json::from_slice::<ResizeData>(&data)
                                    {
                                        recorder
                                            .write_pty_resize(resize_data.width, resize_data.height)
                                            .await
                                    } else {
                                        continue;
                                    }
                                }
                                _ => continue,
                            };
                            if let Err(e) = result {
                                error!("Failed to write recording item: {}", e);
                            }
                        }
                    });
                }
            }
        }
    };

    let ws_protocol = req
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|h| h.to_str().ok())
        .context("missing Sec-Websocket-Protocol request header")?
        .to_string();

    return Ok(ws
        .protocols(vec![
            "channel.k8s.io",
            "v2.channel.k8s.io",
            "v3.channel.k8s.io",
            "v4.channel.k8s.io",
            "v5.channel.k8s.io",
        ])
        .on_upgrade(|socket| async move {
            let client_response = client
                .get(full_url.clone())
                .upgrade()
                .protocols(vec![ws_protocol])
                .send()
                .await
                .context("sending websocket request to Kubernetes API")?;

            let client_socket = client_response
                .into_websocket()
                .await
                .context("negotiating websocket connection with Kubernetes")?;

            let (client_sink, client_source) = client_socket.split();

            let (server_sink, server_source) = socket.split();
            let server_to_client = {
                let recorder_tx = recorder_tx.clone();
                tokio::spawn(pump_websocket(server_source, client_sink, move |msg| {
                    let recorder_tx = recorder_tx.clone();
                    async move {
                        tracing::debug!("Server: {:?}", msg);
                        if let tungstenite::Message::Binary(data) = &msg {
                            let _ = recorder_tx.send(data.to_vec()).await;
                        }
                        anyhow::Ok(msg)
                    }
                }))
            };

            let client_to_server =
                tokio::spawn(pump_websocket(client_source, server_sink, move |msg| {
                    let recorder_tx = recorder_tx.clone();
                    async move {
                        tracing::debug!("Client: {:?}", msg);
                        if let tungstenite::Message::Binary(data) = &msg {
                            let _ = recorder_tx.send(data.to_vec()).await;
                        }
                        anyhow::Ok(msg)
                    }
                }));

            server_to_client.await??;
            client_to_server.await??;
            debug!("Closing Websocket stream");

            Ok::<(), anyhow::Error>(())
        })
        .into_response());
}

#[allow(clippy::too_many_arguments)]
async fn _handle_request_inner(
    req: &Request,
    body: Body,
    k8s_options: &TargetKubernetesOptions,
    path: &str,
    user_info: AuthStateUserInfo,
    session_id: SessionId,
    services: &Services,
    recordings: &Arc<Mutex<SessionRecordings>>,
) -> anyhow::Result<Response> {
    let client =
        create_authenticated_client(k8s_options, &Some(user_info.username.clone()), services)?
            .build()
            .context("building reqwest client")?;

    debug!(
        "Target Kubernetes options: cluster_url={}, auth={:?}",
        k8s_options.cluster_url,
        match &k8s_options.auth {
            warpgate_common::KubernetesTargetAuth::Token(_) => "Token",
            warpgate_common::KubernetesTargetAuth::Certificate(_) => "Certificate",
        }
    );

    let method = req.method().as_str();
    // Construct the full URL to the Kubernetes API server (without target prefix)
    let full_url =
        construct_target_url(req, path, k8s_options).context("constructing target URL")?;

    // Extract headers
    let mut headers = HashMap::new();
    for (name, value) in req.headers() {
        if let Ok(value_str) = value.to_str() {
            headers.insert(name.to_string(), value_str.to_string());
        }
    }

    // Get request body
    let body_bytes = body.into_bytes().await.context("reading request body")?;

    // Record the request if recording is enabled
    let mut recorder_opt = {
        let enabled = {
            let config = services.config.lock().await;
            config.store.recordings.enable
        };
        if enabled {
            match start_recording_api(&session_id, recordings).await {
                Ok(recorder) => Some(recorder),
                Err(e) => {
                    warn!("Failed to start recording: {}", e);
                    None
                }
            }
        } else {
            None
        }
    };

    // Forward request to Kubernetes API
    let mut request_builder = client.request(
        http::Method::from_bytes(method.as_bytes()).context("request method")?,
        full_url.clone(),
    );

    // Add headers (excluding authorization, host, and content-length as they'll be set by reqwest)
    let mut upstream_headers = HashMap::new();
    for (name, value) in &headers {
        let header_name_lower = name.to_lowercase();
        if ![
            "host",
            "content-length",
            "connection",
            "transfer-encoding",
            "authorization",
        ]
        .contains(&header_name_lower.as_str())
        {
            if let (Ok(header_name), Ok(header_value)) = (
                http::HeaderName::from_bytes(name.as_bytes()),
                http::HeaderValue::from_str(value),
            ) {
                request_builder = request_builder.header(header_name, header_value);
                upstream_headers.insert(name.clone(), value.clone());
            }
        } else {
            debug!(header = name, "Filtering out header from upstream request");
        }
    }

    debug!(
        filtered_headers = ?upstream_headers,
        "Headers being sent to upstream Kubernetes API"
    );

    if !body_bytes.is_empty() {
        request_builder = request_builder.body(body_bytes.to_vec());
    }

    // Debug logging for upstream request
    debug!(
        method = method,
        url = %full_url,
        headers = ?headers,
        body_size = body_bytes.len(),
        "Sending request to upstream Kubernetes API"
    );

    let response = request_builder
        .send()
        .await
        .inspect_err(|e| {
            warn!(
                method = method,
                url = %full_url,
                error = %e,
                "Kubernetes API request failed"
            );
        })
        .context("sending request to Kubernetes API")?;

    let status = response.status();
    let response_headers = response.headers().clone();

    debug!(
        method = method,
        url = %full_url,
        status = %status,
        response_headers = ?response_headers,
        "Received response from upstream Kubernetes API"
    );

    let (response_body, body_for_recording) = {
        // k8s uses streaming chunked responses for watch API
        let transfer_encoding = response_headers
            .get(poem::http::header::TRANSFER_ENCODING)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_lowercase();

        if transfer_encoding == "chunked" {
            (
                Body::from_bytes_stream(
                    response
                        .bytes_stream()
                        .map_err(|e| std::io::Error::other(e)),
                ),
                None,
            )
        } else {
            let bytes = response
                .bytes()
                .await
                .context("reading kubernetes response")?;

            (Body::from_bytes(bytes.clone()), Some(bytes.to_vec()))
        }
    };

    // Record the response
    if let Some(ref mut recorder) = recorder_opt {
        if let Err(e) = recorder
            .record_response(
                method,
                &full_url.to_string(),
                headers,
                &body_bytes,
                status.as_u16(),
                body_for_recording.unwrap_or_default().as_ref(),
            )
            .await
        {
            warn!("Failed to record Kubernetes response: {}", e);
        }
    }

    let mut poem_response = Response::builder().status(status);

    // Copy response headers
    for (name, value) in response_headers.iter() {
        if let Ok(poem_name) = poem::http::HeaderName::from_bytes(name.as_str().as_bytes()) {
            if let Ok(poem_value) = poem::http::HeaderValue::from_bytes(value.as_bytes()) {
                poem_response = poem_response.header(poem_name, poem_value);
            }
        }
    }

    Ok(poem_response.body(response_body))
}

async fn authenticate_and_get_target(
    req: &Request,
    target_name: &str,
    _state: &Arc<Mutex<State>>,
    services: &Services,
) -> poem::Result<(AuthStateUserInfo, Target)> {
    use RequestCertificateExt; // Import the trait for certificate extraction

    // Check for Bearer token authentication (API tokens)
    if let Some(auth_header) = req.headers().get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                let mut config_provider = services.config_provider.lock().await;
                if let Ok(Some(user)) = config_provider.validate_api_token(token).await {
                    // Look up the specific target by name from the URL
                    let targets = config_provider
                        .list_targets()
                        .await
                        .context("listing targets")?;

                    // Find the target with the specified name
                    for target in targets {
                        if target.name == target_name
                            && matches!(target.options, TargetOptions::Kubernetes(_))
                        {
                            if config_provider
                                .authorize_target(&user.username, &target.name)
                                .await
                                .unwrap_or(false)
                            {
                                return Ok(((&user).into(), target));
                            } else {
                                return Err(poem::Error::from_string(
                                    format!("Access denied to target: {}", target_name),
                                    poem::http::StatusCode::FORBIDDEN,
                                ));
                            }
                        }
                    }

                    return Err(poem::Error::from_string(
                        format!("Kubernetes target not found: {}", target_name),
                        poem::http::StatusCode::NOT_FOUND,
                    ));
                }
            }
        }
    }

    // Check for client certificate authentication
    // Use certificate extracted by middleware if present
    if let Some(client_cert) = req.client_certificate() {
        debug!("Found client certificate from middleware, validating against database");

        match validate_client_certificate(&client_cert.der_bytes, services).await {
            Ok(Some(user_info)) => {
                // Look up the specific target by name from the URL
                let mut config_provider = services.config_provider.lock().await;
                let targets = config_provider
                    .list_targets()
                    .await
                    .context("listing targets")?;

                // Find the target with the specified name
                for target in targets {
                    if target.name == target_name
                        && matches!(target.options, TargetOptions::Kubernetes(_))
                    {
                        if config_provider
                            .authorize_target(&user_info.username, &target.name)
                            .await
                            .unwrap_or(false)
                        {
                            return Ok((user_info, target));
                        } else {
                            return Err(poem::Error::from_string(
                                format!("Access denied to target: {}", target_name),
                                poem::http::StatusCode::FORBIDDEN,
                            ));
                        }
                    }
                }

                return Err(poem::Error::from_string(
                    format!("Kubernetes target not found: {}", target_name),
                    poem::http::StatusCode::NOT_FOUND,
                ));
            }
            Ok(None) => {
                debug!("Client certificate provided but not found in database");
            }
            Err(e) => {
                warn!(error = %e, "Error validating client certificate");
            }
        }
    } else {
        debug!("No client certificate provided in TLS connection");
    }

    // Return unauthorized if no valid authentication found
    Err(poem::Error::from_string(
        "Unauthorized: Please provide either a valid Bearer token or a client certificate",
        poem::http::StatusCode::UNAUTHORIZED,
    ))
}

fn create_authenticated_client(
    k8s_options: &TargetKubernetesOptions,
    _auth_user: &Option<String>,
    _services: &Services,
) -> anyhow::Result<reqwest::ClientBuilder> {
    debug!(
        server_url = ?k8s_options.cluster_url,
        auth_kind = ?k8s_options.auth,
        tls_config = ?k8s_options.tls,
        "Creating authenticated Kubernetes client"
    );

    // Create HTTP client with the configuration
    let mut client_builder = reqwest::Client::builder();

    if !k8s_options.tls.verify {
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }

    match &k8s_options.auth {
        warpgate_common::KubernetesTargetAuth::Token(auth) => {
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&format!(
                    "Bearer {}",
                    auth.token.expose_secret()
                ))
                .context("setting Authorization header")?,
            );
            client_builder = client_builder.default_headers(headers);
        }
        warpgate_common::KubernetesTargetAuth::Certificate(auth) => {
            // Expect PEM certificate and PEM private key in the auth config
            // Combine into a single PEM bundle for reqwest::Identity
            let cert_pem = auth.certificate.expose_secret();
            let key_pem = auth.private_key.expose_secret();
            let mut pem_bundle = String::new();
            pem_bundle.push_str(cert_pem);
            if !pem_bundle.ends_with('\n') {
                pem_bundle.push('\n');
            }
            pem_bundle.push_str(key_pem);
            if !pem_bundle.ends_with('\n') {
                pem_bundle.push('\n');
            }

            info!("Configuring Kubernetes client with mTLS (certificate auth)");
            let identity = reqwest::Identity::from_pem(pem_bundle.as_bytes())
                .context("Invalid client certificate/key for Kubernetes upstream")?;
            client_builder = client_builder.identity(identity);
        }
    }

    Ok(client_builder)
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
enum SessionRecordingMetadata {
    #[serde(rename = "kubernetes-api")]
    Api,
    #[serde(rename = "kubernetes-exec")]
    Exec {
        namespace: String,
        pod: String,
        container: String,
        command: String,
    },
    #[serde(rename = "kubernetes-attach")]
    Attach {
        namespace: String,
        pod: String,
        container: String,
    },
}

async fn start_recording_api(
    session_id: &SessionId,
    recordings: &Arc<Mutex<SessionRecordings>>,
) -> anyhow::Result<KubernetesRecorder> {
    let mut recordings = recordings.lock().await;
    Ok(recordings
        .start::<KubernetesRecorder, _>(
            session_id,
            Some("api".into()),
            SessionRecordingMetadata::Api,
        )
        .await
        .context("starting recording")?)
}

async fn start_recording_exec(
    session_id: &SessionId,
    recordings: &Arc<Mutex<SessionRecordings>>,
    metadata: Option<SessionRecordingMetadata>,
) -> anyhow::Result<TerminalRecorder> {
    let mut recordings = recordings.lock().await;
    recordings
        .start::<TerminalRecorder, _>(session_id, None, metadata)
        .await
        .context("starting recording")
}

// Helper function to validate client certificate against database
async fn validate_client_certificate(
    cert_der: &[u8],
    services: &Services,
) -> anyhow::Result<Option<AuthStateUserInfo>> {
    // Convert DER to PEM format for comparison
    let cert_pem = der_to_pem(cert_der)?;

    let db = services.db.lock().await;

    // Find all certificate credentials and match against the provided certificate
    let cert_credentials = CertificateCredential::Entity::find()
        .find_with_related(warpgate_db_entities::User::Entity)
        .all(&*db)
        .await?;

    for (cert_credential, users) in cert_credentials {
        if let Some(user) = users.into_iter().next() {
            // Normalize both certificates for comparison
            let stored_cert = normalize_certificate_pem(&cert_credential.certificate_pem);
            let provided_cert = normalize_certificate_pem(&cert_pem);

            if stored_cert == provided_cert {
                debug!(
                    user = user.username,
                    cert_label = cert_credential.label,
                    "Client certificate validated for user"
                );

                // Update last_used timestamp
                let mut active_model: CertificateCredential::ActiveModel = cert_credential.into();
                active_model.last_used = Set(Some(chrono::Utc::now()));
                if let Err(e) = active_model.update(&*db).await {
                    warn!("Failed to update certificate last_used timestamp: {}", e);
                }

                return Ok(Some((&User::try_from(user)?).into()));
            }
        }
    }

    Ok(None)
}

fn der_to_pem(der_bytes: &[u8]) -> Result<String, anyhow::Error> {
    use base64::engine::general_purpose;
    use base64::Engine as _;
    let cert_b64 = general_purpose::STANDARD.encode(der_bytes);
    let cert_lines: Vec<String> = cert_b64
        .chars()
        .collect::<Vec<char>>()
        .chunks(64)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect();

    Ok(format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
        cert_lines.join("\n")
    ))
}

fn normalize_certificate_pem(pem: &str) -> String {
    pem.lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<&str>>()
        .join("")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect()
}

/// Certificate data extracted from client TLS connection
#[derive(Debug, Clone)]
pub struct ClientCertificate {
    pub der_bytes: Vec<u8>,
}

/// Middleware that extracts client certificates from enhanced remote_addr and stores them in request extensions
pub struct CertificateExtractorMiddleware;

impl<E> poem::Middleware<E> for CertificateExtractorMiddleware
where
    E: poem::Endpoint,
{
    type Output = CertificateExtractorEndpoint<E>;

    fn transform(&self, ep: E) -> Self::Output {
        CertificateExtractorEndpoint { inner: ep }
    }
}

pub struct CertificateExtractorEndpoint<E> {
    inner: E,
}

impl<E> poem::Endpoint for CertificateExtractorEndpoint<E>
where
    E: poem::Endpoint,
{
    type Output = E::Output;
    async fn call(&self, mut req: poem::Request) -> poem::Result<Self::Output> {
        // Extract certificate from enhanced remote_addr if present
        if let RemoteAddr(Addr::Custom("captured-cert", value)) = req.remote_addr() {
            if let Some(cert_part) = value.split("|cert:").nth(1) {
                // Decode the base64 certificate
                match base64::engine::general_purpose::STANDARD.decode(cert_part) {
                    Ok(cert_der) => {
                        debug!(
                        "Middleware: Successfully extracted client certificate from remote_addr"
                    );

                        let client_cert = ClientCertificate {
                            der_bytes: cert_der,
                        };

                        // Store certificate in request extensions for later access
                        req.extensions_mut().insert(client_cert);
                        debug!("Middleware: Client certificate stored in request extensions");
                    }
                    Err(e) => {
                        warn!(
                            "Middleware: Failed to decode client certificate from remote_addr: {}",
                            e
                        );
                    }
                }
            }
        } else {
            debug!("Middleware: No client certificate found in remote_addr");
        }

        // Continue with the request
        self.inner.call(req).await
    }
}

/// Helper trait to easily extract client certificate from request
pub trait RequestCertificateExt {
    /// Get the client certificate from request extensions, if present
    fn client_certificate(&self) -> Option<&ClientCertificate>;
}

impl RequestCertificateExt for poem::Request {
    fn client_certificate(&self) -> Option<&ClientCertificate> {
        self.extensions().get::<ClientCertificate>()
    }
}

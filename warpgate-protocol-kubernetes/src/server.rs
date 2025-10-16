use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::{self, Engine as _};
use futures::{SinkExt, StreamExt};
use poem::listener::{Acceptor, Listener};
use poem::web::websocket::{Message, WebSocket};
use poem::web::{Data, LocalAddr, Path, RemoteAddr};
use poem::{get, handler, Addr, Body, EndpointExt, IntoResponse, Request, Response, Route, Server};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, ServerConfig, SignatureScheme};
use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use tokio::sync::Mutex;
use tokio_rustls::server::TlsStream;
use tracing::*;
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{
    ListenEndpoint, SessionId, SingleCertResolver, Target, TargetKubernetesOptions, TargetOptions,
    TlsCertificateAndPrivateKey, TlsCertificateBundle, TlsPrivateKey, User,
};
use warpgate_core::recordings::SessionRecordings;
use warpgate_core::{AuthStateStore, ConfigProvider, Services, State};
use warpgate_db_entities::CertificateCredential;

use crate::client::create_kube_config;
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
            RemoteAddr(Addr::Custom(
                "captured-cert",
                format!("{}|cert:{}", remote_addr.0, cert_b64).into(),
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
        .at("/:target_name/ws", get(handle_websocket))
        .with(poem::middleware::Cors::new())
        .with(CertificateExtractorMiddleware)
        .data(state)
        .data(auth_state_store)
        .data(recordings)
        .data(services.clone())
        .data(correlator)
        .before(|req: Request| async move {
            info!("Received Kubernetes API request: {}", req.uri());
            Ok(req)
        });

    info!(?address, "Kubernetes protocol listening");

    let certificate_and_key = {
        let config = services.config.lock().await;
        let certificate_path = config
            .paths_relative_to
            .join(&config.store.kubernetes.certificate);
        let key_path = config.paths_relative_to.join(&config.store.kubernetes.key);

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
    // Create our custom certificate-capturing acceptor
    let tcp_acceptor = address.poem_listener().await?.into_acceptor().await?;
    let cert_capturing_acceptor = CertificateCapturingAcceptor::new(tcp_acceptor, tls_config);

    Server::new_with_acceptor(cert_capturing_acceptor)
        .run(app)
        .await
        .context("Kubernetes server error")?;

    Ok(())
}

#[handler]
async fn handle_api_request(
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

    let client =
        create_authenticated_client(&k8s_options, &Some(user_info.username.clone()), &services)
            .await?;

    info!(
        "Target Kubernetes options: cluster_url={}, auth={:?}",
        k8s_options.cluster_url,
        match &k8s_options.auth {
            warpgate_common::KubernetesTargetAuth::Token(_) => "Token",
            warpgate_common::KubernetesTargetAuth::Certificate(_) => "Certificate",
        }
    );

    let method = req.method().as_str();

    // Extract the API path by removing the target name prefix from the original URI
    let original_path = req.uri().path();
    let api_path = if let Some(stripped) = original_path.strip_prefix(&format!("/{}/", target_name))
    {
        format!("/{}", stripped)
    } else if original_path == format!("/{}", target_name) {
        "/".to_string()
    } else {
        // Fallback to the path parameter method
        format!("/{}", path)
    };

    let query = req.uri().query().unwrap_or("");

    // Construct the full URL to the Kubernetes API server (without target prefix)
    let full_url = if query.is_empty() {
        format!("{}{}", k8s_options.cluster_url, api_path)
    } else {
        format!("{}{}?{}", k8s_options.cluster_url, api_path, query)
    };

    debug!(
        target_name = target_name,
        original_path = original_path,
        api_path = api_path,
        cluster_url = k8s_options.cluster_url,
        full_url = full_url,
        "Constructing upstream Kubernetes API URL"
    );

    // Extract headers
    let mut headers = HashMap::new();
    for (name, value) in req.headers() {
        if let Ok(value_str) = value.to_str() {
            headers.insert(name.to_string(), value_str.to_string());
        }
    }

    // Get request body
    let body_bytes = body.into_bytes().await.map_err(|e| {
        poem::Error::from_string(
            format!("Failed to read body: {}", e),
            poem::http::StatusCode::BAD_REQUEST,
        )
    })?;

    let session = correlator
        .lock()
        .await
        .session_for_request(req, &target_name)
        .await?;

    let session_id = {
        let session = session.lock().await;
        session.set_target(&target).await?;
        session.set_user_info(user_info).await?;
        session.id()
    };

    // Record the request if recording is enabled
    let mut recorder_opt = {
        // Check if recording is enabled in the config
        let config = services.config.lock().await;
        if config.store.recordings.enable {
            drop(config);

            match start_recording(&session_id, &recordings).await {
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

    if let Some(ref mut recorder) = recorder_opt {
        if let Err(e) = recorder
            .record_request(method, &full_url, headers.clone(), &body_bytes)
            .await
        {
            warn!("Failed to record Kubernetes request: {}", e);
        }
    }

    // Forward request to Kubernetes API
    let mut request_builder = client.request(
        http::Method::from_bytes(method.as_bytes()).map_err(|e| {
            poem::Error::from_string(
                format!("Invalid method: {}", e),
                poem::http::StatusCode::BAD_REQUEST,
            )
        })?,
        &full_url,
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

    let response = request_builder.send().await.map_err(|e| {
        warn!(
            method = method,
            url = %full_url,
            error = %e,
            "Kubernetes API request failed"
        );
        poem::Error::from_string(
            format!("Kubernetes API error: {}", e),
            poem::http::StatusCode::BAD_GATEWAY,
        )
    })?;

    let status = response.status();
    let response_headers = response.headers().clone();

    debug!(
        method = method,
        url = %full_url,
        status = %status,
        response_headers = ?response_headers,
        "Received response from upstream Kubernetes API"
    );

    let response_body = response.bytes().await.map_err(|e| {
        poem::Error::from_string(
            format!("Failed to read response: {}", e),
            poem::http::StatusCode::BAD_GATEWAY,
        )
    })?;

    // Record the response
    if let Some(ref mut recorder) = recorder_opt {
        if let Err(e) = recorder
            .record_response(
                method,
                &full_url,
                headers,
                &body_bytes,
                status.as_u16(),
                &response_body,
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

    Ok(poem_response.body(response_body.to_vec()))
}

#[handler]
async fn handle_websocket(
    Path(_target_name): Path<String>,
    ws: WebSocket,
    _state: Data<&Arc<Mutex<State>>>,
    _auth_state_store: Data<&Arc<Mutex<AuthStateStore>>>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| async move {
        let (mut sink, mut stream) = socket.split();

        while let Some(msg) = stream.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    // Echo back for now - in a real implementation, this would
                    // establish a WebSocket connection to the Kubernetes API
                    if sink.send(Message::Text(text)).await.is_err() {
                        break;
                    }
                }
                Ok(Message::Binary(data)) => {
                    if sink.send(Message::Binary(data)).await.is_err() {
                        break;
                    }
                }
                Ok(Message::Close(_)) => break,
                Err(_) => break,
                _ => {}
            }
        }
    })
}

async fn authenticate_and_get_target(
    req: &Request,
    target_name: &str,
    _state: &Arc<Mutex<State>>,
    services: &Services,
) -> Result<(AuthStateUserInfo, Target), poem::Error> {
    use RequestCertificateExt; // Import the trait for certificate extraction

    // Check for Bearer token authentication (API tokens)
    if let Some(auth_header) = req.headers().get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                let mut config_provider = services.config_provider.lock().await;
                if let Ok(Some(user)) = config_provider.validate_api_token(token).await {
                    // Look up the specific target by name from the URL
                    let targets = config_provider.list_targets().await.map_err(|e| {
                        poem::Error::from_string(
                            format!("Failed to list targets: {}", e),
                            poem::http::StatusCode::INTERNAL_SERVER_ERROR,
                        )
                    })?;

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
                let targets = config_provider.list_targets().await.map_err(|e| {
                    poem::Error::from_string(
                        format!("Failed to list targets: {}", e),
                        poem::http::StatusCode::INTERNAL_SERVER_ERROR,
                    )
                })?;

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

async fn create_authenticated_client(
    k8s_options: &TargetKubernetesOptions,
    _auth_user: &Option<String>,
    _services: &Services,
) -> Result<reqwest::Client, poem::Error> {
    debug!(
        server_url = ?k8s_options.cluster_url,
        auth_kind = ?k8s_options.auth,
        tls_config = ?k8s_options.tls,
        "Creating authenticated Kubernetes client"
    );

    let config = create_kube_config(k8s_options).await.map_err(|e| {
        warn!(error = %e, "Failed to create kube config");
        poem::Error::from_string(
            format!("Kubernetes config error: {}", e),
            poem::http::StatusCode::BAD_REQUEST,
        )
    })?;

    // Create HTTP client with the configuration
    let mut client_builder = reqwest::Client::builder();

    if config.accept_invalid_certs {
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }

    match &k8s_options.auth {
        warpgate_common::KubernetesTargetAuth::Token(auth) => {
            info!(
            "Setting Kubernetes auth token: {}...",
            &auth.token.expose_secret()[..std::cmp::min(10, auth.token.expose_secret().len())]
        );
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&format!("Bearer {}", auth.token.expose_secret()))
                    .map_err(|e| {
                        poem::Error::from_string(
                            format!("Invalid token: {}", e),
                            poem::http::StatusCode::BAD_REQUEST,
                        )
                    })?,
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
            let identity = reqwest::Identity::from_pem(pem_bundle.as_bytes()).map_err(|e| {
                poem::Error::from_string(
                    format!("Invalid client certificate/key for Kubernetes upstream: {}", e),
                    poem::http::StatusCode::BAD_REQUEST,
                )
            })?;
            client_builder = client_builder.identity(identity);
        }
    }

    client_builder.build().map_err(|e| {
        poem::Error::from_string(
            format!("Failed to create HTTP client: {}", e),
            poem::http::StatusCode::INTERNAL_SERVER_ERROR,
        )
    })
}

async fn start_recording(
    session_id: &SessionId,
    recordings: &Arc<Mutex<SessionRecordings>>,
) -> Result<KubernetesRecorder, poem::Error> {
    let mut recordings = recordings.lock().await;
    recordings
        .start::<KubernetesRecorder>(session_id, "kubernetes-api".to_string())
        .await
        .map_err(|e| {
            poem::Error::from_string(
                format!("Recording error: {}", e),
                poem::http::StatusCode::INTERNAL_SERVER_ERROR,
            )
        })
}

// Helper function to validate client certificate against database
async fn validate_client_certificate(
    cert_der: &[u8],
    services: &Services,
) -> Result<Option<AuthStateUserInfo>, anyhow::Error> {
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
                info!(
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
        let remote_addr = req.remote_addr().to_string();
        if let Some(cert_part) = remote_addr.split("|cert:").nth(1) {
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

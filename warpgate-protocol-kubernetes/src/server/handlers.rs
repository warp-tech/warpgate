use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use futures::{StreamExt, TryStreamExt};
use poem::web::websocket::WebSocket;
use poem::web::{Data, Path};
use poem::{handler, Body, IntoResponse, Request, Response};
use reqwest_websocket::Upgrade;
use serde::Deserialize;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite;
use tracing::*;
use url::Url;
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::helpers::websocket::pump_websocket;
use warpgate_common::{SessionId, TargetKubernetesOptions, TargetOptions};
use warpgate_core::logging::http::{
    get_client_ip, log_request_error, log_request_result, span_for_request,
};
use warpgate_core::recordings::{SessionRecordings, TerminalRecorder, TerminalRecordingStreamId};
use warpgate_core::{Services, State};

use crate::correlator::RequestCorrelator;
use crate::recording::{deduce_exec_recording_metadata, start_recording_api, start_recording_exec};
use crate::server::auth::{authenticate_and_get_target, create_authenticated_client};

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
pub async fn handle_api_request(
    ws: Option<WebSocket>,
    req: &Request,
    Path((target_name, path)): Path<(String, String)>,
    body: Body,
    state: Data<&Arc<Mutex<State>>>,
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
            _handle_normal_request_inner(
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
async fn _handle_normal_request_inner(
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

async fn run_websocket_recording(mut recorder: TerminalRecorder, mut rx: mpsc::Receiver<Vec<u8>>) {
    while let Some(data) = rx.recv().await {
        if data.is_empty() {
            continue;
        }
        let msg_type = data[0];
        let data = (&data[1..]).to_vec();

        let result = match msg_type {
            0..2 => {
                recorder
                    .write(
                        TerminalRecordingStreamId::from_usual_fd_number(msg_type)
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
                if let Ok(resize_data) = serde_json::from_slice::<ResizeData>(&data) {
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

    let (recorder_tx, recorder_rx) = mpsc::channel::<Vec<u8>>(1000);
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
                Ok(recorder) => {
                    tokio::spawn(run_websocket_recording(recorder, recorder_rx));
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

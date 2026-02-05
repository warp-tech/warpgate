use std::fmt::Display;
use std::net::ToSocketAddrs;

use poem::http::{Method, StatusCode, Uri};
use poem::web::{Data, RemoteAddr};
use poem::{Addr, FromRequest, Request};
use tracing::*;

use crate::{Services, WarpgateServerHandle};

pub async fn get_client_ip(req: &Request, services: Option<&Services>) -> Option<String> {
    let trust_x_forwarded_headers = if let Some(services) = services {
        let config = services.config.lock().await;
        config.store.http.trust_x_forwarded_headers
    } else {
        false
    };

    let socket_addr = match req.remote_addr() {
        // See [CertificateExtractorEndpoint]
        RemoteAddr(Addr::Custom("captured-cert", value)) => {
            #[allow(clippy::unwrap_used)]
            let original_remote_addr = value.split("|").next().unwrap();
            original_remote_addr
                .to_socket_addrs()
                .ok()
                .and_then(|i| i.into_iter().next())
        }
        other => other.as_socket_addr().cloned(),
    };

    let remote_ip = socket_addr.map(|x| x.ip().to_string());

    if trust_x_forwarded_headers {
        req.header("x-forwarded-for")
            .map(|x| x.to_string())
            .or(remote_ip)
    } else {
        remote_ip
    }
}

pub async fn span_for_request(
    req: &Request,
    handle: Option<&WarpgateServerHandle>,
) -> poem::Result<Span> {
    let services = Data::<&Services>::from_request_without_body(req).await.ok();
    let client_ip = get_client_ip(req, services.as_deref().copied())
        .await
        .unwrap_or("<unknown>".into());

    Ok(match handle {
        Some(handle) => {
            let ss = handle.session_state().lock().await;
            match ss.user_info.clone() {
                Some(ref user_info) => {
                    info_span!("HTTP", session=%handle.id(), session_username=%user_info.username, %client_ip)
                }
                None => info_span!("HTTP", session=%handle.id(), %client_ip),
            }
        }
        None => info_span!("HTTP"),
    })
}

pub fn log_request_result(
    method: &Method,
    url: &Uri,
    client_ip: Option<&str>,
    status: &StatusCode,
) {
    let client_ip = client_ip.unwrap_or("<unknown>");
    if status.is_server_error() || status.is_client_error() {
        warn!(%method, %url, %status, %client_ip, "Request failed");
    } else {
        info!(%method, %url, %status, %client_ip, "Request");
    }
}

pub fn log_request_error<E: Display>(
    method: &Method,
    url: &Uri,
    client_ip: Option<&str>,
    error: &E,
) {
    let client_ip = client_ip.unwrap_or("<unknown>");
    error!(%method, %url, %error, %client_ip, "Request failed");
}

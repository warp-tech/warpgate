use std::error::Error;

use http::{Method, StatusCode, Uri};
use poem::web::Data;
use poem::{FromRequest, Request};
use tracing::*;
use warpgate_common::helpers::locks::DebugLock;
use warpgate_core::Services;

use crate::session_handle::WarpgateServerHandleFromRequest;

pub async fn span_for_request(req: &Request) -> poem::Result<Span> {
    let handle = WarpgateServerHandleFromRequest::from_request_without_body(req).await;

    let client_ip = get_client_ip(req).await?;

    Ok(match handle {
        Ok(ref handle) => {
            let handle = handle.lock2().await;
            let ss = handle.session_state().lock2().await;
            match ss.user_info.clone() {
                Some(ref user_info) => {
                    info_span!("HTTP", session=%handle.id(), session_username=%user_info.username, %client_ip)
                }
                None => info_span!("HTTP", session=%handle.id(), %client_ip),
            }
        }
        Err(_) => info_span!("HTTP"),
    })
}

pub fn log_request_result(method: &Method, url: &Uri, client_ip: &str, status: &StatusCode) {
    if status.is_server_error() || status.is_client_error() {
        warn!(%method, %url, %status, %client_ip, "Request failed");
    } else {
        info!(%method, %url, %status, %client_ip, "Request");
    }
}

pub fn log_request_error<E: Error>(method: &Method, url: &Uri, client_ip: &str, error: E) {
    error!(%method, %url, %error, %client_ip, "Request failed");
}

pub async fn get_client_ip(req: &Request) -> poem::Result<String> {
    let services = Data::<&Services>::from_request_without_body(req).await.ok();
    let trust_x_forwarded_headers = if let Some(services) = services {
        let config = services.config.lock2().await;
        config.store.http.trust_x_forwarded_headers
    } else {
        false
    };

    let remote_ip = req
        .remote_addr()
        .as_socket_addr()
        .map(|x| x.ip().to_string())
        .unwrap_or("<unknown>".into());

    match trust_x_forwarded_headers {
        true => Ok(req
            .header("x-forwarded-for")
            .map(|x| x.to_string())
            .unwrap_or(remote_ip)),
        false => Ok(remote_ip),
    }
}

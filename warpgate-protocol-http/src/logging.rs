use http::{Method, StatusCode, Uri};
use poem::web::Data;
use poem::{FromRequest, Request};
use tracing::*;
use warpgate_core::Services;

use crate::session_handle::WarpgateServerHandleFromRequest;

pub async fn span_for_request(req: &Request) -> poem::Result<Span> {
    let handle = WarpgateServerHandleFromRequest::from_request_without_body(req).await;
    let services: Data<&Services> = <_>::from_request_without_body(req).await?;
    let config = services.config.lock().await;

    let remote_ip = req
        .remote_addr()
        .as_socket_addr()
        .map(|x| x.ip().to_string())
        .unwrap_or("<unknown>".into());

    let client_ip = match config.store.http.trust_x_forwarded_headers {
        true => req
            .header("x-forwarded-for")
            .map(|x| x.to_string())
            .unwrap_or(remote_ip),
        false => remote_ip,
    };

    Ok(match handle {
        Ok(ref handle) => {
            let handle = handle.lock().await;
            let ss = handle.session_state().lock().await;
            match { ss.username.clone() } {
                Some(ref username) => {
                    info_span!("HTTP", session=%handle.id(), session_username=%username, %client_ip)
                }
                None => info_span!("HTTP", session=%handle.id(), %client_ip),
            }
        }
        Err(_) => info_span!("HTTP"),
    })
}

pub fn log_request_result(method: &Method, url: &Uri, status: &StatusCode) {
    if status.is_server_error() || status.is_client_error() {
        warn!(%method, %url, %status, "Request failed");
    } else {
        info!(%method, %url, %status, "Request");
    }
}

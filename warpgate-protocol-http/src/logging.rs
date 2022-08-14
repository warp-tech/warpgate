use http::{Method, StatusCode, Uri};
use poem::{FromRequest, Request};
use tracing::*;

use crate::session_handle::WarpgateServerHandleFromRequest;

pub async fn span_for_request(req: &Request) -> poem::Result<Span> {
    let handle = WarpgateServerHandleFromRequest::from_request_without_body(req).await;

    Ok(match handle {
        Ok(ref handle) => {
            let handle = handle.lock().await;
            let ss = handle.session_state().lock().await;
            match { ss.username.clone() } {
                Some(ref username) => {
                    info_span!("HTTP", session=%handle.id(), session_username=%username)
                }
                None => info_span!("HTTP", session=%handle.id()),
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

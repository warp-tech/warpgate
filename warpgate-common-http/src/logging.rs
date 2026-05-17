use std::fmt::Debug;
use std::net::ToSocketAddrs;

use poem::http::{Method, StatusCode, Uri};
use poem::web::RemoteAddr;
use poem::{Addr, Request};
use tracing::*;
use warpgate_common::http_headers::X_FORWARDED_FOR;
use warpgate_core::{Services, WarpgateServerHandle};

use crate::auth::first_forwarded_header_value;

fn trusted_client_ip(
    req: &Request,
    remote_ip: Option<String>,
    trust_x_forwarded: bool,
) -> Option<String> {
    if trust_x_forwarded
        && let Some(ip) = req
            .header(&X_FORWARDED_FOR)
            .and_then(first_forwarded_header_value)
    {
        Some(ip.to_string())
    } else {
        remote_ip
    }
}

pub async fn get_client_ip(req: &Request, services: &Services) -> Option<String> {
    let trust_x_forwarded_headers = {
        let config = services.config.lock().await;
        config.store.http.trust_x_forwarded_headers
    };

    let socket_addr = match req.remote_addr() {
        // See [CertificateExtractorEndpoint]
        RemoteAddr(Addr::Custom("captured-cert", value)) => {
            #[allow(clippy::unwrap_used)]
            let original_remote_addr = value.split('|').next().unwrap();
            original_remote_addr
                .to_socket_addrs()
                .ok()
                .and_then(|i| i.into_iter().next())
        }
        other => other.as_socket_addr().copied(),
    };

    let remote_ip = socket_addr.map(|x| x.ip().to_string());

    trusted_client_ip(req, remote_ip, trust_x_forwarded_headers)
}

pub async fn span_for_request(
    req: &Request,
    services: &Services,
    handle: Option<&WarpgateServerHandle>,
) -> poem::Result<Span> {
    let client_ip = get_client_ip(req, services)
        .await
        .unwrap_or_else(|| "<unknown>".into());

    Ok(if let Some(handle) = handle {
        let ss = handle.session_state().lock().await;
        if let Some(ref user_info) = ss.user_info.clone() {
            info_span!("HTTP", session=%handle.id(), session_username=%user_info.username, %client_ip)
        } else {
            info_span!("HTTP", session=%handle.id(), %client_ip)
        }
    } else {
        info_span!("HTTP")
    })
}

pub fn log_request_result(method: &Method, url: &Uri, client_ip: Option<&str>, status: StatusCode) {
    let client_ip = client_ip.unwrap_or("<unknown>");
    if status.is_server_error() || status.is_client_error() {
        warn!(%method, %url, %status, %client_ip, "Request failed");
    } else {
        info!(%method, %url, %status, %client_ip, "Request");
    }
}

pub fn log_request_error<E: Debug>(method: &Method, url: &Uri, client_ip: Option<&str>, error: &E) {
    let client_ip = client_ip.unwrap_or("<unknown>");
    error!(%method, %url, ?error, %client_ip, "Request failed");
}

#[cfg(test)]
mod tests {
    use poem::Request;

    use super::*;

    #[test]
    fn trusted_client_ip_uses_first_forwarded_for_value() {
        let req = Request::builder()
            .header(&X_FORWARDED_FOR, "203.0.113.10, 10.0.0.2")
            .finish();

        assert_eq!(
            trusted_client_ip(&req, Some("10.0.0.1".to_string()), true),
            Some("203.0.113.10".to_string())
        );
    }

    #[test]
    fn trusted_client_ip_falls_back_when_forwarded_for_is_empty() {
        let req = Request::builder().header(&X_FORWARDED_FOR, " , ").finish();

        assert_eq!(
            trusted_client_ip(&req, Some("10.0.0.1".to_string()), true),
            Some("10.0.0.1".to_string())
        );
    }

    #[test]
    fn client_ip_ignores_forwarded_for_when_not_trusted() {
        let req = Request::builder()
            .header(&X_FORWARDED_FOR, "203.0.113.10")
            .finish();

        assert_eq!(
            trusted_client_ip(&req, Some("10.0.0.1".to_string()), false),
            Some("10.0.0.1".to_string())
        );
    }
}

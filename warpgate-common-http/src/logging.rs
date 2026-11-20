use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use poem::http::{Method, StatusCode, Uri};
use poem::web::RemoteAddr;
use poem::{Addr, Request};
use tracing::*;
use url::form_urlencoded;
use warpgate_core::{Services, WarpgateServerHandle};

use crate::request::trusted_client_ip;

fn remote_socket_addr(remote_addr: &RemoteAddr) -> Option<SocketAddr> {
    match remote_addr {
        // An acceptor that learned something during the TLS handshake carries
        // it after the socket address (see `mtls_acceptor::annotate_remote_addr`)
        RemoteAddr(Addr::Custom(_, value)) => value
            .split('|')
            .next()
            .and_then(|addr| addr.to_socket_addrs().ok())
            .and_then(|mut addrs| addrs.next()),
        other => other.as_socket_addr().copied(),
    }
}

/// The peer IP of the connection itself, ignoring any forwarding headers.
pub fn raw_remote_ip(req: &Request) -> Option<String> {
    remote_socket_addr(req.remote_addr()).map(|x| x.ip().to_string())
}

pub async fn get_client_ip(req: &Request, services: &Services) -> Option<String> {
    let trust_x_forwarded_headers = {
        let config = services.config.lock().await;
        config.store.http.trust_x_forwarded_headers
    };

    trusted_client_ip(req, raw_remote_ip(req), trust_x_forwarded_headers)
}

pub async fn get_client_ip_addr(req: &Request, services: &Services) -> Option<IpAddr> {
    get_client_ip(req, services)
        .await
        .and_then(|ip| ip.parse().ok())
}

/// The port of a client behind a proxy or a forwarding node is unknown and
/// recorded as 0
fn client_socket_addr(ip: IpAddr, peer: Option<SocketAddr>) -> SocketAddr {
    peer.filter(|peer| peer.ip() == ip)
        .unwrap_or_else(|| SocketAddr::new(ip, 0))
}

/// The client's address, honoring forwarding headers
pub async fn get_client_socket_addr(req: &Request, services: &Services) -> Option<SocketAddr> {
    let ip = get_client_ip_addr(req, services).await?;
    Some(client_socket_addr(
        ip,
        remote_socket_addr(req.remote_addr()),
    ))
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
        let ss = handle.user_session_state().lock().await;
        if let Some(ref user_info) = ss.user_info.clone() {
            info_span!("HTTP", session=%handle.user_session_id(), session_username=%user_info.username, %client_ip)
        } else {
            info_span!("HTTP", session=%handle.user_session_id(), %client_ip)
        }
    } else {
        info_span!("HTTP")
    })
}

/// The request URI for logs: a `warpgate-ticket` query value is a credential.
pub fn redacted_uri(uri: &Uri) -> String {
    let Some(query) = uri.query() else {
        return uri.to_string();
    };
    let is_ticket = |key: &str| key == "warpgate-ticket";
    if !form_urlencoded::parse(query.as_bytes()).any(|(key, _)| is_ticket(&key)) {
        return uri.to_string();
    }
    let query = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(
            form_urlencoded::parse(query.as_bytes()).map(|(key, value)| {
                let value = if is_ticket(&key) {
                    Cow::Borrowed("redacted")
                } else {
                    value
                };
                (key, value)
            }),
        )
        .finish();
    format!("{}?{query}", uri.path())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_query_value_is_redacted() {
        let uri: Uri = "/app/x?a=1&warpgate-ticket=s3cret&b=2".parse().unwrap();
        assert_eq!(
            redacted_uri(&uri),
            "/app/x?a=1&warpgate-ticket=redacted&b=2"
        );
        let plain: Uri = "/app/x?a=1".parse().unwrap();
        assert_eq!(redacted_uri(&plain), "/app/x?a=1");
    }

    #[test]
    fn extracts_socket_addr_from_plain_and_annotated_remote_addr() {
        let socket: SocketAddr = "203.0.113.10:54321".parse().unwrap();
        assert_eq!(
            remote_socket_addr(&RemoteAddr(Addr::SocketAddr(socket))),
            Some(socket)
        );
        assert_eq!(
            remote_socket_addr(&RemoteAddr(Addr::Custom(
                "tls",
                "203.0.113.10:54321|foo".into(),
            ))),
            Some(socket)
        );
    }

    #[test]
    fn client_socket_addr_keeps_the_port_only_of_a_direct_client() {
        let peer: SocketAddr = "10.0.0.1:54321".parse().unwrap();
        let forwarded: IpAddr = "203.0.113.10".parse().unwrap();

        assert_eq!(client_socket_addr(peer.ip(), Some(peer)), peer);
        assert_eq!(
            client_socket_addr(forwarded, Some(peer)),
            SocketAddr::new(forwarded, 0)
        );
        assert_eq!(
            client_socket_addr(forwarded, None),
            SocketAddr::new(forwarded, 0)
        );
    }
}

pub fn log_request_result(method: &Method, url: &Uri, client_ip: Option<&str>, status: StatusCode) {
    let url = redacted_uri(url);
    let client_ip = client_ip.unwrap_or("<unknown>");
    if status.is_server_error() || status.is_client_error() {
        warn!(%method, %url, %status, %client_ip, "Request failed");
    } else {
        info!(%method, %url, %status, %client_ip, "Request");
    }
}

pub fn log_request_error(method: &Method, url: &Uri, client_ip: Option<&str>, error: &poem::Error) {
    let status = error.status();
    if !status.is_client_error() && !status.is_server_error() {
        log_request_result(method, url, client_ip, status);
        return;
    }
    let url = redacted_uri(url);
    let client_ip = client_ip.unwrap_or("<unknown>");
    error!(%method, %url, ?error, %client_ip, "Request failed");
}

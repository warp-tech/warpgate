use std::borrow::Cow;
use std::net::{IpAddr, ToSocketAddrs};

use poem::http::{Method, StatusCode, Uri};
use poem::web::RemoteAddr;
use poem::{Addr, Request};
use tracing::*;
use url::form_urlencoded;
use warpgate_common::UserSessionId;
use warpgate_core::{Services, WarpgateServerHandle};

use crate::request::trusted_client_ip;

/// The peer IP of the connection itself, ignoring any forwarding headers.
pub fn raw_remote_ip(req: &Request) -> Option<String> {
    let socket_addr = match req.remote_addr() {
        // An acceptor that learned something during the TLS handshake carries
        // it after the socket address (see `tls_acceptor::annotate_remote_addr`)
        RemoteAddr(Addr::Custom(_, value)) => value
            .split('|')
            .next()
            .and_then(|addr| addr.to_socket_addrs().ok())
            .and_then(|mut addrs| addrs.next()),
        other => other.as_socket_addr().copied(),
    };

    socket_addr.map(|x| x.ip().to_string())
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

/// Who a request is attributed to in its log span.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SpanIdentity {
    pub session: Option<UserSessionId>,
    pub username: Option<String>,
}

impl SpanIdentity {
    pub fn or(self, fallback: Self) -> Self {
        Self {
            session: self.session.or(fallback.session),
            username: self.username.or(fallback.username),
        }
    }
}

pub async fn span_for_request(
    req: &Request,
    services: &Services,
    handle: Option<&WarpgateServerHandle>,
    fallback: SpanIdentity,
) -> poem::Result<Span> {
    let client_ip = get_client_ip(req, services)
        .await
        .unwrap_or_else(|| "<unknown>".into());

    let identity = if let Some(handle) = handle {
        let ss = handle.user_session_state().lock().await;
        SpanIdentity {
            session: Some(handle.user_session_id()),
            username: ss
                .user_info
                .as_ref()
                .map(|user_info| user_info.username.clone()),
        }
    } else {
        SpanIdentity::default()
    }
    .or(fallback);

    Ok(match (identity.session, identity.username) {
        (Some(id), Some(username)) => {
            info_span!("HTTP", session=%id, session_username=%username, %client_ip)
        }
        (Some(id), None) => info_span!("HTTP", session=%id, %client_ip),
        (None, Some(username)) => info_span!("HTTP", session_username=%username, %client_ip),
        (None, None) => info_span!("HTTP"),
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
    fn span_identity_uses_fallback_for_missing_fields() {
        let fallback = SpanIdentity {
            session: Some(UserSessionId(uuid::Uuid::from_u128(1))),
            username: Some("cookie-user".into()),
        };
        assert_eq!(SpanIdentity::default().or(fallback.clone()), fallback);

        let live_session = Some(UserSessionId(uuid::Uuid::from_u128(2)));
        assert_eq!(
            SpanIdentity {
                session: live_session,
                username: None,
            }
            .or(fallback.clone()),
            SpanIdentity {
                session: live_session,
                username: fallback.username.clone(),
            }
        );

        let live = SpanIdentity {
            session: live_session,
            username: Some("live-user".into()),
        };
        assert_eq!(live.clone().or(fallback), live);
    }

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

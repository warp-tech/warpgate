use std::net::IpAddr;

use poem::Request;
use poem::http::header::HOST;
use poem::http::uri::Scheme;
use warpgate_common::http_headers::{X_FORWARDED_FOR, X_FORWARDED_HOST, X_FORWARDED_PROTO};

use crate::{X_WARPGATE_CLUSTER_CLIENT_IP, is_cluster_peer_request};

// proxies append to the end of XFF header
pub fn last_forwarded_header_value(value: &str) -> Option<&str> {
    value
        .rsplit(',')
        .map(str::trim)
        .find(|value| !value.is_empty())
}

pub fn trusted_host_header(should_trust_x_forwarded: bool, req: &Request) -> Option<String> {
    if should_trust_x_forwarded
        && let Some(host) = req
            .header(&X_FORWARDED_HOST)
            .and_then(last_forwarded_header_value)
    {
        return Some(host.to_string());
    }

    req.header(HOST).map(ToString::to_string).or_else(|| {
        let uri = req.original_uri();
        uri.authority().map(|authority| authority.to_string())
    })
}

pub fn trusted_proto(should_trust_x_forwarded: bool, req: &Request) -> Scheme {
    if should_trust_x_forwarded
        && let Some(proto) = req
            .header(&X_FORWARDED_PROTO)
            .and_then(last_forwarded_header_value)
        && let Ok(s) = Scheme::try_from(proto)
    {
        s
    } else {
        req.original_uri()
            .scheme()
            .cloned()
            .unwrap_or(Scheme::HTTPS)
    }
}

pub fn trusted_client_ip(
    req: &Request,
    remote_ip: Option<String>,
    trust_x_forwarded: bool,
) -> Option<String> {
    if is_cluster_peer_request(req)
        && let Some(ip) = req.header(&X_WARPGATE_CLUSTER_CLIENT_IP)
    {
        Some(ip.to_string())
    } else if trust_x_forwarded
        && let Some(ip) = req
            .header(&X_FORWARDED_FOR)
            .and_then(last_forwarded_header_value)
            .and_then(|ip| ip.parse::<IpAddr>().ok())
    {
        Some(ip.to_string())
    } else {
        remote_ip
    }
}

#[cfg(test)]
mod tests {
    use poem::Request;
    use poem::http::header::HOST;
    use uuid::Uuid;
    use warpgate_common::NodeId;

    use super::*;
    use crate::ClusterPeer;

    fn trusted_header_request(
        forwarded_host: Option<&str>,
        forwarded_proto: Option<&str>,
    ) -> Request {
        let mut builder = Request::builder()
            .uri_str("http://internal.example")
            .header(HOST, "fallback.example");

        if let Some(value) = forwarded_host {
            builder = builder.header(&X_FORWARDED_HOST, value);
        }
        if let Some(value) = forwarded_proto {
            builder = builder.header(&X_FORWARDED_PROTO, value);
        }

        builder.finish()
    }

    #[test]
    fn trusted_host_uses_last_forwarded_host() {
        let req = trusted_header_request(Some("client.example, public.example"), None);

        assert_eq!(
            trusted_host_header(true, &req),
            Some("public.example".to_string())
        );
    }

    #[test]
    fn trusted_host_falls_back_when_forwarded_host_is_empty() {
        let req = trusted_header_request(Some(" , "), None);

        assert_eq!(
            trusted_host_header(true, &req),
            Some("fallback.example".to_string())
        );
    }

    #[test]
    fn trusted_proto_uses_last_forwarded_proto() {
        let req = trusted_header_request(None, Some("http, https"));

        assert_eq!(trusted_proto(true, &req), Scheme::HTTPS);
    }

    #[test]
    fn last_forwarded_header_value_skips_empty_items() {
        assert_eq!(
            last_forwarded_header_value("client.example, public.example, "),
            Some("public.example")
        );
        assert_eq!(last_forwarded_header_value(" , "), None);
    }

    #[test]
    fn trusted_client_ip_uses_last_forwarded_for_value() {
        let req = Request::builder()
            .header(&X_FORWARDED_FOR, "198.51.100.7, 203.0.113.10")
            .finish();

        assert_eq!(
            trusted_client_ip(&req, Some("10.0.0.1".to_string()), true),
            Some("203.0.113.10".to_string())
        );
    }

    #[test]
    fn trusted_client_ip_ignores_a_forwarded_for_that_is_not_an_address() {
        let req = Request::builder()
            .header(&X_FORWARDED_FOR, "203.0.113.10, not-an-ip")
            .finish();

        assert_eq!(
            trusted_client_ip(
                &req,
                &Secret::new("".into()),
                Some("10.0.0.1".to_string()),
                true
            ),
            Some("10.0.0.1".to_string())
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

    #[test]
    fn client_ip_takes_the_forwarding_peers_word_for_it() {
        let mut req = Request::builder()
            .header(&X_WARPGATE_CLUSTER_CLIENT_IP, "203.0.113.10")
            .finish();
        // What ClusterPeerMiddleware attaches for a connection the acceptor
        // authenticated as a pinned node
        req.extensions_mut().insert(ClusterPeer {
            node_id: NodeId(Uuid::new_v4()),
        });

        assert_eq!(
            trusted_client_ip(&req, Some("10.0.0.1".to_string()), false),
            Some("203.0.113.10".to_string())
        );
    }

    #[test]
    fn client_ip_ignores_a_cluster_client_ip_from_a_non_peer() {
        let req = Request::builder()
            .header(&X_WARPGATE_CLUSTER_CLIENT_IP, "203.0.113.10")
            .finish();

        assert_eq!(
            trusted_client_ip(&req, Some("10.0.0.1".to_string()), false),
            Some("10.0.0.1".to_string())
        );
    }
}

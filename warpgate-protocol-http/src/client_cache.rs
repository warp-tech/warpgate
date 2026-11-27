use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::Url;
use reqwest::redirect::Policy;
use warpgate_common::TargetHTTPOptions;
use warpgate_common_cache::Cache;
use warpgate_tls::TlsMode;

const HTTP_CLIENT_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

const HTTP_CLIENT_POOL_MAX_IDLE_PER_HOST: usize = 16;

/// Key = target name
pub type HttpClientCache = Cache<String, TargetHTTPOptions, reqwest::Client>;

pub fn build_client(options: &TargetHTTPOptions) -> Result<reqwest::Client> {
    let tls_mode = options.tls.mode;
    let mut client = reqwest::Client::builder()
        .gzip(false) // do not decode
        .connection_verbose(true)
        .pool_idle_timeout(HTTP_CLIENT_POOL_IDLE_TIMEOUT)
        .pool_max_idle_per_host(HTTP_CLIENT_POOL_MAX_IDLE_PER_HOST)
        .redirect(Policy::custom(move |attempt| {
            if follows_redirect(tls_mode, attempt.previous(), attempt.url()) {
                tracing::debug!("Following HTTP->HTTPS redirect");
                attempt.follow()
            } else {
                attempt.stop()
            }
        }));

    if options.tls.mode == TlsMode::Required {
        client = client.https_only(true);
    }

    if !options.tls.verify {
        client = client.danger_accept_invalid_certs(true);
    } else if let Some(ca) = options.tls.ca_pem() {
        // Trust the configured CA in addition to the system roots, so a target
        // with a private CA can still be verified.
        for cert in reqwest::Certificate::from_pem_bundle(ca)
            .context("Parsing the HTTP target CA bundle")?
        {
            client = client.add_root_certificate(cert);
        }
    }

    client.build().context("Could not build HTTP target client")
}

/// Only follow simple HTTP->HTTPS redirects on the same origin to prevent SSRF
fn follows_redirect(tls_mode: TlsMode, previous: &[Url], next: &Url) -> bool {
    let [origin] = previous else {
        return false;
    };
    tls_mode == TlsMode::Preferred
        && origin.scheme() == "http"
        && next.scheme() == "https"
        && origin.host() == next.host()
        && origin.port() == next.port()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn http_options(tls: serde_json::Value) -> TargetHTTPOptions {
        serde_json::from_value(serde_json::json!({ "url": "https://t", "tls": tls })).unwrap()
    }

    /// With verification on, a configured CA (single cert or a bundle) is fed
    /// into the client's root store; malformed certificate material fails the
    /// build instead of being ignored.
    #[test]
    fn ca_trust_material_is_wired_into_the_client() {
        let (ca_pem, _key) = warpgate_ca::issue_ca_root_certificate().unwrap();
        let (ca_pem2, _key2) = warpgate_ca::issue_ca_root_certificate().unwrap();

        // A single CA certificate.
        assert!(
            build_client(&http_options(
                serde_json::json!({ "verify": true, "ca": ca_pem })
            ))
            .is_ok()
        );

        // A bundle of several concatenated PEM certificates.
        let bundle = format!("{ca_pem}\n{ca_pem2}");
        assert!(
            build_client(&http_options(
                serde_json::json!({ "verify": true, "ca": bundle })
            ))
            .is_ok()
        );

        // No CA configured keeps today's behaviour.
        assert!(build_client(&http_options(serde_json::json!({ "verify": true }))).is_ok());

        // A PEM block that is not a valid certificate is a hard error.
        let broken = "-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----\n";
        assert!(
            build_client(&http_options(
                serde_json::json!({ "verify": true, "ca": broken })
            ))
            .is_err()
        );

        // With verification off the CA is never parsed, so bad material is ignored.
        assert!(
            build_client(&http_options(
                serde_json::json!({ "verify": false, "ca": broken })
            ))
            .is_ok()
        );
    }

    #[test]
    fn follows_only_same_host_https_upgrade_on_first_hop() {
        let origin = url("http://app:9000/x");
        let follow =
            |next: &str| follows_redirect(TlsMode::Preferred, &[origin.clone()], &url(next));

        assert!(follow("https://app:9000/x"));
        assert!(!follow("https://app/x"));
        assert!(!follow("https://attacker:9443/steal"));
        assert!(!follow("http://app:9000/x"));
        assert!(follows_redirect(
            TlsMode::Preferred,
            &[url("http://app/x")],
            &url("https://app/x")
        ));

        let chain = [origin.clone(), url("https://app/x")];
        assert!(!follows_redirect(
            TlsMode::Preferred,
            &chain,
            &url("https://app/y")
        ));

        assert!(!follows_redirect(
            TlsMode::Required,
            &[origin.clone()],
            &url("https://app/x")
        ));
        assert!(!follows_redirect(
            TlsMode::Disabled,
            &[origin],
            &url("https://app/x")
        ));
    }
}

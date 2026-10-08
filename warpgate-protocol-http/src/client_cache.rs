use std::time::Duration;

use anyhow::{Context, Result};
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
        .gzip(true)
        .connection_verbose(true)
        .pool_idle_timeout(HTTP_CLIENT_POOL_IDLE_TIMEOUT)
        .pool_max_idle_per_host(HTTP_CLIENT_POOL_MAX_IDLE_PER_HOST)
        .redirect(Policy::custom(move |attempt| {
            let started_with_http = attempt
                .previous()
                .first()
                .is_some_and(|url| url.scheme() == "http");

            if tls_mode == TlsMode::Preferred
                && started_with_http
                && attempt.url().scheme() == "https"
            {
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
    }

    client.build().context("Could not build HTTP target client")
}

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use reqwest::redirect::Policy;
use tokio::sync::Mutex;
use warpgate_common::TargetHTTPOptions;
use warpgate_tls::TlsMode;

pub const HTTP_CLIENT_IDLE_TTL: Duration = Duration::from_secs(10 * 60);
pub const HTTP_CLIENT_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
pub const HTTP_CLIENT_CACHE_VACUUM_INTERVAL: Duration = Duration::from_secs(60);

const HTTP_CLIENT_POOL_MAX_IDLE_PER_HOST: usize = 16;

#[derive(PartialEq, Eq)]
struct ClientConfiguration {
    url: String,
    tls_mode: TlsMode,
    tls_verify: bool,
}

impl From<&TargetHTTPOptions> for ClientConfiguration {
    fn from(options: &TargetHTTPOptions) -> Self {
        Self {
            url: options.url.clone(),
            tls_mode: options.tls.mode,
            tls_verify: options.tls.verify,
        }
    }
}

struct CachedClient {
    configuration: ClientConfiguration,
    client: reqwest::Client,
    last_used: Instant,
}

#[derive(Clone)]
pub struct HttpClientCache {
    clients: Arc<Mutex<HashMap<String, CachedClient>>>,
    idle_ttl: Duration,
    #[cfg(test)]
    build_count: Arc<std::sync::atomic::AtomicUsize>,
}

impl Default for HttpClientCache {
    fn default() -> Self {
        Self::new(HTTP_CLIENT_IDLE_TTL)
    }
}

impl HttpClientCache {
    fn new(idle_ttl: Duration) -> Self {
        Self {
            clients: Arc::new(Mutex::new(HashMap::new())),
            idle_ttl,
            #[cfg(test)]
            build_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    pub async fn client_for(
        &self,
        target_name: &str,
        options: &TargetHTTPOptions,
    ) -> Result<reqwest::Client> {
        let now = Instant::now();
        let configuration = ClientConfiguration::from(options);
        let mut clients = self.clients.lock().await;

        clients.retain(|_, entry| now.duration_since(entry.last_used) < self.idle_ttl);

        if let Some(entry) = clients.get_mut(target_name)
            && entry.configuration == configuration
        {
            entry.last_used = now;
            return Ok(entry.client.clone());
        }

        let client = build_client(&configuration)?;
        #[cfg(test)]
        self.build_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        clients.insert(
            target_name.to_string(),
            CachedClient {
                configuration,
                client: client.clone(),
                last_used: now,
            },
        );

        Ok(client)
    }

    pub async fn vacuum(&self) {
        let now = Instant::now();
        self.clients
            .lock()
            .await
            .retain(|_, entry| now.duration_since(entry.last_used) < self.idle_ttl);
    }
}

fn build_client(configuration: &ClientConfiguration) -> Result<reqwest::Client> {
    let tls_mode = configuration.tls_mode;
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

    if configuration.tls_mode == TlsMode::Required {
        client = client.https_only(true);
    }

    if !configuration.tls_verify {
        client = client.danger_accept_invalid_certs(true);
    }

    client.build().context("Could not build HTTP target client")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn install_crypto_provider() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    fn make_options(url: &str) -> TargetHTTPOptions {
        TargetHTTPOptions {
            url: url.to_string(),
            tls: Default::default(),
            headers: None,
            external_host: None,
        }
    }

    #[tokio::test]
    async fn reuses_client_for_unchanged_target() {
        install_crypto_provider();
        let cache = HttpClientCache::default();
        let options = make_options("https://example.com");

        cache.client_for("target", &options).await.unwrap();
        cache.client_for("target", &options).await.unwrap();

        assert_eq!(
            cache.build_count.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn rebuilds_client_when_target_configuration_changes() {
        install_crypto_provider();
        let cache = HttpClientCache::default();

        cache
            .client_for("target", &make_options("https://example.com"))
            .await
            .unwrap();
        cache
            .client_for("target", &make_options("https://example.org"))
            .await
            .unwrap();

        assert_eq!(
            cache.build_count.load(std::sync::atomic::Ordering::Relaxed),
            2
        );
    }

    #[tokio::test]
    async fn rebuilds_client_after_idle_ttl() {
        install_crypto_provider();
        let cache = HttpClientCache::new(Duration::ZERO);
        let options = make_options("https://example.com");

        cache.client_for("target", &options).await.unwrap();
        cache.client_for("target", &options).await.unwrap();

        assert_eq!(
            cache.build_count.load(std::sync::atomic::Ordering::Relaxed),
            2
        );
    }
}

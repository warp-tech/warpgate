use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use uuid::Uuid;
use warpgate_common::TargetKubernetesOptions;

/// How long an upstream client is reused before it is rebuilt. Rebuilding
/// re-resolves the target's credential, so this bounds how long a rotated
/// secret (e.g. in Vault) or an expiring EKS token (valid for 15 minutes)
/// stays in use.
const CLIENT_TTL: Duration = Duration::from_secs(5 * 60);

struct CachedClient {
    options: TargetKubernetesOptions,
    client: reqwest::Client,
    created: Instant,
}

type Slot = Arc<Mutex<Option<CachedClient>>>;

/// Upstream API clients, one per Kubernetes target, shared across requests.
///
/// A `reqwest::Client` owns its connection pool, so building one per request
/// opens a new TCP connection and TLS handshake to the API server every time
/// and a `kubectl` command's fan-out of requests pays that round-trip cost for
/// each of them. Reusing the client keeps connections alive (and multiplexed
/// over HTTP/2 where the API server offers it).
///
/// A cached client is only reused while the target's options are unchanged, so
/// editing a target's URL, TLS settings or credential takes effect on the next
/// request.
///
/// Clients are shared between all users of a target, so they must carry only
/// the target's own credential. Anything user-specific (e.g. impersonation
/// headers) belongs on the individual request, never in the cached client —
/// otherwise one user's identity would leak into another's requests.
#[derive(Default)]
pub struct UpstreamClientCache {
    slots: std::sync::Mutex<HashMap<Uuid, Slot>>,
}

impl UpstreamClientCache {
    /// The cached client for `target_id`, or one freshly made by `build`.
    ///
    /// Concurrent requests for the same target wait for a single build rather
    /// than each opening their own connection; other targets aren't held up.
    pub async fn get_or_build<F, Fut>(
        &self,
        target_id: Uuid,
        options: &TargetKubernetesOptions,
        build: F,
    ) -> anyhow::Result<reqwest::Client>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = anyhow::Result<reqwest::Client>>,
    {
        let slot = self.slot(target_id);
        let mut slot = slot.lock().await;
        if let Some(cached) = &*slot
            && cached.options == *options
            && cached.created.elapsed() < CLIENT_TTL
        {
            return Ok(cached.client.clone());
        }

        let client = build().await?;
        *slot = Some(CachedClient {
            options: options.clone(),
            client: client.clone(),
            created: Instant::now(),
        });
        Ok(client)
    }

    /// Drop the cached client for `target_id`, e.g. after the API server
    /// rejected its credential, so the next request builds a new one.
    pub fn evict(&self, target_id: Uuid) {
        self.slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&target_id);
    }

    fn slot(&self, target_id: Uuid) -> Slot {
        self.slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(target_id)
            .or_default()
            .clone()
    }

    #[cfg(test)]
    async fn age_all(&self, by: Duration) {
        let slots: Vec<Slot> = self
            .slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .cloned()
            .collect();
        for slot in slots {
            if let Some(cached) = &mut *slot.lock().await {
                cached.created = cached.created.checked_sub(by).unwrap_or(cached.created);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use warpgate_common::{KubernetesTargetAuth, KubernetesTargetIamRoleAuth};

    use super::*;

    fn options(url: &str) -> TargetKubernetesOptions {
        TargetKubernetesOptions {
            cluster_url: url.into(),
            tls: Default::default(),
            auth: KubernetesTargetAuth::IamRole(KubernetesTargetIamRoleAuth {}),
        }
    }

    async fn get(
        cache: &UpstreamClientCache,
        target: Uuid,
        opts: &TargetKubernetesOptions,
        builds: &AtomicUsize,
    ) {
        // reqwest is built without a default crypto provider; the binary
        // installs one at startup.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        cache
            .get_or_build(target, opts, || async {
                builds.fetch_add(1, Ordering::SeqCst);
                Ok(reqwest::Client::new())
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn reuses_client_for_same_target_and_options() {
        let cache = UpstreamClientCache::default();
        let builds = AtomicUsize::new(0);
        let target = Uuid::new_v4();
        let opts = options("https://a:6443");

        for _ in 0..5 {
            get(&cache, target, &opts, &builds).await;
        }
        assert_eq!(builds.load(Ordering::SeqCst), 1);

        get(&cache, Uuid::new_v4(), &opts, &builds).await;
        assert_eq!(
            builds.load(Ordering::SeqCst),
            2,
            "targets don't share clients"
        );
    }

    #[tokio::test]
    async fn rebuilds_when_options_change() {
        let cache = UpstreamClientCache::default();
        let builds = AtomicUsize::new(0);
        let target = Uuid::new_v4();

        get(&cache, target, &options("https://a:6443"), &builds).await;
        get(&cache, target, &options("https://b:6443"), &builds).await;
        assert_eq!(builds.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn rebuilds_after_ttl_or_eviction() {
        let cache = UpstreamClientCache::default();
        let builds = AtomicUsize::new(0);
        let target = Uuid::new_v4();
        let opts = options("https://a:6443");

        get(&cache, target, &opts, &builds).await;
        cache.age_all(CLIENT_TTL).await;
        get(&cache, target, &opts, &builds).await;
        assert_eq!(builds.load(Ordering::SeqCst), 2);

        cache.evict(target);
        get(&cache, target, &opts, &builds).await;
        assert_eq!(builds.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn failed_build_is_not_cached() {
        let cache = UpstreamClientCache::default();
        let target = Uuid::new_v4();
        let opts = options("https://a:6443");

        let failed = cache
            .get_or_build(target, &opts, || async { anyhow::bail!("no credential") })
            .await;
        assert!(failed.is_err());

        let builds = AtomicUsize::new(0);
        get(&cache, target, &opts, &builds).await;
        assert_eq!(builds.load(Ordering::SeqCst), 1);
    }
}

use std::future::Future;
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use quick_cache::sync::{Cache, EntryAction, EntryResult};

// LRU cache limit
const CAPACITY: usize = 1024;

#[derive(Clone)]
struct Cached<C, V> {
    config: C,
    client: V,
    created: Instant,
}

/// Cache of reusable HTTP clients
#[derive(Clone)]
pub struct ClientCache<K, C, V> {
    cache: Arc<Cache<K, Cached<C, V>>>,
    max_age: Duration,
}

impl<K, C, V> ClientCache<K, C, V>
where
    K: Clone + Eq + Hash,
    C: Clone + PartialEq,
    V: Clone,
{
    pub fn new(max_age: Duration) -> Self {
        Self {
            cache: Arc::new(Cache::new(CAPACITY)),
            max_age,
        }
    }

    pub async fn get_or_build<F, Fut>(&self, key: &K, config: &C, build: F) -> Result<V>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<V>>,
    {
        let guard = match self
            .cache
            .entry_async(key, |_, cached| {
                if cached.config == *config && cached.created.elapsed() < self.max_age {
                    EntryAction::Retain(cached.client.clone())
                } else {
                    EntryAction::ReplaceWithGuard
                }
            })
            .await
        {
            EntryResult::Retained(client) => return Ok(client),
            EntryResult::Vacant(guard) | EntryResult::Replaced(guard, _) => guard,
            EntryResult::Removed(..) | EntryResult::Timeout => {
                anyhow::bail!("client cache entry vanished")
            }
        };

        let client = build().await?;
        let _ = guard.insert(Cached {
            config: config.clone(),
            client: client.clone(),
            created: Instant::now(),
        });
        Ok(client)
    }

    pub fn remove(&self, key: &K) {
        self.cache.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    type TestCache = ClientCache<u32, &'static str, usize>;

    async fn get(cache: &TestCache, key: u32, config: &'static str, builds: &AtomicUsize) {
        cache
            .get_or_build(&key, &config, || async {
                Ok(builds.fetch_add(1, Ordering::SeqCst))
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn reuses_client_per_key_and_config() {
        let cache = TestCache::new(Duration::MAX);
        let builds = AtomicUsize::new(0);

        for _ in 0..5 {
            get(&cache, 1, "a", &builds).await;
        }
        assert_eq!(builds.load(Ordering::SeqCst), 1);

        get(&cache, 2, "a", &builds).await;
        assert_eq!(builds.load(Ordering::SeqCst), 2, "keys don't share clients");

        get(&cache, 1, "b", &builds).await;
        assert_eq!(builds.load(Ordering::SeqCst), 3, "config change rebuilds");
    }

    #[tokio::test]
    async fn concurrent_requests_share_one_build() {
        let cache = TestCache::new(Duration::MAX);
        let builds = AtomicUsize::new(0);
        // Yields so the second request arrives while the first is still building.
        let slow_build = || async {
            let n = builds.fetch_add(1, Ordering::SeqCst);
            for _ in 0..3 {
                tokio::task::yield_now().await;
            }
            Ok(n)
        };

        let (a, b) = tokio::join!(
            cache.get_or_build(&1, &"a", slow_build),
            cache.get_or_build(&1, &"a", slow_build),
        );
        assert_eq!((a.unwrap(), b.unwrap()), (0, 0));
        assert_eq!(builds.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn rebuilds_after_max_age() {
        let cache = TestCache::new(Duration::ZERO);
        let builds = AtomicUsize::new(0);

        get(&cache, 1, "a", &builds).await;
        get(&cache, 1, "a", &builds).await;
        assert_eq!(builds.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn failed_build_is_not_cached() {
        let cache = TestCache::new(Duration::MAX);
        let failed = cache
            .get_or_build(&1, &"a", || async { anyhow::bail!("no credential") })
            .await;
        assert!(failed.is_err());

        let builds = AtomicUsize::new(0);
        get(&cache, 1, "a", &builds).await;
        assert_eq!(builds.load(Ordering::SeqCst), 1);
    }
}

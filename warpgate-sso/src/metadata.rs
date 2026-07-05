use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use openidconnect::{DiscoveryError, ProviderMetadataWithLogout, reqwest};

use crate::SsoError;
use crate::config::SsoInternalProviderConfig;

const METADATA_CACHE_TTL: Duration = Duration::from_secs(300);

#[allow(clippy::type_complexity)]
static METADATA_CACHE: LazyLock<Mutex<HashMap<String, (Instant, ProviderMetadataWithLogout)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn cached_metadata(issuer: &str) -> Option<ProviderMetadataWithLogout> {
    let cache = METADATA_CACHE.lock().ok()?;
    let (fetched_at, metadata) = cache.get(issuer)?;
    (fetched_at.elapsed() < METADATA_CACHE_TTL).then(|| metadata.clone())
}

fn store_metadata(issuer: String, metadata: &ProviderMetadataWithLogout) {
    if let Ok(mut cache) = METADATA_CACHE.lock() {
        cache.insert(issuer, (Instant::now(), metadata.clone()));
    }
}

pub async fn discover_metadata(
    config: &SsoInternalProviderConfig,
    http_client: &reqwest::Client,
) -> Result<ProviderMetadataWithLogout, SsoError> {
    let issuer = config.issuer_url()?;
    let cache_key = issuer.to_string();

    if let Some(metadata) = cached_metadata(&cache_key) {
        return Ok(metadata);
    }

    let metadata = ProviderMetadataWithLogout::discover_async(issuer, http_client)
        .await
        .map_err(|e| {
            SsoError::Discovery(match e {
                DiscoveryError::Request(inner) => format!("Request error: {inner:?}"),
                e => format!("{e}"),
            })
        })?;

    store_metadata(cache_key, &metadata);
    Ok(metadata)
}

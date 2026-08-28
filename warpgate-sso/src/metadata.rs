use std::collections::HashMap;
use std::error::Error;
use std::fmt::Write;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use openidconnect::url::Url;
use openidconnect::{ProviderMetadataWithLogout, reqwest};

use crate::SsoError;
use crate::config::SsoInternalProviderConfig;

const METADATA_CACHE_TTL: Duration = Duration::from_secs(300);

/// Schemes an endpoint from a discovery document is allowed to use.
///
/// `https` is what the OIDC Discovery spec mandates; `http` is kept for
/// providers reached over a trusted network (test rigs, in-cluster IdPs).
const ALLOWED_ENDPOINT_SCHEMES: [&str; 2] = ["https", "http"];

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

/// Render an error together with its whole `source` chain.
///
/// `DiscoveryError`'s own `Display` is a bare summary — `Parse` renders as
/// "Failed to parse server response" and keeps the serde path (e.g. `missing
/// field `keys``) only in its source, which is usually the sole clue as to
/// which document the provider served badly.
fn describe_error(err: &(dyn Error + 'static)) -> String {
    let mut out = err.to_string();
    let mut source = err.source();
    while let Some(err) = source {
        let _ = write!(out, ": {err}");
        source = err.source();
    }
    out
}

fn check_endpoint_scheme(endpoint: &str, url: &Url) -> Result<(), SsoError> {
    if ALLOWED_ENDPOINT_SCHEMES.contains(&url.scheme()) {
        return Ok(());
    }
    Err(SsoError::UnsupportedEndpointScheme {
        endpoint: endpoint.to_owned(),
        url: url.to_string(),
    })
}

/// Reject a discovery document that advertises an endpoint we shouldn't be
/// dereferencing or handing to a browser.
///
/// `openidconnect` parses endpoints as generic URLs and puts no constraint on
/// their scheme, so a hostile or compromised provider can advertise something
/// like `javascript:...` as its `authorization_endpoint` or
/// `end_session_endpoint`. Both of those reach the browser as a URL to
/// navigate to (`GET /sso/providers/:name/start` and `GET /sso/logout` return
/// them to the frontend, which assigns them to `location.href`), so a
/// `javascript:` URL there would execute on the gateway's own origin. The
/// remaining endpoints are only ever fetched server-side, but there is no
/// legitimate non-HTTP value for any of them either.
///
/// Checking here covers every consumer of discovery metadata, present and
/// future, instead of relying on each call site to remember.
fn validate_endpoint_schemes(metadata: &ProviderMetadataWithLogout) -> Result<(), SsoError> {
    check_endpoint_scheme(
        "authorization_endpoint",
        metadata.authorization_endpoint().url(),
    )?;
    check_endpoint_scheme("jwks_uri", metadata.jwks_uri().url())?;

    let optional = [
        ("token_endpoint", metadata.token_endpoint().map(|x| x.url())),
        (
            "userinfo_endpoint",
            metadata.userinfo_endpoint().map(|x| x.url()),
        ),
        (
            "registration_endpoint",
            metadata.registration_endpoint().map(|x| x.url()),
        ),
        (
            "end_session_endpoint",
            metadata
                .additional_metadata()
                .end_session_endpoint
                .as_ref()
                .map(|x| x.url()),
        ),
    ];

    for (endpoint, url) in optional {
        if let Some(url) = url {
            check_endpoint_scheme(endpoint, url)?;
        }
    }

    Ok(())
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
        .map_err(|e| SsoError::Discovery(describe_error(&e)))?;

    // Validate before caching, so a hostile document is never served from the
    // cache and never reaches a caller.
    validate_endpoint_schemes(&metadata)?;

    store_metadata(cache_key, &metadata);
    Ok(metadata)
}

#[cfg(test)]
pub mod tests {
    use serde_json::{Value, json};

    use super::{ProviderMetadataWithLogout, SsoError, describe_error, validate_endpoint_schemes};

    /// A minimal discovery document, with `extra` merged over the defaults.
    pub fn metadata(extra: &Value) -> ProviderMetadataWithLogout {
        let mut doc = json!({
            "issuer": "https://idp.example.com",
            "authorization_endpoint": "https://idp.example.com/authorize",
            "jwks_uri": "https://idp.example.com/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        });

        if let (Some(doc), Some(extra)) = (doc.as_object_mut(), extra.as_object()) {
            for (key, value) in extra {
                doc.insert(key.clone(), value.clone());
            }
        }

        serde_json::from_value(doc).unwrap()
    }

    /// The endpoint `validate_endpoint_schemes` rejected, if it rejected one.
    fn rejected_endpoint(extra: &Value) -> Option<String> {
        match validate_endpoint_schemes(&metadata(extra)) {
            Err(SsoError::UnsupportedEndpointScheme { endpoint, .. }) => Some(endpoint),
            _ => None,
        }
    }

    /// `DiscoveryError` keeps the actionable half of a failure (e.g. the JWKS
    /// body Authentik serves for a provider with no signing key, which is
    /// missing its `keys` member) in the source rather than the summary.
    #[derive(Debug, thiserror::Error)]
    #[error("missing field `keys`")]
    struct Detail;

    #[derive(Debug, thiserror::Error)]
    #[error("Failed to parse server response")]
    struct Summary(#[source] Detail);

    #[test]
    fn error_sources_are_reported_alongside_the_summary() {
        let described = describe_error(&Summary(Detail));
        assert_eq!(
            described,
            "Failed to parse server response: missing field `keys`"
        );
    }

    #[test]
    fn plain_https_document_is_accepted() {
        assert!(
            validate_endpoint_schemes(&metadata(&json!({
                "token_endpoint": "https://idp.example.com/token",
                "userinfo_endpoint": "https://idp.example.com/userinfo",
                "registration_endpoint": "https://idp.example.com/register",
                "end_session_endpoint": "https://idp.example.com/logout",
            })))
            .is_ok()
        );
    }

    #[test]
    fn http_is_accepted_for_providers_on_a_trusted_network() {
        assert!(
            validate_endpoint_schemes(&metadata(&json!({
                "authorization_endpoint": "http://keycloak.internal:8080/authorize",
                "end_session_endpoint": "http://keycloak.internal:8080/logout",
            })))
            .is_ok()
        );
    }

    #[test]
    fn javascript_authorization_endpoint_is_rejected() {
        // This one is handed to the browser by `GET /sso/providers/:name/start`.
        assert_eq!(
            rejected_endpoint(&json!({
                "authorization_endpoint": "javascript:alert(document.cookie)",
            }))
            .as_deref(),
            Some("authorization_endpoint")
        );
    }

    #[test]
    fn javascript_end_session_endpoint_is_rejected() {
        // This one is handed to the browser by `GET /sso/logout`.
        assert_eq!(
            rejected_endpoint(&json!({
                "end_session_endpoint": "javascript:alert(document.cookie)",
            }))
            .as_deref(),
            Some("end_session_endpoint")
        );
    }

    #[test]
    fn data_endpoints_are_rejected() {
        assert_eq!(
            rejected_endpoint(&json!({
                "authorization_endpoint": "data:text/html,<script>alert(1)</script>",
            }))
            .as_deref(),
            Some("authorization_endpoint")
        );
        assert_eq!(
            rejected_endpoint(&json!({
                "end_session_endpoint": "data:text/html,<script>alert(1)</script>",
            }))
            .as_deref(),
            Some("end_session_endpoint")
        );
    }

    #[test]
    fn server_side_endpoints_are_checked_too() {
        for endpoint in [
            "jwks_uri",
            "token_endpoint",
            "userinfo_endpoint",
            "registration_endpoint",
        ] {
            assert_eq!(
                rejected_endpoint(&json!({ endpoint: "file:///etc/passwd" })).as_deref(),
                Some(endpoint)
            );
        }
    }

    #[test]
    fn the_offending_url_is_reported() {
        let err = validate_endpoint_schemes(&metadata(&json!({
            "end_session_endpoint": "javascript:alert(1)",
        })))
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
        assert!(err.contains("javascript:alert(1)"), "{err}");
    }
}

use std::collections::HashMap;
use std::error::Error;
use std::fmt::Write;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use openidconnect::url::Url;
use openidconnect::{ProviderMetadataWithLogout, reqwest};
use tokio::sync::Mutex;
use warpgate_common_cache::Cache;

use crate::SsoError;
use crate::config::SsoInternalProviderConfig;

const METADATA_CACHE_TTL: Duration = Duration::from_secs(300);

// avoid refreshing on every request if metadata is simply bad
const METADATA_REFRESH_MIN_INTERVAL: Duration = Duration::from_secs(10);

/// Schemes an endpoint from a discovery document is allowed to use.
///
/// `https` is what the OIDC Discovery spec mandates; `http` is kept for
/// providers reached over a trusted network (test rigs, in-cluster IdPs).
const ALLOWED_ENDPOINT_SCHEMES: [&str; 2] = ["https", "http"];

// Providers can share an issuer while using different tenant metadata and keys.
type MetadataCacheKey = (String, Option<String>);

static METADATA_CACHE: LazyLock<Cache<MetadataCacheKey, (), ProviderMetadataWithLogout>> =
    LazyLock::new(|| Cache::new(METADATA_CACHE_TTL));

static LAST_FORCED_CACHE_EVICTION: LazyLock<Mutex<HashMap<MetadataCacheKey, Instant>>> =
    LazyLock::new(Default::default);

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
    let key = metadata_cache_key(config)?;
    METADATA_CACHE
        .get_or_build(&key, &(), || async {
            if let Some(url) = config.discovery_url() {
                check_endpoint_scheme("discovery_url", url)?;
                let response = http_client
                    .get(url.clone())
                    .header(reqwest::header::ACCEPT, "application/json")
                    .send()
                    .await
                    .map_err(|e| SsoError::Discovery(describe_error(&e)))?;
                if response.status() != reqwest::StatusCode::OK {
                    return Err(SsoError::Discovery(format!(
                        "HTTP status code {} at {url}", response.status()
                    )));
                }
                if let Some(content_type) = response.headers().get(reqwest::header::CONTENT_TYPE)
                    && !content_type.to_str().ok()
                        .and_then(|value| value.split(';').next())
                        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
                {
                    return Err(SsoError::Discovery(format!(
                        "unexpected response Content-Type {content_type:?} at {url}; expected application/json"
                    )));
                }
                let body = response.bytes().await
                    .map_err(|e| SsoError::Discovery(describe_error(&e)))?;
                let metadata: ProviderMetadataWithLogout = serde_path_to_error::deserialize(
                    &mut serde_json::Deserializer::from_slice(&body),
                )
                .map_err(|e| SsoError::Discovery(describe_error(&e)))?;
                if metadata.issuer() != &issuer {
                    return Err(SsoError::Discovery(format!(
                        "unexpected issuer URI `{}` (expected `{issuer}`)",
                        metadata.issuer()
                    )));
                }
                validate_endpoint_schemes(&metadata)?;
                let jwks = openidconnect::core::CoreJsonWebKeySet::fetch_async(
                    metadata.jwks_uri(),
                    http_client,
                )
                .await
                .map_err(|e| SsoError::Discovery(describe_error(&e)))?;
                return Ok(metadata.set_jwks(jwks));
            }
            let metadata = ProviderMetadataWithLogout::discover_async(issuer, http_client)
                .await
                .map_err(|e| SsoError::Discovery(describe_error(&e)))?;

            // Validate before caching, so a hostile document is never served from
            // the cache and never reaches a caller.
            validate_endpoint_schemes(&metadata)?;
            Ok(metadata)
        })
        .await
}

fn metadata_cache_key(config: &SsoInternalProviderConfig) -> Result<MetadataCacheKey, SsoError> {
    Ok((
        config.issuer_url()?.to_string(),
        config.discovery_url().map(ToString::to_string),
    ))
}

/// false = not evicted due to interval check
async fn evict_for_forced_refresh(key: &MetadataCacheKey) -> bool {
    let mut last = LAST_FORCED_CACHE_EVICTION.lock().await;
    if last
        .get(key)
        .is_some_and(|at| at.elapsed() < METADATA_REFRESH_MIN_INTERVAL)
    {
        return false;
    }
    last.insert(key.clone(), Instant::now());
    METADATA_CACHE.remove(key);
    true
}

pub async fn refresh_metadata(
    config: &SsoInternalProviderConfig,
    http_client: &reqwest::Client,
) -> Result<ProviderMetadataWithLogout, SsoError> {
    evict_for_forced_refresh(&metadata_cache_key(config)?).await;
    discover_metadata(config, http_client).await
}

#[cfg(test)]
pub mod tests {
    use serde_json::{Value, json};

    use super::{
        ProviderMetadataWithLogout, SsoError, describe_error, evict_for_forced_refresh,
        validate_endpoint_schemes,
    };

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

    #[tokio::test]
    async fn forced_refresh_is_throttled_per_metadata_source() {
        let a = ("https://a.example".to_owned(), None);
        let b = ("https://b.example".to_owned(), None);
        let tenant = (
            a.0.clone(),
            Some("https://tenant.example/discovery".to_owned()),
        );
        assert!(evict_for_forced_refresh(&a).await);
        assert!(!evict_for_forced_refresh(&a).await);
        assert!(evict_for_forced_refresh(&b).await);
        assert!(evict_for_forced_refresh(&tenant).await);
    }

    async fn discovery_server(issuer: Option<&str>) -> (String, tokio::task::JoinHandle<()>) {
        discovery_response_server(issuer, 200, Some("application/json"), |_| {}).await
    }

    async fn discovery_response_server(
        issuer: Option<&str>,
        status: u16,
        content_type: Option<&str>,
        modify: impl FnOnce(&mut Value),
    ) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let mut document = json!({
            "issuer": issuer.unwrap_or(&base),
            "authorization_endpoint": format!("{base}/authorize"),
            "jwks_uri": format!("{base}/keys"),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        });
        modify(&mut document);
        let document = document.to_string();
        let content_type = content_type
            .map(|value| format!("Content-Type: {value}\r\n"))
            .unwrap_or_default();
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = String::new();
                BufReader::new(&mut socket)
                    .read_line(&mut request)
                    .await
                    .unwrap();
                let (status, header, body) = if request.starts_with("GET /keys ") {
                    (200, "Content-Type: application/json\r\n", r#"{"keys":[]}"#)
                } else {
                    (status, content_type.as_str(), document.as_str())
                };
                let response = format!(
                    "HTTP/1.1 {status} Test\r\n{header}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });
        (base, task)
    }

    fn custom_config(issuer: &str, discovery: Option<String>) -> crate::SsoInternalProviderConfig {
        serde_json::from_value(json!({
            "type": "custom",
            "client_id": "test-client",
            "client_secret": "test-secret",
            "issuer_url": issuer,
            "discovery_url": discovery,
            "scopes": [],
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn custom_discovery_preserves_issuer_checks_and_isolates_tenants() {
        let issuer = "https://identity.oraclecloud.com/";
        let (first, first_task) = discovery_server(Some(issuer)).await;
        let (second, second_task) = discovery_server(Some(issuer)).await;
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let client = openidconnect::reqwest::Client::new();
        let first_config = custom_config(issuer, Some(format!("{first}/discovery")));
        let second_config = custom_config(issuer, Some(format!("{second}/discovery")));
        let a = super::discover_metadata(&first_config, &client)
            .await
            .unwrap();
        let b = super::discover_metadata(&second_config, &client)
            .await
            .unwrap();
        assert_eq!(a.issuer().as_str(), issuer);
        assert_eq!(b.issuer().as_str(), issuer);
        assert_ne!(a.jwks_uri(), b.jwks_uri());
        assert_eq!(a.jwks_uri().as_str(), format!("{first}/keys"));
        let refreshed = super::refresh_metadata(&first_config, &client)
            .await
            .unwrap();
        assert_eq!(refreshed.jwks_uri(), a.jwks_uri());

        let wrong_issuer = custom_config(
            "https://wrong.example/",
            first_config.discovery_url().map(ToString::to_string),
        );
        let error = super::discover_metadata(&wrong_issuer, &client)
            .await
            .unwrap_err();
        assert!(
            error.to_string().to_lowercase().contains("issuer"),
            "{error}"
        );
        first_task.abort();
        second_task.abort();
    }

    #[tokio::test]
    async fn standard_discovery_still_works_without_an_override() {
        let (base, task) = discovery_server(None).await;
        let config = custom_config(&base, None);
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let client = openidconnect::reqwest::Client::new();
        let metadata = super::discover_metadata(&config, &client).await.unwrap();
        assert_eq!(
            metadata.authorization_endpoint().as_str(),
            format!("{base}/authorize")
        );
        task.abort();
    }

    #[tokio::test]
    async fn custom_discovery_rejects_disallowed_schemes_and_endpoints() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let client = openidconnect::reqwest::Client::new();
        let config = custom_config(
            "https://issuer.example/",
            Some("file:///discovery.json".into()),
        );
        let error = super::discover_metadata(&config, &client)
            .await
            .unwrap_err();
        assert!(
            matches!(error, SsoError::UnsupportedEndpointScheme { endpoint, .. } if endpoint == "discovery_url")
        );

        let (base, task) = discovery_response_server(
            Some("https://issuer.example/"),
            200,
            Some("application/json"),
            |document| document["authorization_endpoint"] = json!("javascript:alert(1)"),
        )
        .await;
        let config = custom_config("https://issuer.example/", Some(format!("{base}/discovery")));
        let error = super::discover_metadata(&config, &client)
            .await
            .unwrap_err();
        assert!(
            matches!(error, SsoError::UnsupportedEndpointScheme { endpoint, .. } if endpoint == "authorization_endpoint")
        );
        task.abort();
    }

    #[tokio::test]
    async fn custom_discovery_validates_status_and_preserves_parse_details() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let client = openidconnect::reqwest::Client::new();
        for (status, content_type, missing, expected) in [
            (201, "application/json", false, "HTTP status code 201"),
            (503, "application/json", false, "HTTP status code 503"),
            (200, "text/html", false, "Content-Type"),
            (200, "application/json", true, "missing field `issuer`"),
        ] {
            let (base, task) = discovery_response_server(
                Some("https://issuer.example/"),
                status,
                Some(content_type),
                |document| {
                    if missing {
                        document.as_object_mut().unwrap().remove("issuer");
                    }
                },
            )
            .await;
            let config =
                custom_config("https://issuer.example/", Some(format!("{base}/discovery")));
            let error = super::discover_metadata(&config, &client)
                .await
                .unwrap_err();
            assert!(matches!(error, SsoError::Discovery(_)), "{error}");
            assert!(error.to_string().contains(expected), "{error}");
            task.abort();
        }
        let (base, task) = discovery_response_server(
            Some("https://issuer.example/"),
            200,
            Some("application/json"),
            |document| document["response_types_supported"] = json!([5]),
        )
        .await;
        let config = custom_config("https://issuer.example/", Some(format!("{base}/discovery")));
        let error = super::discover_metadata(&config, &client)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("response_types_supported[0]"),
            "{error}"
        );
        task.abort();
    }

    #[tokio::test]
    async fn custom_discovery_accepts_missing_or_parameterized_json_content_type() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let client = openidconnect::reqwest::Client::new();
        for content_type in [None, Some("Application/JSON; charset=utf-8")] {
            let (base, task) = discovery_response_server(
                Some("https://issuer.example/"),
                200,
                content_type,
                |_| {},
            )
            .await;
            let config =
                custom_config("https://issuer.example/", Some(format!("{base}/discovery")));
            super::discover_metadata(&config, &client).await.unwrap();
            task.abort();
        }
    }
}

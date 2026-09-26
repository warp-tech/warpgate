use std::borrow::Cow;
use std::collections::HashMap;

use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreAuthenticationFlow, CoreClientAuthMethod,
    CoreErrorResponseType, CoreGenderClaim, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm, CoreRevocableToken, CoreRevocationErrorResponse,
    CoreTokenIntrospectionResponse, CoreTokenType,
};
use openidconnect::url::Url;
use openidconnect::{
    AccessTokenHash, AdditionalClaims, Audience, AuthType, AuthorizationCode, Client, ClientSecret,
    CsrfToken, EmptyExtraTokenFields, EndpointMaybeSet, EndpointNotSet, EndpointSet,
    HttpClientError, IdToken, IdTokenClaims, IdTokenFields, LogoutRequest, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, PostLogoutRedirectUrl,
    ProviderMetadataWithLogout, RedirectUrl, RequestTokenError, Scope, StandardErrorResponse,
    StandardTokenResponse, TokenResponse, UserInfoClaims, UserInfoError, reqwest,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::config::SsoInternalProviderConfig;
use crate::request::SsoLoginRequest;
use crate::{SsoError, discover_metadata};

/// A single entry in a group-style claim: either a bare string, or a
/// SCIM-style object (RFC 7643) from which we take `value` (stable group ID)
/// and `display` (human-readable name).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum GroupClaimEntry {
    Str(String),
    Obj {
        #[serde(default)]
        value: Option<String>,
        #[serde(default)]
        display: Option<String>,
    },
}

/// A group-style claim value: a single entry, or an array of entries
/// (strings and/or objects, mixed). Some OIDC providers return a single
/// value as a bare scalar rather than a one-element array; both are accepted.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum GroupClaim {
    One(GroupClaimEntry),
    Many(Vec<GroupClaimEntry>),
}

/// Flatten a group claim into a sorted, de-duplicated list of strings.
///
/// For object entries BOTH `value` and `display` are emitted (when present),
/// so role mappings may be keyed on either the stable group ID or its name.
/// (A collision between one group's `display` and another's `value` would map
/// both -- effectively impossible with opaque IDs.)
pub fn flatten_group_claim(claim: GroupClaim) -> Vec<String> {
    let entries = match claim {
        GroupClaim::One(e) => vec![e],
        GroupClaim::Many(v) => v,
    };
    let mut out: Vec<String> = entries
        .into_iter()
        .flat_map(|e| match e {
            GroupClaimEntry::Str(s) => vec![s],
            GroupClaimEntry::Obj { value, display } => {
                [value, display].into_iter().flatten().collect()
            }
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(transparent)]
pub struct WarpgateClaims(
    /// Flat map of claims since role claim names are configurable
    pub HashMap<String, serde_json::Value>,
);

impl AdditionalClaims for WarpgateClaims {}

pub type WarpgateIdToken = IdToken<
    WarpgateClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

type WarpgateIdTokenClaims = IdTokenClaims<WarpgateClaims, CoreGenderClaim>;

type WarpgateTokenResponse = StandardTokenResponse<
    IdTokenFields<
        WarpgateClaims,
        EmptyExtraTokenFields,
        CoreGenderClaim,
        CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
    >,
    CoreTokenType,
>;

type WarpgateClient = Client<
    WarpgateClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    WarpgateTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointSet,      // HasAuthUrl
    EndpointNotSet,   // HasDeviceAuthUrl
    EndpointNotSet,   // HasIntrospectionUrl
    EndpointNotSet,   // HasRevocationUrl
    EndpointMaybeSet, // HasTokenUrl
    EndpointMaybeSet, // HasUserInfoUrl
>;

pub struct SsoResult {
    pub token: WarpgateIdToken,
    pub claims: WarpgateIdTokenClaims,
    pub userinfo_claims: Option<UserInfoClaims<WarpgateClaims, CoreGenderClaim>>,
}

pub struct SsoClient {
    config: SsoInternalProviderConfig,
    http_client: reqwest::Client,
}

/// Extract the `iss` claim from a raw JWT **without** verifying its signature.
///
/// Used only as a routing hint to pick which SSO provider should fully verify a
/// bearer token, so we can skip issuer discovery for unrelated providers. The
/// result is never trusted for any security decision.
pub fn unverified_issuer(id_token_str: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct IssuerClaim {
        iss: Option<String>,
    }

    jsonwebtoken::dangerous::insecure_decode::<IssuerClaim>(id_token_str)
        .ok()?
        .claims
        .iss
}

/// `UserInfoError`'s own Display drops the response body and its Debug renders
/// it as a byte array, both of which hide the provider's actual error message.
fn describe_userinfo_error(err: &UserInfoError<HttpClientError<reqwest::Error>>) -> String {
    match err {
        UserInfoError::Response(status, body, _) => {
            format!("HTTP {status}: {}", String::from_utf8_lossy(body))
        }
        e => format!("{e}"),
    }
}

/// Whether HTTP Basic client authentication would transmit this secret intact.
///
/// RFC 6749 section 2.3.1 requires the client secret to be form-urlencoded before it
/// is base64'd into the `Authorization: Basic` credentials, and `oauth2` does
/// exactly that. Providers are supposed to decode it again, but several
/// (Authentik among them) compare the raw header value against the stored
/// secret, so a secret containing `+`, `=` or `/` arrives as its percent-encoded
/// form and is rejected as `invalid_client`.
fn secret_survives_basic_auth(secret: &ClientSecret) -> bool {
    let raw = secret.secret();
    form_urlencoded::byte_serialize(raw.as_bytes()).collect::<String>() == *raw
}

/// A provider that omits `token_endpoint_auth_methods_supported` defaults to
/// `client_secret_basic` alone (OIDC Discovery section 3), so an absent list is a no.
fn advertises_secret_post(metadata: &ProviderMetadataWithLogout) -> bool {
    metadata
        .token_endpoint_auth_methods_supported()
        .is_some_and(|methods| methods.contains(&CoreClientAuthMethod::ClientSecretPost))
}

/// Pick the client authentication method for the token endpoint.
///
/// Basic auth is the RFC's recommendation and stays the default, but it is only
/// unambiguous for secrets that form-urlencoding leaves alone. For the rest,
/// `client_secret_post` carries the secret verbatim and both sides agree on it.
fn resolve_auth_type(
    configured: AuthType,
    secret: &ClientSecret,
    metadata: &ProviderMetadataWithLogout,
) -> AuthType {
    if !matches!(configured, AuthType::BasicAuth) || secret_survives_basic_auth(secret) {
        return configured;
    }
    if advertises_secret_post(metadata) {
        debug!("Client secret needs escaping for basic auth; using client_secret_post instead");
        return AuthType::RequestBody;
    }
    warn!(
        "Client secret contains characters that must be escaped for basic auth, and the provider does not advertise client_secret_post. If authentication fails with invalid_client, rotate the secret to one made up of letters, digits and `-._*`."
    );
    configured
}

async fn make_client(
    config: &SsoInternalProviderConfig,
    http_client: &reqwest::Client,
) -> Result<WarpgateClient, SsoError> {
    let metadata = discover_metadata(config, http_client).await?;
    let secret = config.client_secret()?;
    let auth_type = resolve_auth_type(config.auth_type(), &secret, &metadata);

    let client =
        WarpgateClient::from_provider_metadata(metadata, config.client_id().clone(), Some(secret))
            .set_auth_type(auth_type);

    Ok(client)
}

impl SsoClient {
    pub fn new(config: SsoInternalProviderConfig) -> Result<Self, SsoError> {
        Ok(Self {
            config,
            http_client: reqwest::ClientBuilder::new().build()?,
        })
    }

    pub async fn supports_single_logout(&self) -> Result<bool, SsoError> {
        let metadata = discover_metadata(&self.config, &self.http_client).await?;
        Ok(metadata
            .additional_metadata()
            .end_session_endpoint
            .is_some())
    }

    pub async fn start_login(&self, redirect_url: String) -> Result<SsoLoginRequest, SsoError> {
        let redirect_url = RedirectUrl::new(redirect_url)?;
        let client: WarpgateClient = make_client(&self.config, &self.http_client).await?;
        let mut auth_req = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_redirect_uri(Cow::Owned(redirect_url.clone()));

        for (k, v) in self.config.extra_parameters() {
            auth_req = auth_req.add_extra_param(k, v);
        }

        for scope in self.config.scopes() {
            auth_req = auth_req.add_scope(Scope::new(scope.clone()));
        }

        let pkce_verifier = if self.config.needs_pkce_verifier() {
            let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
            auth_req = auth_req.set_pkce_challenge(pkce_challenge);
            Some(pkce_verifier)
        } else {
            None
        };

        let (auth_url, csrf_token, nonce) = auth_req.url();

        Ok(SsoLoginRequest {
            auth_url,
            csrf_token,
            nonce,
            pkce_verifier,
            redirect_url,
            config: self.config.clone(),
        })
    }

    pub async fn finish_login(
        &self,
        pkce_verifier: Option<PkceCodeVerifier>,
        redirect_url: RedirectUrl,
        nonce: &Nonce,
        code: String,
    ) -> Result<SsoResult, SsoError> {
        let client: WarpgateClient = make_client(&self.config, &self.http_client)
            .await?
            .set_redirect_uri(redirect_url);

        let mut req = client.exchange_code(AuthorizationCode::new(code))?;
        if let Some(verifier) = pkce_verifier {
            req = req.set_pkce_verifier(verifier);
        }

        let token_response = req.request_async(&self.http_client).await.map_err(
            |e: RequestTokenError<
                HttpClientError<reqwest::Error>,
                StandardErrorResponse<CoreErrorResponseType>,
            >| match e {
                RequestTokenError::ServerResponse(response) => SsoError::Verification(format!(
                    "{}: {:?}",
                    response.error(),
                    response.error_description()
                )),
                RequestTokenError::Parse(err, path) => SsoError::Verification(format!(
                    "Parse error: {:?} / {:?}",
                    err,
                    String::from_utf8_lossy(&path)
                )),
                e => SsoError::Verification(format!("{e}")),
            },
        )?;

        let mut token_verifier = client.id_token_verifier();

        if let Some(trusted_audiences) = self.config.additional_trusted_audiences() {
            token_verifier = token_verifier.set_other_audience_verifier_fn(|aud: &Audience| {
                trusted_audiences.contains(&**aud)
            });
        }

        if self.config.trust_unknown_audiences() {
            token_verifier = token_verifier.set_other_audience_verifier_fn(|_aud| true);
        }

        let id_token: &WarpgateIdToken = token_response.id_token().ok_or(SsoError::NotOidc)?;
        let claims = id_token.claims(&token_verifier, nonce)?;

        let user_info_req = client
            .user_info(token_response.access_token().to_owned(), None)
            .map_err(|err| {
                debug!("Provider has no usable userinfo endpoint: {err}");
                err
            })
            .ok();

        let userinfo_claims: Option<UserInfoClaims<WarpgateClaims, CoreGenderClaim>> =
            if let Some(user_info_req) = user_info_req {
                match user_info_req.request_async(&self.http_client).await {
                    Ok(userinfo) => Some(userinfo),
                    Err(err) => {
                        warn!(
                            "Failed to fetch userinfo: {}",
                            describe_userinfo_error(&err)
                        );
                        None
                    }
                }
            } else {
                None
            };

        if let Some(expected_access_token_hash) = claims.access_token_hash() {
            let actual_access_token_hash = AccessTokenHash::from_token(
                token_response.access_token(),
                id_token.signing_alg()?,
                id_token.signing_key(&token_verifier)?,
            )?;
            if actual_access_token_hash != *expected_access_token_hash {
                return Err(SsoError::Mitm);
            }
        }

        Ok(SsoResult {
            token: id_token.clone(),
            userinfo_claims,
            claims: claims.clone(),
        })
    }

    /// Verify a raw OIDC ID token (e.g. from a kubectl exec plugin) without a
    /// code exchange or nonce. Validates signature against the issuer JWKS and
    /// checks `iss`, `exp` and `aud` (honouring the provider's trusted-audience
    /// configuration).
    pub async fn verify_id_token(&self, id_token_str: &str) -> Result<SsoResult, SsoError> {
        // Parse first, so a non-JWT bearer token (e.g. an API token) is rejected
        // before we make any network call to the issuer.
        let id_token: WarpgateIdToken = id_token_str
            .parse()
            .map_err(|e| SsoError::Verification(format!("Malformed ID token: {e}")))?;

        // Capture audience-check configuration before building the verifier.
        let trusted: Vec<String> = self
            .config
            .additional_trusted_audiences()
            .cloned()
            .unwrap_or_default();
        let trust_unknown = self.config.trust_unknown_audiences();
        let client_id = self.config.client_id().as_str().to_owned();

        let client: WarpgateClient = make_client(&self.config, &self.http_client).await?;

        // Disable the built-in audience check so we can enforce it ourselves
        // below.  Signature / iss / exp are still fully enforced.
        let token_verifier = client.id_token_verifier().require_audience_match(false);

        // No nonce in a non-interactive flow: accept any (absent) nonce.
        let claims = id_token
            .claims(&token_verifier, |_: Option<&Nonce>| Ok::<(), String>(()))?
            .clone();

        // Manual audience enforcement: a token is accepted iff its audience
        // contains Warpgate's own client_id OR any configured trusted audience.
        // When trust_unknown_audiences is true we skip the check entirely
        // (documented semantics), but signature/iss/exp are always enforced.
        if !trust_unknown {
            let auds = claims.audiences();
            let ok = auds.iter().any(|a| {
                let a = a.as_str();
                a == client_id || trusted.iter().any(|t| t == a)
            });
            if !ok {
                return Err(SsoError::Verification(format!(
                    "ID token audience not trusted (audiences: {})",
                    auds.iter()
                        .map(|a| a.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
        }

        Ok(SsoResult {
            token: id_token,
            claims,
            userinfo_claims: None,
        })
    }

    /// Verify a raw ID token and map it to a SsoLoginResponse in one call.
    pub async fn verify_id_token_to_response(
        &self,
        id_token_str: &str,
    ) -> Result<crate::SsoLoginResponse, SsoError> {
        let result = self.verify_id_token(id_token_str).await?;
        Ok(crate::request::map_sso_result(&self.config, result).await)
    }

    pub async fn logout(&self, token: WarpgateIdToken, redirect_url: Url) -> Result<Url, SsoError> {
        let metadata = discover_metadata(&self.config, &self.http_client).await?;
        let Some(ref url) = metadata.additional_metadata().end_session_endpoint else {
            return Err(SsoError::LogoutNotSupported);
        };
        let mut req: LogoutRequest = url.clone().into();
        req = req.set_id_token_hint(&token);
        req = req.set_client_id(self.config.client_id().clone());
        req = req.set_post_logout_redirect_uri(PostLogoutRedirectUrl::from_url(redirect_url));
        Ok(req.http_get_url())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        AuthType, ClientSecret, GroupClaim, advertises_secret_post, flatten_group_claim,
        resolve_auth_type, secret_survives_basic_auth,
    };
    use crate::metadata::tests::metadata;

    fn survives(secret: &str) -> bool {
        secret_survives_basic_auth(&ClientSecret::new(secret.to_owned()))
    }

    #[test]
    fn url_safe_secrets_survive_basic_auth() {
        assert!(survives(""));
        assert!(survives("abcXYZ0189"));
        assert!(survives("a-b_c.d*e"));
    }

    #[test]
    fn secrets_needing_escaping_do_not() {
        // The characters from issue #1815, plus the rest of base64's alphabet
        // and a few that form-urlencoding also rewrites.
        for secret in ["a+b", "ab==", "a/b", "a b", "a:b", "a%b", "pä"] {
            assert!(!survives(secret), "{secret} was considered safe");
        }
    }

    #[test]
    fn secret_post_is_taken_from_the_discovery_document() {
        assert!(!advertises_secret_post(&metadata(&json!({}))));
        assert!(!advertises_secret_post(&metadata(&json!({
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        }))));
        assert!(advertises_secret_post(&metadata(&json!({
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        }))));
    }

    fn resolved(secret: &str, extra: &serde_json::Value) -> AuthType {
        resolve_auth_type(
            AuthType::BasicAuth,
            &ClientSecret::new(secret.to_owned()),
            &metadata(extra),
        )
    }

    #[test]
    fn only_an_unsafe_secret_switches_to_secret_post() {
        let both = json!({
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        });

        assert!(matches!(resolved("urlsafe", &both), AuthType::BasicAuth));
        assert!(matches!(
            resolved("has+plus=", &both),
            AuthType::RequestBody
        ));
        // Nothing to switch to: basic auth is attempted and the admin is warned.
        assert!(matches!(
            resolved("has+plus=", &json!({})),
            AuthType::BasicAuth
        ));
    }

    fn flat(j: serde_json::Value) -> Vec<String> {
        flatten_group_claim(serde_json::from_value::<GroupClaim>(j).unwrap())
    }

    #[test]
    fn bare_string() {
        assert_eq!(flat(json!("a")), vec!["a".to_string()]);
    }

    #[test]
    fn array_of_strings_sorted() {
        assert_eq!(
            flat(json!(["b", "a"])),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn single_object_value_and_display() {
        assert_eq!(
            flat(json!({"value": "id1", "display": "Admins"})),
            vec!["Admins".to_string(), "id1".to_string()]
        );
    }

    #[test]
    fn array_of_objects() {
        assert_eq!(
            flat(json!([
                {"value": "id1", "display": "Admins"},
                {"value": "id2", "display": "Users"}
            ])),
            vec![
                "Admins".to_string(),
                "Users".to_string(),
                "id1".to_string(),
                "id2".to_string()
            ]
        );
    }

    #[test]
    fn mixed_strings_and_partial_objects() {
        assert_eq!(
            flat(json!(["x", {"display": "D"}, {"value": "V"}])),
            vec!["D".to_string(), "V".to_string(), "x".to_string()]
        );
    }

    #[test]
    fn deduplicates() {
        assert_eq!(flat(json!(["a", "a"])), vec!["a".to_string()]);
    }

    #[test]
    fn empty_array() {
        assert!(flat(json!([])).is_empty());
    }

    #[test]
    fn object_without_value_or_display() {
        assert!(flat(json!([{"foo": "bar"}])).is_empty());
    }

    #[test]
    fn complex_mixed_objects_with_cross_dedup_and_spaces() {
        // value/display collisions across entries (e.g. two groups sharing a
        // display, a display equal to another entry's string) must all collapse
        // to a single sorted, de-duplicated set. A value containing a space
        // sorts before non-space characters.
        assert_eq!(
            flat(json!([
                "bla",
                {"value": "val1", "display": "dis1"},
                {"value": "val2", "display": "dis1"},
                {"value": "val1", "display": "dis2"},
                "bla2",
                {"value": "val 3", "display": "bla2"}
            ])),
            vec![
                "bla".to_string(),
                "bla2".to_string(),
                "dis1".to_string(),
                "dis2".to_string(),
                "val 3".to_string(),
                "val1".to_string(),
                "val2".to_string(),
            ]
        );
    }
}

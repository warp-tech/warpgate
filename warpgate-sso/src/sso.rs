use std::borrow::Cow;

use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreAuthenticationFlow, CoreErrorResponseType,
    CoreGenderClaim, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
    CoreRevocableToken, CoreRevocationErrorResponse, CoreTokenIntrospectionResponse, CoreTokenType,
};
use openidconnect::url::Url;
use openidconnect::{
    AccessTokenHash, AdditionalClaims, Audience, AuthorizationCode, Client, CsrfToken,
    DiscoveryError, EmptyExtraTokenFields, EndpointMaybeSet, EndpointNotSet, EndpointSet,
    HttpClientError, IdToken, IdTokenClaims, IdTokenFields, LogoutRequest, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, PostLogoutRedirectUrl,
    ProviderMetadataWithLogout, RedirectUrl, RequestTokenError, Scope, StandardErrorResponse,
    StandardTokenResponse, TokenResponse, UserInfoClaims, reqwest,
};
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::SsoError;
use crate::config::SsoInternalProviderConfig;
use crate::request::SsoLoginRequest;

/// Deserialize a value that may be either a single string or a sequence of strings.
///
/// Some OIDC providers (e.g. oidc-mock) return a single claim value
/// as a bare string rather than a one-element array.
/// This deserializer accepts both forms.
fn string_or_vec<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrVec {
        String(String),
        Vec(Vec<String>),
    }

    Option::<StringOrVec>::deserialize(deserializer).map(|opt| {
        opt.map(|sv| match sv {
            StringOrVec::String(s) => vec![s],
            StringOrVec::Vec(v) => v,
        })
    })
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WarpgateClaims {
    #[serde(default, deserialize_with = "string_or_vec")]
    pub warpgate_roles: Option<Vec<String>>,
    #[serde(default, deserialize_with = "string_or_vec")]
    pub warpgate_admin_roles: Option<Vec<String>>,
}

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

pub async fn discover_metadata(
    config: &SsoInternalProviderConfig,
    http_client: &reqwest::Client,
) -> Result<ProviderMetadataWithLogout, SsoError> {
    ProviderMetadataWithLogout::discover_async(config.issuer_url()?, http_client)
        .await
        .map_err(|e| {
            SsoError::Discovery(match e {
                DiscoveryError::Request(inner) => format!("Request error: {inner:?}"),
                e => format!("{e}"),
            })
        })
}

async fn make_client(
    config: &SsoInternalProviderConfig,
    http_client: &reqwest::Client,
) -> Result<WarpgateClient, SsoError> {
    let metadata = discover_metadata(config, http_client).await?;

    let client = WarpgateClient::from_provider_metadata(
        metadata,
        config.client_id().clone(),
        Some(config.client_secret()?),
    )
    .set_auth_type(config.auth_type());

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
                error!("Failed to fetch userinfo: {err:?}");
                err
            })
            .ok();

        let userinfo_claims: Option<UserInfoClaims<WarpgateClaims, CoreGenderClaim>> =
            if let Some(user_info_req) = user_info_req {
                match user_info_req.request_async(&self.http_client).await {
                    Ok(userinfo) => Some(userinfo),
                    Err(err) => {
                        error!("Failed to fetch userinfo: {err:?}");
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

        let id_token: WarpgateIdToken = id_token_str
            .parse()
            .map_err(|e| SsoError::Verification(format!("Malformed ID token: {e}")))?;

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

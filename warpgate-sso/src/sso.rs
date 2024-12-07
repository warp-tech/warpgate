use std::borrow::Cow;
use std::ops::Deref;

use futures::future::OptionFuture;
use openidconnect::core::{
    CoreAuthenticationFlow, CoreClient, CoreGenderClaim, CoreIdToken, CoreIdTokenClaims,
};
use openidconnect::reqwest::async_http_client;
use openidconnect::url::Url;
use openidconnect::{
    AccessTokenHash, AdditionalClaims, AuthorizationCode, CsrfToken, DiscoveryError, LogoutRequest,
    Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, PostLogoutRedirectUrl,
    ProviderMetadataWithLogout, RedirectUrl, RequestTokenError, Scope, TokenResponse,
    UserInfoClaims,
};
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::config::SsoInternalProviderConfig;
use crate::request::SsoLoginRequest;
use crate::SsoError;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WarpgateClaims {
    // This uses the "warpgate_roles" claim from OIDC
    pub warpgate_roles: Option<Vec<String>>,
}

impl AdditionalClaims for WarpgateClaims {}

pub struct SsoResult {
    pub token: CoreIdToken,
    pub claims: CoreIdTokenClaims,
    pub userinfo_claims: Option<UserInfoClaims<WarpgateClaims, CoreGenderClaim>>,
}

pub struct SsoClient {
    config: SsoInternalProviderConfig,
}

pub async fn discover_metadata(
    config: &SsoInternalProviderConfig,
) -> Result<ProviderMetadataWithLogout, SsoError> {
    ProviderMetadataWithLogout::discover_async(config.issuer_url()?, async_http_client)
        .await
        .map_err(|e| {
            SsoError::Discovery(match e {
                DiscoveryError::Request(inner) => format!("Request error: {inner}"),
                e => format!("{e}"),
            })
        })
}

async fn make_client(config: &SsoInternalProviderConfig) -> Result<CoreClient, SsoError> {
    let metadata = discover_metadata(config).await?;

    let client = CoreClient::from_provider_metadata(
        metadata,
        config.client_id().clone(),
        Some(config.client_secret()?),
    )
    .set_auth_type(config.auth_type());

    Ok(client)
}

impl SsoClient {
    pub fn new(config: SsoInternalProviderConfig) -> Self {
        Self { config }
    }

    pub async fn supports_single_logout(&self) -> Result<bool, SsoError> {
        let metadata = discover_metadata(&self.config).await?;
        Ok(metadata
            .additional_metadata()
            .end_session_endpoint
            .is_some())
    }

    pub async fn start_login(&self, redirect_url: String) -> Result<SsoLoginRequest, SsoError> {
        let redirect_url = RedirectUrl::new(redirect_url)?;
        let client = make_client(&self.config).await?;
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
            auth_req = auth_req.add_scope(Scope::new(scope.to_string()));
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
        let client = make_client(&self.config)
            .await?
            .set_redirect_uri(redirect_url);

        let mut req = client.exchange_code(AuthorizationCode::new(code));
        if let Some(verifier) = pkce_verifier {
            req = req.set_pkce_verifier(verifier);
        }

        let token_response = req
            .request_async(async_http_client)
            .await
            .map_err(|e| match e {
                RequestTokenError::ServerResponse(response) => {
                    SsoError::Verification(response.error().to_string())
                }
                RequestTokenError::Parse(err, path) => SsoError::Verification(format!(
                    "Parse error: {:?} / {:?}",
                    err,
                    String::from_utf8_lossy(&path)
                )),
                e => SsoError::Verification(format!("{e}")),
            })?;

        let mut token_verifier = client.id_token_verifier();
        dbg!(self.config.additional_trusted_audiences());

        if let Some(trusted_audiences) = self.config.additional_trusted_audiences() {
            token_verifier = token_verifier.set_other_audience_verifier_fn(|aud| {
                dbg!(aud);
                trusted_audiences.contains(aud.deref())
            });
        }

        let id_token: &CoreIdToken = token_response.id_token().ok_or(SsoError::NotOidc)?;
        let claims = id_token.claims(&token_verifier, nonce)?;

        let user_info_req = client
            .user_info(token_response.access_token().to_owned(), None)
            .map_err(|err| {
                error!("Failed to fetch userinfo: {err:?}");
                err
            })
            .ok();

        let userinfo_claims: Option<UserInfoClaims<WarpgateClaims, CoreGenderClaim>> =
            OptionFuture::from(user_info_req.map(|req| req.request_async(async_http_client)))
                .await
                .and_then(|res| {
                    res.map_err(|err| {
                        error!("Failed to fetch userinfo: {err:?}");
                        err
                    })
                    .ok()
                });

        if let Some(expected_access_token_hash) = claims.access_token_hash() {
            let actual_access_token_hash = AccessTokenHash::from_token(
                token_response.access_token(),
                &id_token.signing_alg()?,
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

    pub async fn logout(&self, token: CoreIdToken, redirect_url: Url) -> Result<Url, SsoError> {
        let metadata = discover_metadata(&self.config).await?;
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

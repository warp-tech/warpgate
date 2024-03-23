use futures::future::OptionFuture;
use openidconnect::core::CoreGenderClaim;
use openidconnect::reqwest::async_http_client;
use openidconnect::url::Url;
use openidconnect::{
    AccessTokenHash, AdditionalClaims, AuthorizationCode, CsrfToken, Nonce, OAuth2TokenResponse,
    PkceCodeVerifier, RedirectUrl, RequestTokenError, TokenResponse, UserInfoClaims,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, error};

#[derive(Debug, Deserialize, Serialize, Clone)]
struct WarpgateClaims {
    // This uses the "warpgate_groups" claim from OIDC
    warpgate_groups: Option<Vec<String>>,
}

impl AdditionalClaims for WarpgateClaims {}

use crate::{make_client, SsoError, SsoInternalProviderConfig, SsoLoginResponse};

#[derive(Serialize, Deserialize, Debug)]
pub struct SsoLoginRequest {
    pub(crate) auth_url: Url,
    pub(crate) csrf_token: CsrfToken,
    pub(crate) nonce: Nonce,
    pub(crate) redirect_url: RedirectUrl,
    pub(crate) pkce_verifier: Option<PkceCodeVerifier>,
    pub(crate) config: SsoInternalProviderConfig,
}

impl SsoLoginRequest {
    pub fn auth_url(&self) -> &Url {
        &self.auth_url
    }

    pub fn csrf_token(&self) -> &CsrfToken {
        &self.csrf_token
    }

    pub async fn verify_code(self, code: String) -> Result<SsoLoginResponse, SsoError> {
        let client = make_client(&self.config)
            .await?
            .set_redirect_uri(self.redirect_url.clone());

        let mut req = client.exchange_code(AuthorizationCode::new(code));
        if let Some(verifier) = self.pkce_verifier {
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

        let id_token = token_response.id_token().ok_or(SsoError::NotOidc)?;
        let claims = id_token.claims(&client.id_token_verifier(), &self.nonce)?;

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

        debug!("OIDC claims: {:?}", claims);
        debug!("OIDC userinfo claims: {:?}", userinfo_claims);

        macro_rules! get_claim {
            ($method:ident) => {
                claims
                    .$method()
                    .or(userinfo_claims.as_ref().and_then(|x| x.$method()))
            };
        }

        Ok(SsoLoginResponse {
            name: get_claim!(name)
                .and_then(|x| x.get(None))
                .map(|x| x.as_str())
                .map(ToString::to_string),

            email: get_claim!(email)
                .map(|x| x.as_str())
                .map(ToString::to_string),

            email_verified: get_claim!(email_verified),

            groups: userinfo_claims.and_then(|x| x.additional_claims().warpgate_groups.clone()),
        })
    }
}

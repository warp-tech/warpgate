use openidconnect::reqwest::async_http_client;
use openidconnect::url::Url;
use openidconnect::{
    AccessTokenHash, AuthorizationCode, CsrfToken, Nonce, OAuth2TokenResponse, PkceCodeVerifier,
    RedirectUrl, RequestTokenError, TokenResponse,
};
use serde::{Deserialize, Serialize};

use crate::{make_client, SsoError, SsoInternalProviderConfig, SsoLoginResponse};

#[derive(Serialize, Deserialize, Debug)]
pub struct SsoLoginRequest {
    pub(crate) auth_url: Url,
    pub(crate) csrf_token: CsrfToken,
    pub(crate) nonce: Nonce,
    pub(crate) redirect_url: RedirectUrl,
    pub(crate) pkce_verifier: PkceCodeVerifier,
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

        let token_response = client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(self.pkce_verifier)
            .request_async(async_http_client)
            .await
            .map_err(|e| match e {
                RequestTokenError::ServerResponse(response) => {
                    SsoError::Verification(response.error().to_string())
                }
                e => SsoError::Verification(format!("{e}")),
            })?;

        let id_token = token_response.id_token().ok_or(SsoError::NotOidc)?;
        let claims = id_token.claims(&client.id_token_verifier(), &self.nonce)?;

        if let Some(expected_access_token_hash) = claims.access_token_hash() {
            let actual_access_token_hash = AccessTokenHash::from_token(
                token_response.access_token(),
                &id_token.signing_alg()?,
            )?;
            if actual_access_token_hash != *expected_access_token_hash {
                return Err(SsoError::Mitm);
            }
        }

        Ok(SsoLoginResponse {
            name: claims
                .name()
                .and_then(|x| x.get(None))
                .map(|x| x.as_str())
                .map(ToString::to_string),
            email: claims.email().map(|x| x.as_str()).map(ToString::to_string),
            email_verified: claims.email_verified(),
        })
    }
}

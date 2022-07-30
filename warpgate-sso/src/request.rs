use openidconnect::core::CoreClient;
use openidconnect::reqwest::async_http_client;
use openidconnect::url::Url;
use openidconnect::{
    AccessTokenHash, AuthorizationCode, CsrfToken, Nonce, OAuth2TokenResponse, PkceCodeVerifier,
    TokenResponse,
};

use crate::SsoLoginResponse;

pub struct SsoLoginRequest {
    pub(crate) auth_url: Url,
    pub(crate) csrf_token: CsrfToken,
    pub(crate) nonce: Nonce,
    pub(crate) pkce_verifier: PkceCodeVerifier,
    pub(crate) client: CoreClient,
}

impl SsoLoginRequest {
    pub fn auth_url(&self) -> &Url {
        &self.auth_url
    }

    pub fn csrf_token(&self) -> &CsrfToken {
        &self.csrf_token
    }

    pub async fn verify_code(self, code: String) -> SsoLoginResponse {
        let token_response = self
            .client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(self.pkce_verifier)
            .request_async(async_http_client)
            .await
            .expect("verify");

        let id_token = token_response
            .id_token()
            .expect("Server did not return an ID token");
        let claims = id_token
            .claims(&self.client.id_token_verifier(), &self.nonce)
            .expect("idtoken claims");

        if let Some(expected_access_token_hash) = claims.access_token_hash() {
            let actual_access_token_hash = AccessTokenHash::from_token(
                token_response.access_token(),
                &id_token.signing_alg().expect("signing alg"),
            )
            .expect("hash");
            if actual_access_token_hash != *expected_access_token_hash {
                panic!("Invalid access token");
            }
        }

        SsoLoginResponse {
            name: claims
                .name()
                .and_then(|x| x.get(None))
                .map(|x| x.as_str())
                .map(ToString::to_string),
            email: claims.email().map(|x| x.as_str()).map(ToString::to_string),
            email_verified: claims.email_verified(),
        }
    }
}

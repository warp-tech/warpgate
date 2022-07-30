use std::borrow::Cow;

use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::reqwest::async_http_client;
use openidconnect::{CsrfToken, Nonce, PkceCodeChallenge, RedirectUrl, Scope};

use crate::config::SsoProviderConfig;
use crate::request::SsoLoginRequest;
use crate::SsoError;

pub struct SsoClient {
    config: SsoProviderConfig,
    provider_metadata: CoreProviderMetadata,
}

impl SsoClient {
    pub async fn new(config: SsoProviderConfig) -> Result<Self, SsoError> {
        let provider_metadata =
            CoreProviderMetadata::discover_async(config.issuer_url().clone(), async_http_client)
                .await
                .map_err(|e| SsoError::Discovery(format!("{e}")))?;

        Ok(Self {
            config,
            provider_metadata,
        })
    }

    fn make_client(&self) -> CoreClient {
        CoreClient::from_provider_metadata(
            self.provider_metadata.clone(),
            self.config.client_id().clone(),
            Some(self.config.client_secret().clone()),
        )
    }

    pub fn start_login(&self, redirect_url: String) -> Result<SsoLoginRequest, SsoError> {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let client = self.make_client();
        let mut auth_req = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_redirect_uri(Cow::Owned(RedirectUrl::new(redirect_url)?));

        for scope in vec!["email", "profile"] {
            auth_req = auth_req.add_scope(Scope::new(scope.to_string()));
        }

        let (auth_url, csrf_token, nonce) = auth_req.set_pkce_challenge(pkce_challenge).url();

        Ok(SsoLoginRequest {
            auth_url,
            csrf_token,
            nonce,
            pkce_verifier,
            client,
        })
    }
}

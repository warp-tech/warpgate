use std::borrow::Cow;

use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::reqwest::async_http_client;
use openidconnect::{CsrfToken, Nonce, PkceCodeChallenge, RedirectUrl, Scope};

use crate::config::SsoInternalProviderConfig;
use crate::request::SsoLoginRequest;
use crate::SsoError;

pub struct SsoClient {
    config: SsoInternalProviderConfig,
}

pub async fn make_client(config: &SsoInternalProviderConfig) -> Result<CoreClient, SsoError> {
    let metadata =
        CoreProviderMetadata::discover_async(config.issuer_url()?, async_http_client)
            .await
            .map_err(|e| SsoError::Discovery(format!("{e}")))?;
    Ok(CoreClient::from_provider_metadata(
        metadata,
        config.client_id().clone(),
        Some(config.client_secret().clone()),
    ))
}

impl SsoClient {
    pub fn new(config: SsoInternalProviderConfig) -> Self {
        Self { config }
    }

    pub async fn start_login(&self, redirect_url: String) -> Result<SsoLoginRequest, SsoError> {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let redirect_url = RedirectUrl::new(redirect_url)?;
        let client = make_client(&self.config).await?;
        let mut auth_req = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_redirect_uri(Cow::Owned(redirect_url.clone()));

        for scope in self.config.scopes() {
            auth_req = auth_req.add_scope(Scope::new(scope.to_string()));
        }

        let (auth_url, csrf_token, nonce) = auth_req.set_pkce_challenge(pkce_challenge).url();

        Ok(SsoLoginRequest {
            auth_url,
            csrf_token,
            nonce,
            pkce_verifier,
            redirect_url,
            config: self.config.clone(),
        })
    }
}

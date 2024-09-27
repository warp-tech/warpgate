use std::borrow::Cow;
use std::ops::Deref;

use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreIdToken};
use openidconnect::reqwest::async_http_client;
use openidconnect::url::Url;
use openidconnect::{
    CsrfToken, DiscoveryError, LogoutRequest, Nonce, PkceCodeChallenge, PostLogoutRedirectUrl,
    ProviderMetadataWithLogout, RedirectUrl, Scope,
};

use crate::config::SsoInternalProviderConfig;
use crate::request::SsoLoginRequest;
use crate::SsoError;

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

pub async fn make_client(config: &SsoInternalProviderConfig) -> Result<CoreClient, SsoError> {
    let metadata = discover_metadata(config).await?;

    let client = CoreClient::from_provider_metadata(
        metadata,
        config.client_id().clone(),
        Some(config.client_secret()?),
    )
    .set_auth_type(config.auth_type());

    if let Some(trusted_audiences) = config.additional_trusted_audiences() {
        client
            .id_token_verifier()
            .set_other_audience_verifier_fn(|aud| trusted_audiences.contains(aud.deref()));
    }

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

use openidconnect::url::Url;
use openidconnect::{CsrfToken, Nonce, PkceCodeVerifier, RedirectUrl};
use serde::{Deserialize, Serialize};
use tracing::{debug, error};

use crate::{SsoClient, SsoError, SsoInternalProviderConfig, SsoLoginResponse};

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

    pub fn redirect_url(&self) -> &RedirectUrl {
        &self.redirect_url
    }

    pub async fn verify_code(self, code: String) -> Result<SsoLoginResponse, SsoError> {
        let config = self.config;
        let result = SsoClient::new(config.clone())?
            .finish_login(self.pkce_verifier, self.redirect_url, &self.nonce, code)
            .await?;

        debug!("OIDC claims: {:?}", result.claims);
        debug!("OIDC userinfo claims: {:?}", result.userinfo_claims);

        macro_rules! get_claim {
            ($method:ident) => {
                result
                    .claims
                    .$method()
                    .or(result.userinfo_claims.as_ref().and_then(|x| x.$method()))
            };
        }

        // If preferred_username is absent, fall back to `email`
        let preferred_username = get_claim!(preferred_username)
            .map(|x| x.as_str())
            .map(ToString::to_string)
            .or_else(|| {
                get_claim!(email)
                    .map(|x| x.as_str())
                    .map(ToString::to_string)
            });

        let name = get_claim!(name)
            .and_then(|x| x.get(None))
            .map(|x| x.as_str())
            .map(ToString::to_string);

        let email = get_claim!(email)
            .map(|x| x.as_str())
            .map(ToString::to_string);

        let email_verified = get_claim!(email_verified);

        // Get groups from warpgate_roles claim (works for Custom providers)
        let mut groups = result
            .userinfo_claims
            .and_then(|x| x.additional_claims().warpgate_roles.clone());

        // For Google provider with service account, fetch groups from Directory API
        if groups.is_none() {
            match crate::google_groups::fetch_groups_if_configured(&config, email.as_deref()).await
            {
                Ok(Some(google_groups)) => groups = Some(google_groups),
                Ok(None) => {}
                Err(e) => {
                    error!("Failed to fetch Google groups: {e}");
                }
            }
        }

        Ok(SsoLoginResponse {
            preferred_username,
            name,
            email,
            email_verified,
            groups,
            id_token: result.token.clone(),
        })
    }
}

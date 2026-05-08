use openidconnect::url::Url;
use openidconnect::{CsrfToken, Nonce, PkceCodeVerifier, RedirectUrl};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
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
    pub const fn auth_url(&self) -> &Url {
        &self.auth_url
    }

    pub const fn csrf_token(&self) -> &CsrfToken {
        &self.csrf_token
    }

    pub fn verify_state(&self, state: &str) -> bool {
        self.csrf_token()
            .secret()
            .as_bytes()
            .ct_eq(state.as_bytes())
            .into()
    }

    pub const fn redirect_url(&self) -> &RedirectUrl {
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

        let info_claims = result.userinfo_claims.as_ref();

        macro_rules! get_additional_claim {
            ($method:ident) => {
                result
                    .claims
                    .additional_claims()
                    .$method
                    .clone()
                    .or(info_claims.and_then(|x| x.additional_claims().$method.clone()))
            };
        }

        let (access_groups, admin_groups) =
            match crate::google_groups::fetch_groups_if_configured(&config, email.as_deref()).await
            {
                Ok(Some(google_groups)) => (Some(google_groups.clone()), Some(google_groups)),
                Ok(None) => (
                    get_additional_claim!(warpgate_roles),
                    get_additional_claim!(warpgate_admin_roles),
                ),
                Err(e) => {
                    error!("Failed to fetch Google groups: {e}");
                    (None, None)
                }
            };

        Ok(SsoLoginResponse {
            preferred_username,
            name,
            email,
            email_verified,
            access_roles: access_groups,
            admin_roles: admin_groups,
            id_token: result.token.clone(),
        })
    }
}

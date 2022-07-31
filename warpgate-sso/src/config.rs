use once_cell::sync::Lazy;
use openidconnect::{ClientId, ClientSecret, IssuerUrl};
use serde::{Deserialize, Serialize};

use crate::SsoError;

#[allow(clippy::unwrap_used)]
pub static GOOGLE_ISSUER_URL: Lazy<IssuerUrl> =
    Lazy::new(|| IssuerUrl::new("https://accounts.google.com".to_string()).unwrap());

#[allow(clippy::unwrap_used)]
pub static APPLE_ISSUER_URL: Lazy<IssuerUrl> =
    Lazy::new(|| IssuerUrl::new("https://appleid.apple.com".to_string()).unwrap());

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SsoProviderConfig {
    pub name: String,
    pub label: Option<String>,
    pub provider: SsoInternalProviderConfig,
}

impl SsoProviderConfig {
    pub fn label(&self) -> &str {
        return self
            .label
            .as_deref()
            .unwrap_or_else(|| self.provider.label());
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SsoInternalProviderConfig {
    #[serde(rename = "google")]
    Google {
        client_id: ClientId,
        client_secret: ClientSecret,
    },
    #[serde(rename = "apple")]
    Apple {
        client_id: ClientId,
        client_secret: ClientSecret,
    },
    #[serde(rename = "azure")]
    Azure {
        client_id: ClientId,
        client_secret: ClientSecret,
        tenant: String,
    },
    #[serde(rename = "custom")]
    Custom {
        name: String,
        label: String,
        client_id: ClientId,
        client_secret: ClientSecret,
        issuer_url: IssuerUrl,
        scopes: Vec<String>,
    },
}

impl SsoInternalProviderConfig {
    #[inline]
    pub fn label(&self) -> &'static str {
        match self {
            SsoInternalProviderConfig::Google { .. } => "Google",
            SsoInternalProviderConfig::Apple { .. } => "Apple",
            SsoInternalProviderConfig::Azure { .. } => "Azure",
            SsoInternalProviderConfig::Custom { .. } => "SSO",
        }
    }

    #[inline]
    pub fn client_id(&self) -> &ClientId {
        match self {
            SsoInternalProviderConfig::Google { client_id, .. }
            | SsoInternalProviderConfig::Apple { client_id, .. }
            | SsoInternalProviderConfig::Azure { client_id, .. }
            | SsoInternalProviderConfig::Custom { client_id, .. } => client_id,
        }
    }

    #[inline]
    pub fn client_secret(&self) -> &ClientSecret {
        match self {
            SsoInternalProviderConfig::Google { client_secret, .. }
            | SsoInternalProviderConfig::Apple { client_secret, .. }
            | SsoInternalProviderConfig::Azure { client_secret, .. }
            | SsoInternalProviderConfig::Custom { client_secret, .. } => client_secret,
        }
    }

    #[inline]
    pub fn issuer_url(&self) -> Result<IssuerUrl, SsoError> {
        Ok(match self {
            SsoInternalProviderConfig::Google { .. } => GOOGLE_ISSUER_URL.clone(),
            SsoInternalProviderConfig::Apple { .. } => APPLE_ISSUER_URL.clone(),
            SsoInternalProviderConfig::Azure { tenant, .. } => {
                IssuerUrl::new(format!("https://login.microsoftonline.com/{tenant}/v2.0"))?
            }
            SsoInternalProviderConfig::Custom { issuer_url, .. } => issuer_url.clone(),
        })
    }

    #[inline]
    pub fn scopes(&self) -> Vec<String> {
        match self {
            SsoInternalProviderConfig::Google { .. }
            | SsoInternalProviderConfig::Apple { .. }
            | SsoInternalProviderConfig::Azure { .. } => vec!["email".to_string()],
            SsoInternalProviderConfig::Custom { scopes, .. } => scopes.clone(),
        }
    }
}

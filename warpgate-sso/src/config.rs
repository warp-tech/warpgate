use once_cell::sync::Lazy;
use openidconnect::{ClientId, ClientSecret, IssuerUrl};
use serde::{Deserialize, Serialize};

#[allow(clippy::unwrap_used)]
pub static GOOGLE_ISSUER_URL: Lazy<IssuerUrl> =
    Lazy::new(|| IssuerUrl::new("https://accounts.google.com".to_string()).unwrap());

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SsoProviderConfig {
    pub name: String,
    pub label: Option<String>,
    pub provider: SsoInternalProviderConfig,
}

impl SsoProviderConfig {
    pub fn label(&self) -> &str {
        return self.label.as_deref().unwrap_or_else(|| self.provider.label());
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
            SsoInternalProviderConfig::Custom { .. } => "SSO",
        }
    }

    #[inline]
    pub fn client_id(&self) -> &ClientId {
        match self {
            SsoInternalProviderConfig::Google { client_id, .. } => client_id,
            SsoInternalProviderConfig::Custom { client_id, .. } => client_id,
        }
    }

    #[inline]
    pub fn client_secret(&self) -> &ClientSecret {
        match self {
            SsoInternalProviderConfig::Google { client_secret, .. } => client_secret,
            SsoInternalProviderConfig::Custom { client_secret, .. } => client_secret,
        }
    }

    #[inline]
    pub fn issuer_url(&self) -> &IssuerUrl {
        match self {
            SsoInternalProviderConfig::Google { .. } => &GOOGLE_ISSUER_URL,
            SsoInternalProviderConfig::Custom { issuer_url, .. } => issuer_url,
        }
    }

    #[inline]
    pub fn scopes(&self) -> Vec<String> {
        match self {
            SsoInternalProviderConfig::Google { .. } => vec!["email".to_string()],
            SsoInternalProviderConfig::Custom { scopes, .. } => scopes.clone(),
        }
    }
}

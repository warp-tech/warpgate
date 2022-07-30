use once_cell::sync::Lazy;
use openidconnect::{ClientId, ClientSecret, IssuerUrl};
use serde::{Deserialize, Serialize};

pub static GOOGLE_ISSUER_URL: Lazy<IssuerUrl> =
    Lazy::new(|| IssuerUrl::new("https://accounts.google.com".to_string()).unwrap());

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "provider")]
pub enum SsoProviderConfig {
    #[serde(rename="google")]
    Google {
        name: String,
        label: String,
        client_id: ClientId,
        client_secret: ClientSecret,
    },
    #[serde(rename="custom")]
    Custom {
        name: String,
        label: String,
        client_id: ClientId,
        client_secret: ClientSecret,
        issuer_url: IssuerUrl,
        scopes: Vec<String>,
    },
}

impl SsoProviderConfig {
    pub fn name(&self) -> &String {
        match self {
            SsoProviderConfig::Google { name, .. } => name,
            SsoProviderConfig::Custom { name, .. } => name,
        }
    }

    pub fn label(&self) -> &String {
        match self {
            SsoProviderConfig::Google { label, .. } => label,
            SsoProviderConfig::Custom { label, .. } => label,
        }
    }

    pub fn client_id(&self) -> &ClientId {
        match self {
            SsoProviderConfig::Google { client_id, .. } => client_id,
            SsoProviderConfig::Custom { client_id, .. } => client_id,
        }
    }

    pub fn client_secret(&self) -> &ClientSecret {
        match self {
            SsoProviderConfig::Google { client_secret, .. } => client_secret,
            SsoProviderConfig::Custom { client_secret, .. } => client_secret,
        }
    }

    pub fn issuer_url(&self) -> &IssuerUrl {
        match self {
            SsoProviderConfig::Google { .. } => &GOOGLE_ISSUER_URL,
            SsoProviderConfig::Custom { issuer_url, .. } => issuer_url,
        }
    }

    pub fn scopes(&self) -> Vec<String> {
        match self {
            SsoProviderConfig::Google { .. } => vec!["email".to_string()],
            SsoProviderConfig::Custom { scopes, .. } => scopes.clone(),
        }
    }
}

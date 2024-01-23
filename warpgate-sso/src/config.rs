use std::collections::HashMap;
use std::time::SystemTime;

use data_encoding::BASE64;
use once_cell::sync::Lazy;
use openidconnect::{AuthType, ClientId, ClientSecret, IssuerUrl};
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
        key_id: String,
        team_id: String,
    },
    #[serde(rename = "azure")]
    Azure {
        client_id: ClientId,
        client_secret: ClientSecret,
        tenant: String,
    },
    #[serde(rename = "custom")]
    Custom {
        client_id: ClientId,
        client_secret: ClientSecret,
        issuer_url: IssuerUrl,
        scopes: Vec<String>,
        role_mappings: Option<Vec<(String, String)>>,
        additional_trusted_audiences: Option<Vec<String>>,
    },
}

#[derive(Debug, Serialize)]
struct AppleIDClaims<'a> {
    sub: &'a str,
    aud: &'a str,
    exp: usize,
    nbf: usize,
    iss: &'a str,
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
    pub fn client_secret(&self) -> Result<ClientSecret, SsoError> {
        Ok(match self {
            SsoInternalProviderConfig::Google { client_secret, .. }
            | SsoInternalProviderConfig::Azure { client_secret, .. }
            | SsoInternalProviderConfig::Custom { client_secret, .. } => client_secret.clone(),
            SsoInternalProviderConfig::Apple {
                client_secret,
                client_id,
                key_id,
                team_id,
            } => {
                let key_content =
                    BASE64
                        .decode(client_secret.secret().as_bytes())
                        .map_err(|e| {
                            SsoError::ConfigError(format!(
                                "could not decode base64 client_secret: {e}"
                            ))
                        })?;
                let key = jsonwebtoken::EncodingKey::from_ec_pem(&key_content).map_err(|e| {
                    SsoError::ConfigError(format!(
                        "could not parse client_secret as a private key: {e}"
                    ))
                })?;
                let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
                header.kid = Some(key_id.into());

                #[allow(clippy::unwrap_used)]
                ClientSecret::new(jsonwebtoken::encode(
                    &header,
                    &AppleIDClaims {
                        aud: &APPLE_ISSUER_URL,
                        sub: client_id,
                        exp: SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap()
                            .as_secs() as usize
                            + 600,
                        nbf: SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap()
                            .as_secs() as usize,
                        iss: team_id,
                    },
                    &key,
                )?)
            }
        })
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
            SsoInternalProviderConfig::Google { .. } | SsoInternalProviderConfig::Azure { .. } => {
                vec!["email".to_string()]
            }
            SsoInternalProviderConfig::Custom { scopes, .. } => scopes.clone(),
            SsoInternalProviderConfig::Apple { .. } => vec![],
        }
    }

    #[inline]
    pub fn extra_parameters(&self) -> HashMap<String, String> {
        match self {
            SsoInternalProviderConfig::Apple { .. } => {
                let mut map = HashMap::new();
                map.insert("response_mode".to_string(), "form_post".to_string());
                map
            }
            _ => HashMap::new(),
        }
    }

    #[inline]
    pub fn auth_type(&self) -> AuthType {
        #[allow(clippy::match_like_matches_macro)]
        match self {
            SsoInternalProviderConfig::Apple { .. } => AuthType::RequestBody,
            _ => AuthType::BasicAuth,
        }
    }

    #[inline]
    pub fn needs_pkce_verifier(&self) -> bool {
        #[allow(clippy::match_like_matches_macro)]
        match self {
            SsoInternalProviderConfig::Apple { .. } => false,
            _ => true,
        }
    }

    #[inline]
    pub fn role_mappings(&self) -> Option<Vec<(String, String)>> {
        #[allow(clippy::match_like_matches_macro)]
        match self {
            SsoInternalProviderConfig::Custom { role_mappings, .. } => role_mappings.clone(),
            _ => None,
        }
    }

    #[inline]
    pub fn additional_trusted_audiences(&self) -> Option<&Vec<String>> {
        #[allow(clippy::match_like_matches_macro)]
        match self {
            SsoInternalProviderConfig::Custom {
                additional_trusted_audiences,
                ..
            } => additional_trusted_audiences.as_ref(),
            _ => None,
        }
    }
}

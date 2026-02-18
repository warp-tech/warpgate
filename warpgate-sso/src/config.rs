use std::collections::HashMap;
use std::time::SystemTime;

use data_encoding::BASE64;
use once_cell::sync::Lazy;
use openidconnect::{AuthType, ClientId, ClientSecret, IssuerUrl};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::SsoError;

/// A role mapping value that accepts either a single role or a list of roles.
/// In YAML config: `"group": "role"` or `"group": ["role1", "role2"]`
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum RoleMapping {
    Single(String),
    Multiple(Vec<String>),
}

impl RoleMapping {
    pub fn roles(&self) -> Vec<String> {
        match self {
            RoleMapping::Single(s) => vec![s.clone()],
            RoleMapping::Multiple(v) => v.clone(),
        }
    }
}

#[allow(clippy::unwrap_used)]
pub static GOOGLE_ISSUER_URL: Lazy<IssuerUrl> =
    Lazy::new(|| IssuerUrl::new("https://accounts.google.com".to_string()).unwrap());

#[allow(clippy::unwrap_used)]
pub static APPLE_ISSUER_URL: Lazy<IssuerUrl> =
    Lazy::new(|| IssuerUrl::new("https://appleid.apple.com".to_string()).unwrap());

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SsoProviderConfig {
    pub name: String,
    pub label: Option<String>,
    pub provider: SsoInternalProviderConfig,
    pub return_domain_whitelist: Option<Vec<String>>,
    #[serde(default)]
    pub auto_create_users: bool,
    /// Default credential policy for auto-created users.
    /// Keys: "http", "ssh", "mysql", "postgres"
    /// Values: list of credential kinds e.g. ["sso"], ["web"], []
    pub default_credential_policy: Option<serde_json::Value>,
}

impl SsoProviderConfig {
    pub fn label(&self) -> &str {
        self.label
            .as_deref()
            .unwrap_or_else(|| self.provider.label())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type")]
pub enum SsoInternalProviderConfig {
    #[serde(rename = "google")]
    Google {
        #[schemars(with = "String")]
        client_id: ClientId,
        #[schemars(with = "String")]
        client_secret: ClientSecret,
        /// Service account email for Google Directory API group lookups
        service_account_email: Option<String>,
        /// PEM private key from the service account JSON key file
        service_account_key: Option<String>,
        /// A Google Workspace admin email for domain-wide delegation
        admin_email: Option<String>,
        /// Maps Google group email addresses to Warpgate role names.
        /// Use "*" as a key to set a default role for any group not explicitly mapped.
        role_mappings: Option<HashMap<String, RoleMapping>>,
    },
    #[serde(rename = "apple")]
    Apple {
        #[schemars(with = "String")]
        client_id: ClientId,
        #[schemars(with = "String")]
        client_secret: ClientSecret,
        key_id: String,
        team_id: String,
    },
    #[serde(rename = "azure")]
    Azure {
        #[schemars(with = "String")]
        client_id: ClientId,
        #[schemars(with = "String")]
        client_secret: ClientSecret,
        tenant: String,
    },
    #[serde(rename = "custom")]
    Custom {
        #[schemars(with = "String")]
        client_id: ClientId,
        #[schemars(with = "String")]
        client_secret: ClientSecret,
        #[schemars(with = "String")]
        issuer_url: IssuerUrl,
        scopes: Vec<String>,
        role_mappings: Option<HashMap<String, RoleMapping>>,
        additional_trusted_audiences: Option<Vec<String>>,
        #[serde(default)]
        trust_unknown_audiences: bool,
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
            SsoInternalProviderConfig::Custom { issuer_url, .. } => {
                let mut url = issuer_url.url().clone();
                let path = url.path().to_owned();
                if let Some(path) = path.strip_suffix("/.well-known/openid-configuration") {
                    url.set_path(path);
                    let url_string = url.to_string();
                    IssuerUrl::new(url_string.trim_end_matches('/').into())?
                } else {
                    issuer_url.clone()
                }
            }
        })
    }

    #[inline]
    pub fn scopes(&self) -> Vec<String> {
        match self {
            SsoInternalProviderConfig::Google { .. } | SsoInternalProviderConfig::Azure { .. } => {
                vec!["email".into(), "profile".into()]
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
    pub fn role_mappings(&self) -> Option<HashMap<String, RoleMapping>> {
        #[allow(clippy::match_like_matches_macro)]
        match self {
            SsoInternalProviderConfig::Google { role_mappings, .. }
            | SsoInternalProviderConfig::Custom { role_mappings, .. } => role_mappings.clone(),
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

    #[inline]
    pub fn trust_unknown_audiences(&self) -> bool {
        #[allow(clippy::match_like_matches_macro)]
        match self {
            SsoInternalProviderConfig::Custom {
                trust_unknown_audiences,
                ..
            } => *trust_unknown_audiences,
            _ => false,
        }
    }
}

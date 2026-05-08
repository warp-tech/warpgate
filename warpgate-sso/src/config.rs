use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::sync::LazyLock;
use std::time::SystemTime;

use data_encoding::BASE64;
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
            Self::Single(s) => vec![s.clone()],
            Self::Multiple(v) => v.clone(),
        }
    }
}

#[allow(clippy::unwrap_used)]
pub static GOOGLE_ISSUER_URL: LazyLock<IssuerUrl> =
    LazyLock::new(|| IssuerUrl::new("https://accounts.google.com".to_string()).unwrap());

#[allow(clippy::unwrap_used)]
pub static APPLE_ISSUER_URL: LazyLock<IssuerUrl> =
    LazyLock::new(|| IssuerUrl::new("https://appleid.apple.com".to_string()).unwrap());

#[derive(Clone, Default, Debug, Serialize, Deserialize, JsonSchema)]
pub enum SsoProviderReturnUrlPrefix {
    #[serde(rename = "@")]
    #[default]
    AtSign,
    #[serde(rename = "_")]
    Underscore,
}

impl Display for SsoProviderReturnUrlPrefix {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AtSign => write!(f, "@"),
            Self::Underscore => write!(f, "_"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SsoProviderConfig {
    pub name: String,
    pub label: Option<String>,
    pub provider: SsoInternalProviderConfig,
    pub return_domain_whitelist: Option<Vec<String>>,
    #[serde(default)]
    pub return_url_prefix: SsoProviderReturnUrlPrefix,
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
        admin_role_mappings: Option<HashMap<String, RoleMapping>>,
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
        admin_role_mappings: Option<HashMap<String, RoleMapping>>,
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
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Google { .. } => "Google",
            Self::Apple { .. } => "Apple",
            Self::Azure { .. } => "Azure",
            Self::Custom { .. } => "SSO",
        }
    }

    #[inline]
    pub const fn client_id(&self) -> &ClientId {
        match self {
            Self::Google { client_id, .. }
            | Self::Apple { client_id, .. }
            | Self::Azure { client_id, .. }
            | Self::Custom { client_id, .. } => client_id,
        }
    }

    #[inline]
    pub fn client_secret(&self) -> Result<ClientSecret, SsoError> {
        Ok(match self {
            Self::Google { client_secret, .. }
            | Self::Azure { client_secret, .. }
            | Self::Custom { client_secret, .. } => client_secret.clone(),
            Self::Apple {
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
            Self::Google { .. } => GOOGLE_ISSUER_URL.clone(),
            Self::Apple { .. } => APPLE_ISSUER_URL.clone(),
            Self::Azure { tenant, .. } => {
                IssuerUrl::new(format!("https://login.microsoftonline.com/{tenant}/v2.0"))?
            }
            Self::Custom { issuer_url, .. } => {
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
            Self::Google { .. } | Self::Azure { .. } => {
                vec!["email".into(), "profile".into()]
            }
            Self::Custom { scopes, .. } => scopes.clone(),
            Self::Apple { .. } => vec![],
        }
    }

    #[inline]
    pub fn extra_parameters(&self) -> HashMap<String, String> {
        match self {
            Self::Apple { .. } => {
                let mut map = HashMap::new();
                map.insert("response_mode".to_string(), "form_post".to_string());
                map
            }
            _ => HashMap::new(),
        }
    }

    #[inline]
    pub const fn auth_type(&self) -> AuthType {
        #[allow(clippy::match_like_matches_macro)]
        match self {
            Self::Apple { .. } => AuthType::RequestBody,
            _ => AuthType::BasicAuth,
        }
    }

    #[inline]
    pub const fn needs_pkce_verifier(&self) -> bool {
        #[allow(clippy::match_like_matches_macro)]
        match self {
            Self::Apple { .. } => false,
            _ => true,
        }
    }

    #[inline]
    pub fn role_mappings(&self) -> Option<HashMap<String, RoleMapping>> {
        #[allow(clippy::match_like_matches_macro)]
        match self {
            Self::Google { role_mappings, .. } | Self::Custom { role_mappings, .. } => {
                role_mappings.clone()
            }
            _ => None,
        }
    }

    #[inline]
    pub fn admin_role_mappings(&self) -> Option<HashMap<String, RoleMapping>> {
        #[allow(clippy::match_like_matches_macro)]
        match self {
            Self::Google {
                admin_role_mappings,
                ..
            }
            | Self::Custom {
                admin_role_mappings,
                ..
            } => admin_role_mappings.clone(),
            _ => None,
        }
    }

    #[inline]
    pub const fn additional_trusted_audiences(&self) -> Option<&Vec<String>> {
        #[allow(clippy::match_like_matches_macro)]
        match self {
            Self::Custom {
                additional_trusted_audiences,
                ..
            } => additional_trusted_audiences.as_ref(),
            _ => None,
        }
    }

    #[inline]
    pub const fn trust_unknown_audiences(&self) -> bool {
        #[allow(clippy::match_like_matches_macro)]
        match self {
            Self::Custom {
                trust_unknown_audiences,
                ..
            } => *trust_unknown_audiences,
            _ => false,
        }
    }
}

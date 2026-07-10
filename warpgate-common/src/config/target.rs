use std::collections::HashMap;

use poem_openapi::{Enum, Object, Union};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use warpgate_tls::TlsMode;

use super::defaults::{
    _default_empty_string, _default_empty_vec, _default_mysql_port,
    _default_postgres_idle_timeout_str, _default_rdp_port, _default_ssh_port, _default_true,
    _default_username, _default_vnc_port,
};
use crate::secrets::{MaybeSecretRef, SecretRef};
use crate::Secret;

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct KubernetesTargetCertificateAuth {
    pub certificate: Secret<String>,
    pub private_key: Secret<String>,
}

impl Default for KubernetesTargetCertificateAuth {
    fn default() -> Self {
        Self {
            certificate: Secret::new(String::new()),
            private_key: Secret::new(String::new()),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Object)]
pub struct TargetSSHOptions {
    pub host: String,
    #[serde(default = "_default_ssh_port")]
    pub port: u16,
    #[serde(default = "_default_username")]
    pub username: String,
    #[serde(default)]
    pub allow_insecure_algos: Option<bool>,
    #[serde(default)]
    pub auth: SSHTargetAuth,
    #[serde(default)]
    pub jump_host: Option<Uuid>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Union)]
#[serde(tag = "kind")]
#[oai(discriminator_name = "kind", one_of)]
pub enum SSHTargetAuth {
    #[serde(rename = "password")]
    Password(SshTargetPasswordAuth),
    #[serde(rename = "publickey")]
    PublicKey(SshTargetPublicKeyAuth),
    #[serde(rename = "iam_role")]
    IamRole(SshTargetIamRoleAuth),
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct SshTargetPasswordAuth {
    pub password: MaybeSecretRef,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object, Default)]
pub struct SshTargetPublicKeyAuth {}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object, Default)]
pub struct SshTargetIamRoleAuth {}

impl Default for SSHTargetAuth {
    fn default() -> Self {
        Self::PublicKey(SshTargetPublicKeyAuth::default())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Object)]
pub struct TargetHTTPOptions {
    #[serde(default = "_default_empty_string")]
    pub url: String,

    #[serde(default)]
    pub tls: Tls,

    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,

    #[serde(default)]
    pub external_host: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Object)]
pub struct Tls {
    #[serde(default)]
    pub mode: TlsMode,

    #[serde(default = "_default_true")]
    pub verify: bool,
}

#[allow(clippy::derivable_impls)]
impl Default for Tls {
    fn default() -> Self {
        Self {
            mode: TlsMode::default(),
            verify: false,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Union)]
#[serde(tag = "kind")]
#[oai(discriminator_name = "kind", one_of)]
pub enum DatabaseTargetAuth {
    #[serde(rename = "password")]
    Password(DatabaseTargetPasswordAuth),
    #[serde(rename = "iam_role")]
    IamRole(DatabaseTargetIamRoleAuth),
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object, Default)]
pub struct DatabaseTargetPasswordAuth {
    #[serde(default)]
    pub password: MaybeSecretRef,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object, Default)]
pub struct DatabaseTargetIamRoleAuth {}

impl Default for DatabaseTargetAuth {
    fn default() -> Self {
        Self::Password(DatabaseTargetPasswordAuth::default())
    }
}


#[derive(Debug, Deserialize, Serialize, Clone, Object)]
pub struct TargetMySqlOptions {
    #[serde(default = "_default_empty_string")]
    pub host: String,

    #[serde(default = "_default_mysql_port")]
    pub port: u16,

    #[serde(default = "_default_username")]
    pub username: String,

    #[serde(default)]
    auth: Option<DatabaseTargetAuth>,

    /// Deprecated: use `auth` instead. Kept for backward compatibility with old configs/API clients.
    #[serde(default, skip_serializing)]
    #[oai(deprecated)]
    password: Option<String>,

    #[serde(default)]
    pub tls: Tls,

    #[serde(default)]
    pub default_database_name: Option<String>,
}

impl TargetMySqlOptions {
    pub fn effective_auth(&self) -> DatabaseTargetAuth {
        if let Some(auth) = &self.auth {
            auth.clone()
        } else {
            DatabaseTargetAuth::Password(DatabaseTargetPasswordAuth {
                password: MaybeSecretRef::Inline(Secret::new(
                    self.password.clone().unwrap_or_default(),
                )),
            })
        }
    }

    pub fn normalize(&mut self) {
        if let Some(password) = self.password.take() {
            self.auth = Some(DatabaseTargetAuth::Password(DatabaseTargetPasswordAuth {
                password: MaybeSecretRef::Inline(Secret::new(password)),
            }));
        } else if self.auth.is_none() {
            self.auth = Some(DatabaseTargetAuth::Password(DatabaseTargetPasswordAuth {
                password: MaybeSecretRef::default(),
            }));
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Default, Enum)]
pub enum PostgresProtocolVersion {
    #[serde(rename = "3.0")]
    #[oai(rename = "3.0")]
    V3_0,
    #[default]
    #[serde(rename = "3.2")]
    #[oai(rename = "3.2")]
    V3_2,
}

#[derive(Debug, Deserialize, Serialize, Clone, Object)]
pub struct TargetPostgresOptions {
    #[serde(default = "_default_empty_string")]
    pub host: String,

    #[serde(default = "_default_mysql_port")]
    pub port: u16,

    #[serde(default = "_default_username")]
    pub username: String,

    #[serde(default)]
    auth: Option<DatabaseTargetAuth>,

    /// Deprecated: use `auth` instead. Kept for backward compatibility with old configs/API clients.
    #[serde(default, skip_serializing)]
    #[oai(deprecated)]
    password: Option<String>,

    #[serde(default)]
    pub tls: Tls,

    #[serde(default = "_default_postgres_idle_timeout_str")]
    pub idle_timeout: Option<String>,

    #[serde(default)]
    pub default_database_name: Option<String>,

    #[serde(default)]
    pub protocol_version: Option<PostgresProtocolVersion>,
}

impl TargetPostgresOptions {
    pub fn effective_auth(&self) -> DatabaseTargetAuth {
        if let Some(auth) = &self.auth {
            auth.clone()
        } else {
            DatabaseTargetAuth::Password(DatabaseTargetPasswordAuth {
                password: MaybeSecretRef::Inline(Secret::new(
                    self.password.clone().unwrap_or_default(),
                )),
            })
        }
    }

    pub fn normalize(&mut self) {
        if let Some(password) = self.password.take() {
            self.auth = Some(DatabaseTargetAuth::Password(DatabaseTargetPasswordAuth {
                password: MaybeSecretRef::Inline(Secret::new(password)),
            }));
        } else if self.auth.is_none() {
            self.auth = Some(DatabaseTargetAuth::Password(DatabaseTargetPasswordAuth {
                password: MaybeSecretRef::default(),
            }));
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Object)]
pub struct TargetVncOptions {
    #[serde(default = "_default_empty_string")]
    pub host: String,

    #[serde(default = "_default_vnc_port")]
    pub port: u16,

    #[serde(default)]
    pub auth: VncTargetAuth,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Union)]
#[serde(tag = "kind")]
#[oai(discriminator_name = "kind", one_of)]
pub enum VncTargetAuth {
    #[serde(rename = "none")]
    None(VncTargetNoneAuth),
    #[serde(rename = "password")]
    Password(VncTargetPasswordAuth),
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object, Default)]
pub struct VncTargetNoneAuth {}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct VncTargetPasswordAuth {
    pub password: MaybeSecretRef,
}

impl Default for VncTargetAuth {
    fn default() -> Self {
        Self::None(VncTargetNoneAuth::default())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Object)]
pub struct TargetRdpOptions {
    #[serde(default = "_default_empty_string")]
    pub host: String,

    #[serde(default = "_default_rdp_port")]
    pub port: u16,

    #[serde(default = "_default_username")]
    pub username: String,

    #[serde(default)]
    pub domain: Option<String>,

    #[serde(default)]
    pub auth: RdpTargetAuth,

    /// Verify the RDP server's TLS certificate against the system root store.
    /// RDP servers commonly use self-signed certificates, so this is off by default.
    #[serde(default)]
    pub verify_tls: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Union)]
#[serde(tag = "kind")]
#[oai(discriminator_name = "kind", one_of)]
pub enum RdpTargetAuth {
    #[serde(rename = "password")]
    Password(RdpTargetPasswordAuth),
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct RdpTargetPasswordAuth {
    pub password: MaybeSecretRef,
}

impl Default for RdpTargetAuth {
    fn default() -> Self {
        Self::Password(RdpTargetPasswordAuth {
            password: MaybeSecretRef::default(),
        })
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Object)]
pub struct TargetKubernetesOptions {
    #[serde(default = "_default_empty_string")]
    pub cluster_url: String,

    #[serde(default)]
    pub tls: Tls,

    #[serde(default)]
    pub auth: KubernetesTargetAuth,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Union)]
#[serde(tag = "kind")]
#[oai(discriminator_name = "kind", one_of)]
pub enum KubernetesTargetAuth {
    #[serde(rename = "token")]
    Token(KubernetesTargetTokenAuth),
    #[serde(rename = "certificate")]
    Certificate(KubernetesTargetCertificateAuth),
    #[serde(rename = "iam_role")]
    IamRole(KubernetesTargetIamRoleAuth),
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct KubernetesTargetTokenAuth {
    pub token: Secret<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object, Default)]
pub struct KubernetesTargetIamRoleAuth {}

impl Default for KubernetesTargetAuth {
    fn default() -> Self {
        Self::Certificate(KubernetesTargetCertificateAuth::default())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Object)]
pub struct Target {
    #[serde(default)]
    pub id: Uuid,
    pub name: String,
    pub description: String,
    #[serde(default = "_default_empty_vec")]
    pub allow_roles: Vec<String>,
    #[serde(flatten)]
    pub options: TargetOptions,
    pub rate_limit_bytes_per_second: Option<u32>,
    pub group_id: Option<Uuid>,
    pub ticket_max_duration_seconds: Option<i64>,
    pub ticket_requests_disabled: bool,
    pub ticket_require_approval: bool,
    pub ticket_max_uses: Option<i16>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Union)]
#[oai(discriminator_name = "kind", one_of)]
pub enum TargetOptions {
    #[serde(rename = "ssh")]
    Ssh(TargetSSHOptions),
    #[serde(rename = "http")]
    Http(TargetHTTPOptions),
    #[serde(rename = "kubernetes")]
    Kubernetes(TargetKubernetesOptions),
    #[serde(rename = "mysql")]
    MySql(TargetMySqlOptions),
    #[serde(rename = "postgres")]
    Postgres(TargetPostgresOptions),
    #[serde(rename = "vnc")]
    Vnc(TargetVncOptions),
    #[serde(rename = "rdp")]
    Rdp(TargetRdpOptions),
}

impl TargetOptions {
    
    pub fn secret_references(&self) -> Vec<SecretRef> {
        let mut refs = Vec::new();
        let mut push = |mr: &MaybeSecretRef| {
            if let Some(r) = mr.as_reference() {
                refs.push(r.clone());
            }
        };

        match self {
            TargetOptions::Ssh(ssh) => {
                if let SSHTargetAuth::Password(auth) = &ssh.auth {
                    push(&auth.password);
                }
            }
            TargetOptions::MySql(my) => {
                if let DatabaseTargetAuth::Password(auth) = my.effective_auth() {
                    push(&auth.password);
                }
            }
            TargetOptions::Postgres(pg) => {
                if let DatabaseTargetAuth::Password(auth) = pg.effective_auth() {
                    push(&auth.password);
                }
            }
            TargetOptions::Vnc(vnc) => {
                if let VncTargetAuth::Password(auth) = &vnc.auth {
                    push(&auth.password);
                }
            }
            TargetOptions::Rdp(rdp) => {
                let RdpTargetAuth::Password(auth) = &rdp.auth;
                push(&auth.password);
            }
            TargetOptions::Kubernetes(_) => {}
            TargetOptions::Http(_) => {}
        }

        refs
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn ssh_password_reference_is_collected() {
        let options = TargetOptions::Ssh(TargetSSHOptions {
            host: "h".into(),
            port: 22,
            username: "u".into(),
            allow_insecure_algos: None,
            jump_host: None,
            auth: SSHTargetAuth::Password(SshTargetPasswordAuth {
                password: MaybeSecretRef::from_str("vault://vault-prod/secret/db#password").unwrap(),
            }),
        });

        let refs = options.secret_references();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].to_string(), "vault://vault-prod/secret/db#password");
    }

    #[test]
    fn inline_credentials_are_not_references() {
        let options = TargetOptions::Ssh(TargetSSHOptions {
            host: "h".into(),
            port: 22,
            username: "u".into(),
            allow_insecure_algos: None,
            jump_host: None,
            auth: SSHTargetAuth::Password(SshTargetPasswordAuth {
                password: MaybeSecretRef::from_str("hunter2").unwrap(),
            }),
        });

        assert!(options.secret_references().is_empty());
    }

    #[test]
    fn ssh_public_key_auth_has_no_references() {
        let options = TargetOptions::Ssh(TargetSSHOptions {
            host: "h".into(),
            port: 22,
            username: "u".into(),
            allow_insecure_algos: None,
            jump_host: None,
            auth: SSHTargetAuth::PublicKey(SshTargetPublicKeyAuth::default()),
        });

        assert!(options.secret_references().is_empty());
    }

    #[test]
    fn ssh_iam_role_auth_has_no_references() {
        let options = TargetOptions::Ssh(TargetSSHOptions {
            host: "h".into(),
            port: 22,
            username: "u".into(),
            allow_insecure_algos: None,
            jump_host: None,
            auth: SSHTargetAuth::IamRole(SshTargetIamRoleAuth::default()),
        });

        assert!(options.secret_references().is_empty());
    }

    #[test]
    fn http_and_kubernetes_targets_never_have_references() {
        let http = TargetOptions::Http(TargetHTTPOptions {
            url: "http://x".into(),
            tls: Tls::default(),
            headers: None,
            external_host: None,
        });
        assert!(http.secret_references().is_empty());

        let k8s = TargetOptions::Kubernetes(TargetKubernetesOptions {
            cluster_url: "https://x".into(),
            tls: Tls::default(),
            auth: KubernetesTargetAuth::default(),
        });
        assert!(k8s.secret_references().is_empty());
    }

    fn mysql_options(auth: Option<DatabaseTargetAuth>, password: Option<String>) -> TargetMySqlOptions {
        TargetMySqlOptions {
            host: "h".into(),
            port: 3306,
            username: "u".into(),
            auth,
            password,
            tls: Tls::default(),
            default_database_name: None,
        }
    }

    fn postgres_options(
        auth: Option<DatabaseTargetAuth>,
        password: Option<String>,
    ) -> TargetPostgresOptions {
        TargetPostgresOptions {
            host: "h".into(),
            port: 5432,
            username: "u".into(),
            auth,
            password,
            tls: Tls::default(),
            idle_timeout: None,
            default_database_name: None,
            protocol_version: None,
        }
    }

    #[test]
    fn mysql_effective_auth_falls_back_to_legacy_password_field() {
        let opts = mysql_options(None, Some("hunter2".into()));
        match opts.effective_auth() {
            DatabaseTargetAuth::Password(p) => {
                assert_eq!(p.password.as_reference(), None);
            }
            _ => panic!("expected Password auth"),
        }
    }

    #[test]
    fn mysql_effective_auth_prefers_auth_field_over_legacy_password() {
        let opts = mysql_options(
            Some(DatabaseTargetAuth::Password(DatabaseTargetPasswordAuth {
                password: MaybeSecretRef::from_str("vault://vault-prod/secret/db#password")
                    .unwrap(),
            })),
            Some("stale-legacy-value".into()),
        );
        match opts.effective_auth() {
            DatabaseTargetAuth::Password(p) => {
                assert_eq!(
                    p.password.as_reference().unwrap().to_string(),
                    "vault://vault-prod/secret/db#password"
                );
            }
            _ => panic!("expected Password auth"),
        }
    }

    #[test]
    fn mysql_legacy_password_is_never_reinterpreted_as_a_reference() {
        // Even if the legacy plaintext field happens to look like a reference URI, it must stay
        // inline: effective_auth() wraps it directly rather than parsing it via FromStr, so old
        // configs with such a (coincidentally shaped) password keep working unchanged.
        let opts = mysql_options(None, Some("vault://vault-prod/secret/db#password".into()));
        match opts.effective_auth() {
            DatabaseTargetAuth::Password(p) => assert_eq!(p.password.as_reference(), None),
            _ => panic!("expected Password auth"),
        }
    }

    #[test]
    fn mysql_normalize_migrates_legacy_password_into_auth_and_clears_it() {
        let mut opts = mysql_options(None, Some("hunter2".into()));
        opts.normalize();
        assert_eq!(opts.password, None);
        match opts.auth {
            Some(DatabaseTargetAuth::Password(p)) => {
                assert_eq!(p.password.as_reference(), None)
            }
            _ => panic!("expected auth to be populated with Password"),
        }
    }

    #[test]
    fn mysql_normalize_defaults_auth_when_nothing_is_set() {
        let mut opts = mysql_options(None, None);
        opts.normalize();
        assert!(matches!(opts.auth, Some(DatabaseTargetAuth::Password(_))));
    }

    #[test]
    fn mysql_normalize_leaves_existing_auth_untouched_when_no_legacy_password() {
        let mut opts = mysql_options(
            Some(DatabaseTargetAuth::Password(DatabaseTargetPasswordAuth {
                password: MaybeSecretRef::from_str("vault://vault-prod/secret/db#password")
                    .unwrap(),
            })),
            None,
        );
        opts.normalize();
        match opts.auth {
            Some(DatabaseTargetAuth::Password(p)) => {
                assert_eq!(
                    p.password.as_reference().unwrap().to_string(),
                    "vault://vault-prod/secret/db#password"
                );
            }
            _ => panic!("expected auth to remain Password"),
        }
    }

    #[test]
    fn mysql_password_reference_is_collected() {
        let options = TargetOptions::MySql(mysql_options(
            Some(DatabaseTargetAuth::Password(DatabaseTargetPasswordAuth {
                password: MaybeSecretRef::from_str("vault://vault-prod/secret/db#password")
                    .unwrap(),
            })),
            None,
        ));
        let refs = options.secret_references();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].to_string(), "vault://vault-prod/secret/db#password");
    }

    #[test]
    fn mysql_iam_role_auth_has_no_references() {
        let options = TargetOptions::MySql(mysql_options(
            Some(DatabaseTargetAuth::IamRole(DatabaseTargetIamRoleAuth::default())),
            None,
        ));
        assert!(options.secret_references().is_empty());
    }

    #[test]
    fn postgres_password_reference_is_collected() {
        let options = TargetOptions::Postgres(postgres_options(
            Some(DatabaseTargetAuth::Password(DatabaseTargetPasswordAuth {
                password: MaybeSecretRef::from_str("vault://vault-prod/secret/pg#password")
                    .unwrap(),
            })),
            None,
        ));
        let refs = options.secret_references();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].to_string(), "vault://vault-prod/secret/pg#password");
    }

    #[test]
    fn postgres_effective_auth_falls_back_to_legacy_password_field() {
        let opts = postgres_options(None, Some("hunter2".into()));
        match opts.effective_auth() {
            DatabaseTargetAuth::Password(p) => assert_eq!(p.password.as_reference(), None),
            _ => panic!("expected Password auth"),
        }
    }

    #[test]
    fn postgres_normalize_migrates_legacy_password_into_auth_and_clears_it() {
        let mut opts = postgres_options(None, Some("hunter2".into()));
        opts.normalize();
        assert_eq!(opts.password, None);
        assert!(matches!(opts.auth, Some(DatabaseTargetAuth::Password(_))));
    }

    #[test]
    fn postgres_iam_role_auth_has_no_references() {
        let options = TargetOptions::Postgres(postgres_options(
            Some(DatabaseTargetAuth::IamRole(DatabaseTargetIamRoleAuth::default())),
            None,
        ));
        assert!(options.secret_references().is_empty());
    }
}

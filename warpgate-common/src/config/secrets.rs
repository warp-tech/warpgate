use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::Secret;

fn _default_approle_mount() -> String {
    "approle".to_string()
}

fn _default_kubernetes_mount() -> String {
    "kubernetes".to_string()
}

fn _default_k8s_jwt_path() -> PathBuf {
    PathBuf::from("/var/run/secrets/kubernetes.io/serviceaccount/token")
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BackendType {
    Vault,
    #[serde(rename = "openbao", alias = "open_bao")]
    OpenBao,
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum VaultAuthConfig {
    Token {
        #[schemars(with = "String")]
        token: Secret<String>,
    },
    AppRole {
        role_id_file: PathBuf,
        secret_id_file: PathBuf,
        #[serde(default = "_default_approle_mount")]
        mount: String,
    },
    Kubernetes {
        role: String,
        #[serde(default = "_default_k8s_jwt_path")]
        jwt_path: PathBuf,
        #[serde(default = "_default_kubernetes_mount")]
        mount: String,
    },
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct VaultTlsConfig {
    #[serde(default)]
    pub ca_cert: Option<PathBuf>,
    #[serde(default)]
    pub skip_verify: bool,
}

impl Default for VaultTlsConfig {
    fn default() -> Self {
        Self {
            ca_cert: None,
            skip_verify: false,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct SecretBackendConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub backend_type: BackendType,
    pub address: String,
    #[serde(default)]
    pub namespace: Option<String>,
    pub auth: VaultAuthConfig,
    #[serde(default)]
    pub tls: VaultTlsConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema)]
pub struct SecretsConfig {
    #[serde(default)]
    pub backends: Vec<SecretBackendConfig>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_type_deserializes_vault() {
        let t: BackendType = serde_json::from_str("\"vault\"").unwrap();
        assert_eq!(t, BackendType::Vault);
    }

    #[test]
    fn backend_type_deserializes_openbao() {
        let t: BackendType = serde_json::from_str("\"openbao\"").unwrap();
        assert_eq!(t, BackendType::OpenBao);
    }

    #[test]
    fn backend_type_deserializes_open_bao_alias() {
        let t: BackendType = serde_json::from_str("\"open_bao\"").unwrap();
        assert_eq!(t, BackendType::OpenBao);
    }

    #[test]
    fn backend_type_serializes_openbao_as_canonical_name() {
        // the `alias` only applies on deserialize; serialization must always use the
        // canonical "openbao" spelling, not "open_bao"
        let json = serde_json::to_string(&BackendType::OpenBao).unwrap();
        assert_eq!(json, "\"openbao\"");
    }

    #[test]
    fn backend_type_rejects_unknown_variant() {
        assert!(serde_json::from_str::<BackendType>("\"foo\"").is_err());
    }

    #[test]
    fn vault_auth_config_token_deserializes() {
        let cfg: VaultAuthConfig =
            serde_json::from_str(r#"{"method":"token","token":"s.abc123"}"#).unwrap();
        match cfg {
            VaultAuthConfig::Token { token } => assert_eq!(token.expose_secret(), "s.abc123"),
            other => panic!("expected Token, got {other:?}"),
        }
    }

    #[test]
    fn vault_auth_config_approle_defaults_mount() {
        let cfg: VaultAuthConfig = serde_json::from_str(
            r#"{"method":"app_role","role_id_file":"/a","secret_id_file":"/b"}"#,
        )
        .unwrap();
        match cfg {
            VaultAuthConfig::AppRole {
                mount,
                role_id_file,
                secret_id_file,
            } => {
                assert_eq!(mount, "approle");
                assert_eq!(role_id_file, PathBuf::from("/a"));
                assert_eq!(secret_id_file, PathBuf::from("/b"));
            }
            other => panic!("expected AppRole, got {other:?}"),
        }
    }

    #[test]
    fn vault_auth_config_approle_explicit_mount_overrides_default() {
        let cfg: VaultAuthConfig = serde_json::from_str(
            r#"{"method":"app_role","role_id_file":"/a","secret_id_file":"/b","mount":"custom-approle"}"#,
        )
        .unwrap();
        match cfg {
            VaultAuthConfig::AppRole { mount, .. } => assert_eq!(mount, "custom-approle"),
            other => panic!("expected AppRole, got {other:?}"),
        }
    }

    #[test]
    fn vault_auth_config_kubernetes_defaults_jwt_path_and_mount() {
        let cfg: VaultAuthConfig =
            serde_json::from_str(r#"{"method":"kubernetes","role":"warpgate"}"#).unwrap();
        match cfg {
            VaultAuthConfig::Kubernetes {
                role,
                jwt_path,
                mount,
            } => {
                assert_eq!(role, "warpgate");
                assert_eq!(
                    jwt_path,
                    PathBuf::from("/var/run/secrets/kubernetes.io/serviceaccount/token")
                );
                assert_eq!(mount, "kubernetes");
            }
            other => panic!("expected Kubernetes, got {other:?}"),
        }
    }

    #[test]
    fn vault_auth_config_kubernetes_explicit_fields_override_defaults() {
        let cfg: VaultAuthConfig = serde_json::from_str(
            r#"{"method":"kubernetes","role":"warpgate","jwt_path":"/custom/jwt","mount":"k8s-alt"}"#,
        )
        .unwrap();
        match cfg {
            VaultAuthConfig::Kubernetes {
                jwt_path, mount, ..
            } => {
                assert_eq!(jwt_path, PathBuf::from("/custom/jwt"));
                assert_eq!(mount, "k8s-alt");
            }
            other => panic!("expected Kubernetes, got {other:?}"),
        }
    }

    #[test]
    fn vault_auth_config_unknown_method_is_rejected() {
        assert!(serde_json::from_str::<VaultAuthConfig>(r#"{"method":"oauth"}"#).is_err());
    }

    #[test]
    fn vault_tls_config_default_has_no_ca_and_verifies() {
        let tls = VaultTlsConfig::default();
        assert_eq!(tls.ca_cert, None);
        assert!(!tls.skip_verify);
    }

    #[test]
    fn vault_tls_config_deserializes_empty_object_to_defaults() {
        let tls: VaultTlsConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(tls.ca_cert, None);
        assert!(!tls.skip_verify);
    }

    #[test]
    fn vault_tls_config_deserializes_explicit_values() {
        let tls: VaultTlsConfig =
            serde_json::from_str(r#"{"ca_cert":"/etc/ca.pem","skip_verify":true}"#).unwrap();
        assert_eq!(tls.ca_cert, Some(PathBuf::from("/etc/ca.pem")));
        assert!(tls.skip_verify);
    }

    #[test]
    fn secret_backend_config_deserializes_full_example() {
        let json = r#"{
            "name": "vault-prod",
            "type": "vault",
            "address": "https://vault.internal:8200",
            "namespace": "warpgate",
            "auth": {
                "method": "app_role",
                "role_id_file": "/run/secrets/role_id",
                "secret_id_file": "/run/secrets/secret_id"
            },
            "tls": {
                "ca_cert": "/etc/vault-ca.pem",
                "skip_verify": false
            }
        }"#;
        let cfg: SecretBackendConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.name, "vault-prod");
        assert_eq!(cfg.backend_type, BackendType::Vault);
        assert_eq!(cfg.address, "https://vault.internal:8200");
        assert_eq!(cfg.namespace, Some("warpgate".to_string()));
        assert!(matches!(cfg.auth, VaultAuthConfig::AppRole { .. }));
        assert_eq!(cfg.tls.ca_cert, Some(PathBuf::from("/etc/vault-ca.pem")));
    }

    #[test]
    fn secret_backend_config_namespace_and_tls_are_optional() {
        let json = r#"{
            "name": "vault-local",
            "type": "vault",
            "address": "http://127.0.0.1:8200",
            "auth": {"method": "token", "token": "root"}
        }"#;
        let cfg: SecretBackendConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.namespace, None);
        assert_eq!(cfg.tls.ca_cert, None);
        assert!(!cfg.tls.skip_verify);
    }

    #[test]
    fn secrets_config_default_has_no_backends() {
        assert!(SecretsConfig::default().backends.is_empty());
    }

    #[test]
    fn secrets_config_deserializes_missing_backends_as_empty() {
        let cfg: SecretsConfig = serde_json::from_str("{}").unwrap();
        assert!(cfg.backends.is_empty());
    }

    #[test]
    fn secrets_config_deserializes_multiple_backends() {
        let json = r#"{
            "backends": [
                {
                    "name": "a",
                    "type": "vault",
                    "address": "https://a:8200",
                    "auth": {"method": "token", "token": "x"}
                },
                {
                    "name": "b",
                    "type": "openbao",
                    "address": "https://b:8200",
                    "auth": {"method": "token", "token": "y"}
                }
            ]
        }"#;
        let cfg: SecretsConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.backends.len(), 2);
        assert_eq!(cfg.backends[0].name, "a");
        assert_eq!(cfg.backends[1].name, "b");
    }
}

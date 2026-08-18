use std::collections::HashMap;

use poem_openapi::{Enum, Object, Union};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use warpgate_tls::TlsMode;

use super::defaults::{
    _default_empty_string, _default_empty_vec, _default_mysql_port,
    _default_postgres_idle_timeout_str, _default_postgres_port, _default_rdp_port,
    _default_ssh_port, _default_username, _default_vnc_port,
};
use crate::encryption::EncryptionError;
use crate::secrets::{MaybeSecretRef, SecretRef};
use crate::{Secret, StoredSecret};

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct KubernetesTargetCertificateAuth {
    pub certificate: Secret<String>,
    pub private_key: StoredSecret,
}

impl Default for KubernetesTargetCertificateAuth {
    fn default() -> Self {
        Self {
            certificate: Secret::new(String::new()),
            private_key: StoredSecret::default(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
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
pub struct SshTargetPublicKeyAuth {
    /// Specific stored client key to authenticate with; `None` uses the keys
    /// marked default.
    #[serde(default)]
    pub key_id: Option<Uuid>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object, Default)]
pub struct SshTargetIamRoleAuth {}

impl Default for SSHTargetAuth {
    fn default() -> Self {
        Self::PublicKey(SshTargetPublicKeyAuth::default())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
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

// `#[serde(default)]` sits on the container, not on each field, so that
// `Default` is the single source for both an absent `tls` block and an absent
// key inside a present one. Spelling the two separately is how `verify` came to
// mean `false` for an omitted block and `true` for an empty one. Kept as a plain
// comment: a doc comment here would surface in the OpenAPI schema.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
#[serde(default)]
pub struct Tls {
    pub mode: TlsMode,
    pub verify: bool,
}

impl Default for Tls {
    fn default() -> Self {
        Self {
            mode: TlsMode::default(),
            // A target that says nothing about certificate checking is not
            // asking for it to be off.
            verify: true,
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

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
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
                password: MaybeSecretRef::Inline(StoredSecret::from(
                    self.password.clone().unwrap_or_default(),
                )),
            })
        }
    }

    pub fn normalize(&mut self) {
        if let Some(password) = self.password.take() {
            self.auth = Some(DatabaseTargetAuth::Password(DatabaseTargetPasswordAuth {
                password: MaybeSecretRef::Inline(StoredSecret::from(password)),
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

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct TargetPostgresOptions {
    #[serde(default = "_default_empty_string")]
    pub host: String,

    #[serde(default = "_default_postgres_port")]
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
                password: MaybeSecretRef::Inline(StoredSecret::from(
                    self.password.clone().unwrap_or_default(),
                )),
            })
        }
    }

    pub fn normalize(&mut self) {
        if let Some(password) = self.password.take() {
            self.auth = Some(DatabaseTargetAuth::Password(DatabaseTargetPasswordAuth {
                password: MaybeSecretRef::Inline(StoredSecret::from(password)),
            }));
        } else if self.auth.is_none() {
            self.auth = Some(DatabaseTargetAuth::Password(DatabaseTargetPasswordAuth {
                password: MaybeSecretRef::default(),
            }));
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
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

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
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

    // TLS compatibility/security profile used for the target-facing RDP connection.
    // Kept as a plain comment so OpenAPI emits a direct enum reference. A field
    // description wraps the enum in allOf, which typescript-fetch misgenerates.
    #[serde(default = "_default_rdp_tls_security")]
    pub tls_security: Option<RdpTlsSecurity>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Default, Enum)]
pub enum RdpTlsSecurity {
    /// ~ Windows 2016/10
    #[serde(rename = "tls_1_2")]
    #[default]
    Tls12,
    /// ~ Windows 2012/8
    #[serde(rename = "tls_1_2_with_legacy_ciphers")]
    Tls12WithLegacyCiphers,
    /// ~ Windows 2008/Vista
    #[serde(rename = "tls_1_0_unsafe")]
    Tls10Unsafe,
}

#[allow(clippy::unnecessary_wraps)]
fn _default_rdp_tls_security() -> Option<RdpTlsSecurity> {
    Some(RdpTlsSecurity::default())
}

impl TargetRdpOptions {
    pub fn tls_security(&self) -> RdpTlsSecurity {
        self.tls_security.unwrap_or_default()
    }
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

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
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
    pub token: StoredSecret,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object, Default)]
pub struct KubernetesTargetIamRoleAuth {}

impl Default for KubernetesTargetAuth {
    fn default() -> Self {
        Self::Certificate(KubernetesTargetCertificateAuth::default())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
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

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Union)]
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
    /// Backend references among this target's credentials, so callers (e.g. a
    /// health check or an admin listing) can tell which secrets live outside
    /// Warpgate's own storage.
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

/// JSON path towards every possible credential within *serialized* TargetOptions
/// Update for new protocols
const SECRET_PATHS: &[&[&str]] = &[
    &["ssh", "auth", "password"],
    &["mysql", "auth", "password"],
    &["mysql", "password"],
    &["postgres", "auth", "password"],
    &["postgres", "password"],
    &["vnc", "auth", "password"],
    &["rdp", "auth", "password"],
    &["kubernetes", "auth", "token"],
    &["kubernetes", "auth", "private_key"],
];

/// Rewrite every secret in a serialized TargetOptions.
///
/// `f` runs on every credential value found, including backend references
/// (`vault://...`, `openbao://...`); callers that encrypt-at-rest must leave
/// references untouched themselves (see [`crate::secrets::is_secret_reference`]) —
/// encrypting one would make it indistinguishable from an inline secret on the
/// next load, silently swapping vault-backed authentication for a literal
/// password equal to the reference URI.
pub fn map_target_secrets(
    options: &mut serde_json::Value,
    f: &mut dyn FnMut(&str) -> Result<String, EncryptionError>,
) -> Result<(), EncryptionError> {
    fn resolve<'a>(
        node: &'a mut serde_json::Value,
        path: &[&str],
    ) -> Option<&'a mut serde_json::Value> {
        path.iter().try_fold(node, |node, step| node.get_mut(step))
    }

    for path in SECRET_PATHS {
        // Only a string is a credential - a missing path, a `null` auth block or an
        // unexpected shape is left exactly as it was found.
        if let Some(serde_json::Value::String(value)) = resolve(options, path) {
            let replacement = f(value)?;
            *value = replacement;
        }
    }
    Ok(())
}

/// Blanks out every secret in a serialized TargetOptions or Target (same JSON paths as options are serde(flatten))
pub fn redact_target_secrets(value: &mut serde_json::Value) {
    // The closure is infallible, so the walk is too.
    let _ = map_target_secrets(value, &mut |_| Ok(String::new()));
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::secrets::is_secret_reference;

    #[test]
    fn omitted_and_empty_tls_agree_on_verifying() {
        let absent: TargetHTTPOptions = serde_json::from_str(r#"{"url":"http://t"}"#).unwrap();
        let empty: TargetHTTPOptions =
            serde_json::from_str(r#"{"url":"http://t","tls":{}}"#).unwrap();

        assert!(absent.tls.verify);
        assert_eq!(absent.tls, empty.tls);
        assert_eq!(absent.tls, Tls::default());
    }

    #[test]
    fn every_target_kind_defaults_to_verifying() {
        let mysql: TargetMySqlOptions = serde_json::from_str(r#"{"host":"t"}"#).unwrap();
        let kubernetes: TargetKubernetesOptions = serde_json::from_str("{}").unwrap();

        assert!(mysql.tls.verify);
        assert!(kubernetes.tls.verify);
    }

    /// Turning verification off has to stay possible — it just has to be said.
    #[test]
    fn verification_can_still_be_opted_out_of() {
        let off: TargetHTTPOptions =
            serde_json::from_str(r#"{"url":"http://t","tls":{"verify":false}}"#).unwrap();

        assert!(!off.tls.verify);
    }

    fn wrap(v: &mut serde_json::Value, prefix: &str) {
        map_target_secrets(v, &mut |s| Ok(format!("{prefix}{s}"))).unwrap();
    }

    /// The reason encryption walks the JSON instead of `TargetOptions`: a
    /// `from_value`/`to_value` round trip drops the `skip_serializing` legacy password
    /// and anything a newer Warpgate wrote. Encrypting must not be able to lose a
    /// credential, so everything outside the mapped paths has to survive byte for byte.
    #[test]
    fn nothing_outside_the_mapped_paths_is_disturbed() {
        let original = serde_json::json!({
            "mysql": {
                "host": "db",
                "port": 3306,
                "auth": { "kind": "password", "password": "current" },
                "password": "legacy",
                "tls": { "mode": "preferred", "verify": true },
                "future_field": 1,
            }
        });

        let mut mapped = original.clone();
        wrap(&mut mapped, "X");
        assert_eq!(mapped["mysql"]["auth"]["password"], "Xcurrent");
        assert_eq!(mapped["mysql"]["password"], "Xlegacy");

        map_target_secrets(&mut mapped, &mut |s| {
            Ok(s.strip_prefix('X').unwrap_or(s).to_owned())
        })
        .unwrap();
        assert_eq!(mapped, original);
    }

    /// Fails when a protocol gains a credential field but not a `SECRET_PATHS` entry.
    #[test]
    fn every_credential_path_is_covered() {
        let cases = [
            (
                serde_json::json!({"ssh": {"auth": {"kind": "password", "password": "p"}}}),
                serde_json::json!({"ssh": {"auth": {"kind": "password", "password": "Xp"}}}),
            ),
            (
                serde_json::json!({"mysql": {"auth": {"kind": "password", "password": "p"}}}),
                serde_json::json!({"mysql": {"auth": {"kind": "password", "password": "Xp"}}}),
            ),
            (
                serde_json::json!({"postgres": {"auth": {"kind": "password", "password": "p"}}}),
                serde_json::json!({"postgres": {"auth": {"kind": "password", "password": "Xp"}}}),
            ),
            (
                serde_json::json!({"vnc": {"auth": {"kind": "password", "password": "p"}}}),
                serde_json::json!({"vnc": {"auth": {"kind": "password", "password": "Xp"}}}),
            ),
            (
                serde_json::json!({"rdp": {"auth": {"kind": "password", "password": "p"}}}),
                serde_json::json!({"rdp": {"auth": {"kind": "password", "password": "Xp"}}}),
            ),
            (
                serde_json::json!({"kubernetes": {"auth": {"kind": "token", "token": "t"}}}),
                serde_json::json!({"kubernetes": {"auth": {"kind": "token", "token": "Xt"}}}),
            ),
            (
                serde_json::json!({"kubernetes": {"auth": {
                    "kind": "certificate", "certificate": "pub", "private_key": "k"
                }}}),
                serde_json::json!({"kubernetes": {"auth": {
                    "kind": "certificate", "certificate": "pub", "private_key": "Xk"
                }}}),
            ),
            // HTTP carries no credential of its own, and `external_host` must stay
            // readable: `get_target_by_hostname` extracts it with raw SQL.
            (
                serde_json::json!({"http": {"url": "http://t", "external_host": "h"}}),
                serde_json::json!({"http": {"url": "http://t", "external_host": "h"}}),
            ),
        ];

        for (mut input, expected) in cases {
            wrap(&mut input, "X");
            assert_eq!(input, expected);
        }
    }

    /// A missing `auth` block must not make the walk fall through to a same-named
    /// field one level up.
    #[test]
    fn an_absent_auth_block_is_skipped_not_confused_with_its_parent() {
        let mut absent = serde_json::json!({"mysql": {"host": "db", "auth": null}});
        wrap(&mut absent, "X");
        assert_eq!(
            absent,
            serde_json::json!({"mysql": {"host": "db", "auth": null}})
        );
    }

    /// Session snapshots are stored redacted; everything else about the target has
    /// to survive, since the snapshot is what the session list displays.
    #[test]
    fn redaction_blanks_credentials_and_keeps_the_rest() {
        let mut snapshot = serde_json::json!({
            "id": "7c1c0e1e-0000-0000-0000-000000000000",
            "name": "prod-db",
            "mysql": {
                "host": "db",
                "port": 3306,
                "username": "root",
                "auth": {"kind": "password", "password": "hunter2"},
                "password": "legacy",
            }
        });

        redact_target_secrets(&mut snapshot);

        assert_eq!(snapshot["mysql"]["auth"]["password"], "");
        assert_eq!(snapshot["mysql"]["password"], "");
        assert_eq!(snapshot["mysql"]["host"], "db");
        assert_eq!(snapshot["mysql"]["username"], "root");
        assert_eq!(snapshot["name"], "prod-db");
    }

    /// A reference URI must survive an encryption sweep byte for byte — encrypting
    /// it would flip it back into an inline secret (the literal URI string) on the
    /// next load, since the ciphertext no longer starts with `vault://`. Callers that
    /// encrypt-at-rest are expected to guard their callback with
    /// `is_secret_reference`, as `serialize_options_for_storage` and the credential
    /// re-encryption backfill do.
    #[test]
    fn reference_uris_are_not_encrypted_by_a_guarded_sweep() {
        let mut value = serde_json::json!({
            "ssh": {"auth": {"kind": "password", "password": "vault://vault-prod/secret/db#password"}}
        });
        map_target_secrets(&mut value, &mut |s| {
            Ok(if is_secret_reference(s) {
                s.to_owned()
            } else {
                format!("X{s}")
            })
        })
        .unwrap();
        assert_eq!(
            value["ssh"]["auth"]["password"],
            "vault://vault-prod/secret/db#password"
        );
    }

    /// Redaction still hides a reference's existence from API responses, even though
    /// the sweep above leaves it untouched for storage.
    #[test]
    fn redaction_still_blanks_reference_uris() {
        let mut value = serde_json::json!({
            "ssh": {"auth": {"kind": "password", "password": "vault://vault-prod/secret/db#password"}}
        });
        redact_target_secrets(&mut value);
        assert_eq!(value["ssh"]["auth"]["password"], "");
    }

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

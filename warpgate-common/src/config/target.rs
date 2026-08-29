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
use crate::{Protocol, Secret, StoredSecret};

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
    #[serde(rename = "certificate")]
    Certificate(SshTargetCertificateAuth),
    #[serde(rename = "iam_role")]
    IamRole(SshTargetIamRoleAuth),
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct SshTargetPasswordAuth {
    pub password: StoredSecret,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object, Default)]
pub struct SshTargetPublicKeyAuth {
    /// Specific stored client key to authenticate with; `None` uses the keys
    /// marked default.
    #[serde(default)]
    pub key_id: Option<Uuid>,
}

/// Whether a Vault mount or role name is one Vault can address.
///
/// The rule lives here rather than in `warpgate-vault` because two crates need
/// it and only one of them can hold a Vault client: the admin API accepts a
/// role at save time, and accepting one the signing path would reject at
/// connect time leaves the operator to learn of the typo from a broken session
/// rather than from the form that took it.
#[must_use]
pub fn vault_name_is_well_formed(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object, Default)]
pub struct SshTargetCertificateAuth {
    /// Vault signing role for this target; `None` uses the configured default
    /// role. The role is what constrains which principals may be requested, so
    /// targets of differing privilege belong to differing roles.
    #[serde(default)]
    pub role: Option<String>,

    /// Critical options this target's certificates may carry.
    ///
    /// Anything not listed here is refused, because the target's sshd enforces
    /// whatever arrives: a `force-command` decides what the session runs, under
    /// the connecting user's own principal and key ID.
    ///
    /// Pinning a `value` also makes the option **mandatory** — a certificate
    /// without it is refused. Otherwise someone who can write the Vault role
    /// but not sign with it removes the pinned `force-command` instead of
    /// adding an option, and a target locked to one command hands out a shell.
    /// A bare name only permits, which is how a role that sometimes sets an
    /// option is expressed.
    #[serde(default)]
    #[oai(default)]
    pub allowed_critical_options: Vec<SshCertificateCriticalOption>,

    /// Certificate extensions this target's certificates may carry.
    ///
    /// A separate authorization mechanism from critical options, and the one
    /// that decides what a session can *do* rather than what it runs. OpenSSH
    /// opens `direct-tcpip` only for `permit-port-forwarding` and reaches the
    /// connecting user's own SSH agent only for `permit-agent-forwarding`, both
    /// judged purely on what the certificate carries. So a pinned
    /// `force-command` does not confine a session on its own: it governs the
    /// shell and exec channels and nothing else.
    ///
    /// Defaults to `permit-pty` alone — enough for an interactive session and
    /// nothing more. Anything else has to be named here, because the alternative
    /// is that a Vault role's `default_extensions`, set deliberately or written
    /// by someone with role-write and no signing right, silently grants
    /// forwarding on a target that was supposed to be locked down.
    #[serde(default = "_default_allowed_extensions")]
    #[oai(default = "_default_allowed_extensions")]
    pub allowed_extensions: Vec<String>,
}

fn _default_allowed_extensions() -> Vec<String> {
    vec!["permit-pty".to_owned()]
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct SshCertificateCriticalOption {
    /// Option name as it appears in the certificate, e.g. `force-command`.
    pub name: String,

    /// The exact value required. Unset accepts any value for this name — worth
    /// avoiding for `force-command`, whose value is the command that runs.
    #[serde(default)]
    pub value: Option<String>,
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
    pub password: StoredSecret,
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
    password: Option<StoredSecret>,

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
                password: self.password.clone().unwrap_or_default(),
            })
        }
    }

    pub fn normalize(&mut self) {
        if let Some(password) = self.password.take() {
            self.auth = Some(DatabaseTargetAuth::Password(DatabaseTargetPasswordAuth {
                password,
            }));
        } else if self.auth.is_none() {
            self.auth = Some(DatabaseTargetAuth::Password(DatabaseTargetPasswordAuth {
                password: StoredSecret::default(),
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
    password: Option<StoredSecret>,

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
                password: self.password.clone().unwrap_or_default(),
            })
        }
    }

    pub fn normalize(&mut self) {
        if let Some(password) = self.password.take() {
            self.auth = Some(DatabaseTargetAuth::Password(DatabaseTargetPasswordAuth {
                password,
            }));
        } else if self.auth.is_none() {
            self.auth = Some(DatabaseTargetAuth::Password(DatabaseTargetPasswordAuth {
                password: StoredSecret::default(),
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
    pub password: StoredSecret,
}

impl Default for VncTargetAuth {
    fn default() -> Self {
        Self::None(VncTargetNoneAuth::default())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Enum, Default)]
pub enum RdpTargetCompression {
    #[default]
    #[serde(rename = "remotefx")]
    #[oai(rename = "remotefx")]
    RemoteFX,
    #[serde(rename = "lossless")]
    #[oai(rename = "lossless")]
    Lossless,
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

    #[serde(default)]
    pub compression: Option<RdpTargetCompression>,

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
    pub password: StoredSecret,
}

impl Default for RdpTargetAuth {
    fn default() -> Self {
        Self::Password(RdpTargetPasswordAuth {
            password: StoredSecret::default(),
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
    pub fn protocol(&self) -> Protocol {
        match self {
            TargetOptions::Ssh(_) => Protocol::Ssh,
            TargetOptions::Http(_) => Protocol::Http,
            TargetOptions::Kubernetes(_) => Protocol::Kubernetes,
            TargetOptions::MySql(_) => Protocol::MySql,
            TargetOptions::Postgres(_) => Protocol::Postgres,
            TargetOptions::Vnc(_) => Protocol::Vnc,
            TargetOptions::Rdp(_) => Protocol::Rdp,
        }
    }

    // both used for connection instructions

    pub fn external_host(&self) -> Option<&str> {
        match self {
            Self::Http(options) => options.external_host.as_deref(),
            _ => None,
        }
    }

    pub fn default_database_name(&self) -> Option<&str> {
        match self {
            Self::MySql(options) => options.default_database_name.as_deref(),
            Self::Postgres(options) => options.default_database_name.as_deref(),
            _ => None,
        }
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

/// Rewrite every secret in a serialized TargetOptions
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
    use super::{TargetHTTPOptions, TargetKubernetesOptions, TargetMySqlOptions, Tls};

    /// The two ways of saying "nothing specified" — an absent `tls` block and an
    /// empty one — must both resolve to verifying.
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
        super::map_target_secrets(v, &mut |s| Ok(format!("{prefix}{s}"))).unwrap();
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

        super::map_target_secrets(&mut mapped, &mut |s| {
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

        super::redact_target_secrets(&mut snapshot);

        assert_eq!(snapshot["mysql"]["auth"]["password"], "");
        assert_eq!(snapshot["mysql"]["password"], "");
        assert_eq!(snapshot["mysql"]["host"], "db");
        assert_eq!(snapshot["mysql"]["username"], "root");
        assert_eq!(snapshot["name"], "prod-db");
    }
}

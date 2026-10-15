use std::collections::HashMap;

use poem_openapi::{Enum, Object, Union};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use warpgate_tls::TlsMode;

use super::defaults::{
    _default_empty_string, _default_empty_vec, _default_mysql_port,
    _default_postgres_idle_timeout_str, _default_postgres_port, _default_rdp_port,
    _default_ssh_ca_mount, _default_ssh_port, _default_username, _default_vnc_port,
};
use crate::secrets::{MaybeSecretRef, SecretRef, StoredSecrets};
use crate::{Protocol, Secret, StoredSecret};

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct KubernetesTargetCertificateAuth {
    pub certificate: Secret<String>,
    pub private_key: MaybeSecretRef,
}

impl Default for KubernetesTargetCertificateAuth {
    fn default() -> Self {
        Self {
            certificate: Secret::new(String::new()),
            private_key: MaybeSecretRef::default(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct TargetSSHOptions {
    pub host: String,
    #[serde(default = "_default_ssh_port")]
    #[oai(validator(minimum(value = "1")))]
    pub port: u16,
    #[serde(default = "_default_username")]
    pub username: String,
    #[serde(default)]
    pub allow_insecure_algos: bool,
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
    pub password: MaybeSecretRef,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object, Default)]
pub struct SshTargetPublicKeyAuth {
    /// Specific stored client key to authenticate with; `None` uses the keys
    /// marked default.
    #[serde(default)]
    pub key_id: Option<Uuid>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct SshTargetCertificateAuth {
    #[oai(validator(min_length = 1, max_length = 64, pattern = r"^[A-Za-z0-9._-]+$"))]
    pub backend: String,

    /// Mount of the SSH secrets engine
    #[serde(default = "_default_ssh_ca_mount")]
    #[oai(
        default = "_default_ssh_ca_mount",
        validator(min_length = 1, max_length = 255, pattern = r"^[A-Za-z0-9_-]+$")
    )]
    pub mount: String,

    /// Signing role
    #[oai(validator(min_length = 1, max_length = 255, pattern = r"^[A-Za-z0-9_-]+$"))]
    pub role: String,
}

impl Default for SshTargetCertificateAuth {
    fn default() -> Self {
        Self {
            backend: String::new(),
            mount: _default_ssh_ca_mount(),
            role: String::new(),
        }
    }
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
    pub headers: HashMap<String, String>,

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
    #[oai(validator(minimum(value = "1")))]
    pub port: u16,

    #[serde(default = "_default_username")]
    pub username: String,

    #[serde(default)]
    pub auth: DatabaseTargetAuth,

    #[serde(default)]
    pub tls: Tls,

    #[serde(default)]
    pub default_database_name: Option<String>,
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
    #[oai(validator(minimum(value = "1")))]
    pub port: u16,

    #[serde(default = "_default_username")]
    pub username: String,

    #[serde(default)]
    pub auth: DatabaseTargetAuth,

    #[serde(default)]
    pub tls: Tls,

    #[serde(default = "_default_postgres_idle_timeout_str")]
    pub idle_timeout: Option<String>,

    #[serde(default)]
    pub default_database_name: Option<String>,

    #[serde(default)]
    pub protocol_version: PostgresProtocolVersion,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct TargetVncOptions {
    #[serde(default = "_default_empty_string")]
    pub host: String,

    #[serde(default = "_default_vnc_port")]
    #[oai(validator(minimum(value = "1")))]
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

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Enum, Default)]
pub enum RdpTargetCompression {
    #[default]
    #[serde(rename = "remotefx")]
    #[oai(rename = "remotefx")]
    RemoteFX,
    #[serde(rename = "lossless")]
    #[oai(rename = "lossless")]
    Lossless,
    /// MS-RDPEGFX
    #[serde(rename = "graphics_pipeline")]
    #[oai(rename = "graphics_pipeline")]
    GraphicsPipeline,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct TargetRdpOptions {
    #[serde(default = "_default_empty_string")]
    pub host: String,

    #[serde(default = "_default_rdp_port")]
    #[oai(validator(minimum(value = "1")))]
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
    pub compression: RdpTargetCompression,

    /// Show the target's own sign-in screen instead of logging on automatically.
    /// The stored credentials still pass network-level authentication (CredSSP).
    #[serde(default)]
    pub interactive_logon: bool,

    // TLS compatibility/security profile used for the target-facing RDP connection.
    // Kept as a plain comment so OpenAPI emits a direct enum reference. A field
    // description wraps the enum in allOf, which typescript-fetch misgenerates.
    #[serde(default)]
    pub tls_security: RdpTlsSecurity,
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
    pub token: MaybeSecretRef,
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
    pub require_approval: bool,
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
    /// Every external secret reference among the credentials
    pub fn secret_references(&self) -> Vec<SecretRef> {
        self.clone()
            .secrets_mut()
            .into_iter()
            .filter_map(|s| s.as_reference().cloned())
            .collect()
    }

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

/// List refs to all credential slots of a target
pub trait TargetSecrets {
    fn secrets_mut(&mut self) -> Vec<&mut MaybeSecretRef>;
}

impl TargetSecrets for TargetSSHOptions {
    fn secrets_mut(&mut self) -> Vec<&mut MaybeSecretRef> {
        match &mut self.auth {
            SSHTargetAuth::Password(auth) => vec![&mut auth.password],
            SSHTargetAuth::PublicKey(_)
            | SSHTargetAuth::Certificate(_)
            | SSHTargetAuth::IamRole(_) => vec![],
        }
    }
}

impl TargetSecrets for TargetHTTPOptions {
    fn secrets_mut(&mut self) -> Vec<&mut MaybeSecretRef> {
        vec![]
    }
}

impl TargetSecrets for TargetKubernetesOptions {
    fn secrets_mut(&mut self) -> Vec<&mut MaybeSecretRef> {
        match &mut self.auth {
            KubernetesTargetAuth::Token(auth) => vec![&mut auth.token],
            KubernetesTargetAuth::Certificate(auth) => vec![&mut auth.private_key],
            KubernetesTargetAuth::IamRole(_) => vec![],
        }
    }
}

impl TargetSecrets for DatabaseTargetAuth {
    fn secrets_mut(&mut self) -> Vec<&mut MaybeSecretRef> {
        match self {
            Self::Password(auth) => vec![&mut auth.password],
            Self::IamRole(_) => vec![],
        }
    }
}

impl TargetSecrets for TargetMySqlOptions {
    fn secrets_mut(&mut self) -> Vec<&mut MaybeSecretRef> {
        self.auth.secrets_mut()
    }
}

impl TargetSecrets for TargetPostgresOptions {
    fn secrets_mut(&mut self) -> Vec<&mut MaybeSecretRef> {
        self.auth.secrets_mut()
    }
}

impl TargetSecrets for TargetVncOptions {
    fn secrets_mut(&mut self) -> Vec<&mut MaybeSecretRef> {
        match &mut self.auth {
            VncTargetAuth::Password(auth) => vec![&mut auth.password],
            VncTargetAuth::None(_) => vec![],
        }
    }
}

impl TargetSecrets for TargetRdpOptions {
    fn secrets_mut(&mut self) -> Vec<&mut MaybeSecretRef> {
        let RdpTargetAuth::Password(auth) = &mut self.auth;
        vec![&mut auth.password]
    }
}

impl TargetSecrets for TargetOptions {
    fn secrets_mut(&mut self) -> Vec<&mut MaybeSecretRef> {
        match self {
            TargetOptions::Ssh(o) => o.secrets_mut(),
            TargetOptions::Http(o) => o.secrets_mut(),
            TargetOptions::Kubernetes(o) => o.secrets_mut(),
            TargetOptions::MySql(o) => o.secrets_mut(),
            TargetOptions::Postgres(o) => o.secrets_mut(),
            TargetOptions::Vnc(o) => o.secrets_mut(),
            TargetOptions::Rdp(o) => o.secrets_mut(),
        }
    }
}

impl StoredSecrets for TargetOptions {
    fn stored_secrets_mut(&mut self) -> Vec<&mut StoredSecret> {
        self.secrets_mut()
            .into_iter()
            .filter_map(|slot| {
                // Only looks like a reference; it may be a legacy plaintext password
                if let MaybeSecretRef::Malformed(raw) = slot {
                    *slot = MaybeSecretRef::Inline(std::mem::take(raw).into());
                }
                slot.inline_mut()
            })
            .collect()
    }
}

impl StoredSecrets for Target {
    fn stored_secrets_mut(&mut self) -> Vec<&mut StoredSecret> {
        self.options.stored_secrets_mut()
    }
}

#[cfg(test)]
mod tests {

    use super::{
        DatabaseTargetAuth, DatabaseTargetIamRoleAuth, DatabaseTargetPasswordAuth, MaybeSecretRef,
        PostgresProtocolVersion, RdpTargetCompression, RdpTlsSecurity, SSHTargetAuth, SecretRef,
        SshTargetCertificateAuth, SshTargetIamRoleAuth, SshTargetPasswordAuth,
        SshTargetPublicKeyAuth, TargetHTTPOptions, TargetKubernetesOptions, TargetMySqlOptions,
        TargetOptions, TargetPostgresOptions, TargetRdpOptions, TargetSSHOptions, Tls,
    };
    use crate::{StoredSecrets, TargetSecrets};

    const REFERENCE: &str = "secret://vault-prod/secret/db#password";

    fn ssh_options(auth: SSHTargetAuth) -> TargetOptions {
        let mut options: TargetSSHOptions = serde_json::from_str(r#"{"host":"h"}"#).unwrap();
        options.auth = auth;
        TargetOptions::Ssh(options)
    }

    fn reference() -> MaybeSecretRef {
        SecretRef {
            backend: "vault-prod".into(),
            mount: "secret".into(),
            path: "db".into(),
            field: "password".into(),
        }
        .into()
    }

    fn db_password_auth(password: MaybeSecretRef) -> DatabaseTargetAuth {
        DatabaseTargetAuth::Password(DatabaseTargetPasswordAuth { password })
    }

    #[test]
    fn password_references_are_collected() {
        let ssh = ssh_options(SSHTargetAuth::Password(SshTargetPasswordAuth {
            password: reference(),
        }));
        let mut mysql: TargetMySqlOptions = serde_json::from_str("{}").unwrap();
        mysql.auth = db_password_auth(reference());
        let mut postgres: TargetPostgresOptions = serde_json::from_str("{}").unwrap();
        postgres.auth = db_password_auth(reference());

        for options in [
            ssh,
            TargetOptions::MySql(mysql),
            TargetOptions::Postgres(postgres),
        ] {
            let refs = options.secret_references();
            assert_eq!(refs.len(), 1);
            assert_eq!(refs[0].to_string(), REFERENCE);
        }
    }

    #[test]
    fn inline_and_non_password_credentials_are_not_references() {
        let mut mysql: TargetMySqlOptions = serde_json::from_str("{}").unwrap();
        mysql.auth = DatabaseTargetAuth::IamRole(DatabaseTargetIamRoleAuth::default());
        let mut postgres: TargetPostgresOptions = serde_json::from_str("{}").unwrap();
        postgres.auth = db_password_auth(MaybeSecretRef::default());
        let cases = [
            ssh_options(SSHTargetAuth::Password(SshTargetPasswordAuth {
                password: MaybeSecretRef::default(),
            })),
            ssh_options(SSHTargetAuth::PublicKey(SshTargetPublicKeyAuth::default())),
            ssh_options(SSHTargetAuth::Certificate(
                SshTargetCertificateAuth::default(),
            )),
            ssh_options(SSHTargetAuth::IamRole(SshTargetIamRoleAuth::default())),
            TargetOptions::MySql(mysql),
            TargetOptions::Postgres(postgres),
            TargetOptions::Http(serde_json::from_str(r#"{"url":"http://x"}"#).unwrap()),
            TargetOptions::Kubernetes(serde_json::from_str("{}").unwrap()),
        ];
        for options in cases {
            assert!(options.secret_references().is_empty());
        }
    }

    /// A reference names where a credential lives; encrypting or blanking it
    /// would hide which backend a target uses from both the UI and the resolver.
    #[test]
    fn references_are_not_stored_secrets() {
        let mut options = ssh_options(SSHTargetAuth::Password(SshTargetPasswordAuth {
            password: reference(),
        }));
        let original = options.clone();

        assert!(options.stored_secrets_mut().is_empty());
        assert!(!options.reencrypt_all().unwrap());
        options.redact();
        assert_eq!(options, original);
    }

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

    /// These fields stopped being `Option`, and m00087 drops the explicit nulls
    /// left behind rather than translating them. Their defaults therefore have to
    /// keep producing what the old `unwrap_or` did.
    #[test]
    fn an_omitted_field_defaults_to_what_the_option_fell_back_to() {
        let ssh: TargetSSHOptions = serde_json::from_str(r#"{"host":"h"}"#).unwrap();
        let http: TargetHTTPOptions = serde_json::from_str(r#"{"url":"http://t"}"#).unwrap();
        let mysql: TargetMySqlOptions = serde_json::from_str("{}").unwrap();
        let postgres: TargetPostgresOptions = serde_json::from_str("{}").unwrap();
        let rdp: TargetRdpOptions = serde_json::from_str("{}").unwrap();

        assert!(!ssh.allow_insecure_algos);
        assert!(http.headers.is_empty());
        assert_eq!(postgres.protocol_version, PostgresProtocolVersion::V3_2);
        assert_eq!(rdp.compression, RdpTargetCompression::RemoteFX);
        assert_eq!(rdp.tls_security, RdpTlsSecurity::Tls12);
        let empty_password = DatabaseTargetAuth::Password(DatabaseTargetPasswordAuth::default());
        assert_eq!(mysql.auth, empty_password);
        assert_eq!(postgres.auth, empty_password);
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

    /// Fails when a protocol gains a credential field that `secrets_mut` does not
    /// list: every sentinel string in the serialized options must be a slot.
    #[test]
    fn every_secret_field_is_a_slot() {
        use std::str::FromStr;

        use super::{
            KubernetesTargetAuth, KubernetesTargetCertificateAuth, KubernetesTargetTokenAuth,
            MaybeSecretRef, RdpTargetAuth, RdpTargetPasswordAuth, SSHTargetAuth,
            SshTargetPasswordAuth, TargetOptions, TargetSecrets, VncTargetAuth,
            VncTargetPasswordAuth,
        };

        fn sentinels(value: &serde_json::Value) -> usize {
            match value {
                serde_json::Value::String(s) => usize::from(s == "s"),
                serde_json::Value::Object(map) => map.values().map(sentinels).sum(),
                serde_json::Value::Array(items) => items.iter().map(sentinels).sum(),
                _ => 0,
            }
        }

        let secret = || MaybeSecretRef::from_str("s").unwrap();
        let mut ssh: TargetSSHOptions = serde_json::from_str(r#"{"host":"h"}"#).unwrap();
        ssh.auth = SSHTargetAuth::Password(SshTargetPasswordAuth { password: secret() });
        let mut mysql: TargetMySqlOptions = serde_json::from_str("{}").unwrap();
        mysql.auth =
            DatabaseTargetAuth::Password(DatabaseTargetPasswordAuth { password: secret() });
        let mut postgres: TargetPostgresOptions = serde_json::from_str("{}").unwrap();
        postgres.auth =
            DatabaseTargetAuth::Password(DatabaseTargetPasswordAuth { password: secret() });
        let mut vnc: super::TargetVncOptions = serde_json::from_str(r#"{"host":"h"}"#).unwrap();
        vnc.auth = VncTargetAuth::Password(VncTargetPasswordAuth { password: secret() });
        let mut rdp: TargetRdpOptions = serde_json::from_str("{}").unwrap();
        rdp.auth = RdpTargetAuth::Password(RdpTargetPasswordAuth { password: secret() });
        let mut k8s_token: TargetKubernetesOptions = serde_json::from_str("{}").unwrap();
        k8s_token.auth = KubernetesTargetAuth::Token(KubernetesTargetTokenAuth { token: secret() });
        let mut k8s_cert: TargetKubernetesOptions = serde_json::from_str("{}").unwrap();
        k8s_cert.auth = KubernetesTargetAuth::Certificate(KubernetesTargetCertificateAuth {
            certificate: "c".to_string().into(),
            private_key: secret(),
        });

        for mut options in [
            TargetOptions::Ssh(ssh),
            TargetOptions::MySql(mysql),
            TargetOptions::Postgres(postgres),
            TargetOptions::Vnc(vnc),
            TargetOptions::Rdp(rdp),
            TargetOptions::Kubernetes(k8s_token),
            TargetOptions::Kubernetes(k8s_cert),
            TargetOptions::Http(serde_json::from_str(r#"{"url":"http://t"}"#).unwrap()),
        ] {
            let rendered = serde_json::to_value(&options).unwrap();
            assert_eq!(
                options.secrets_mut().len(),
                sentinels(&rendered),
                "{rendered}"
            );
        }
    }

    /// Session snapshots are stored redacted; everything else about the target has
    /// to survive, since the snapshot is what the session list displays.
    #[test]
    fn redaction_blanks_credentials_and_keeps_the_rest() {
        use std::str::FromStr;

        let mut mysql: TargetMySqlOptions =
            serde_json::from_str(r#"{"host":"db","username":"root"}"#).unwrap();
        mysql.auth = db_password_auth(MaybeSecretRef::from_str("hunter2").unwrap());
        let options = TargetOptions::MySql(mysql);

        let snapshot = serde_json::to_value(options.redacted()).unwrap();

        assert_eq!(snapshot["mysql"]["auth"]["password"], "");
        assert_eq!(snapshot["mysql"]["host"], "db");
        assert_eq!(snapshot["mysql"]["username"], "root");
    }

    const MALFORMED: &str = "secret://not a valid ref";

    fn malformed_options() -> TargetOptions {
        let options: TargetOptions = serde_json::from_value(serde_json::json!({
            "mysql": {"host": "db", "auth": {"kind": "password", "password": MALFORMED}}
        }))
        .unwrap();
        assert!(matches!(
            &options,
            TargetOptions::MySql(mysql)
                if mysql.auth == db_password_auth(MaybeSecretRef::Malformed(MALFORMED.into()))
        ));
        options
    }

    /// A stored string that only looks like a reference may be a legacy
    /// plaintext password.
    #[test]
    fn malformed_reference_is_redacted() {
        let snapshot = serde_json::to_value(malformed_options().redacted()).unwrap();

        assert_eq!(snapshot["mysql"]["auth"]["password"], "", "{snapshot}");
        assert_eq!(snapshot["mysql"]["host"], "db");
    }

    #[test]
    fn malformed_reference_is_a_stored_secret() {
        assert_eq!(malformed_options().stored_secrets_mut().len(), 1);
    }
}

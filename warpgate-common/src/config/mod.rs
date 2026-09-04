mod defaults;
mod specific_target;
mod target;
mod warnings;

use std::ops::Deref;
use std::path::PathBuf;
use std::time::Duration;

use defaults::{
    _default_audit_retention, _default_azure_imds, _default_azure_resource,
    _default_cookie_max_age, _default_database_url, _default_false, _default_gcp_metadata,
    _default_http_listen, _default_kubernetes_listen, _default_mysql_advertised_version,
    _default_mysql_listen, _default_postgres_listen, _default_rdp_listen, _default_recordings_path,
    _default_retention, _default_session_max_age, _default_ssh_inactivity_timeout,
    _default_ssh_keys_path, _default_ssh_listen, _default_vault_kubernetes_token_path,
    _default_vault_ssh_mount, _default_vault_timeout, _default_vnc_listen,
};
use poem_openapi::{Object, Union};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
pub use specific_target::*;
pub use target::*;
use uuid::Uuid;
pub use warnings::{clear_config_warnings, emit_config_warning, emit_runtime_warning, warnings};
use warpgate_sso::SsoProviderConfig;
use warpgate_tls::IntoTlsCertificateRelativePaths;

use crate::auth::CredentialKind;
use crate::helpers::hash::hash_password;
use crate::helpers::ipnet::WarpgateIpNet;
use crate::helpers::otp::OtpSecretKey;
use crate::{ListenEndpoint, Secret};

#[derive(Debug, Clone, PartialEq, Eq, Union)]
#[oai(discriminator_name = "kind", one_of)]
pub enum UserAuthCredential {
    Password(UserPasswordCredential),
    PublicKey(UserPublicKeyCredential),
    Certificate(UserCertificateCredential),
    Totp(UserTotpCredential),
    Sso(UserSsoCredential),
}

#[derive(Debug, Clone, PartialEq, Eq, Object)]
pub struct UserPasswordCredential {
    pub hash: Secret<String>,
}

impl UserPasswordCredential {
    pub fn from_password(password: &Secret<String>) -> Self {
        Self {
            hash: Secret::new(hash_password(password.expose_secret())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Object)]
pub struct UserPublicKeyCredential {
    pub key: Secret<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Object)]
pub struct UserCertificateCredential {
    pub certificate_pem: Secret<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Object)]
pub struct UserTotpCredential {
    pub key: OtpSecretKey,
}
#[derive(Debug, Clone, PartialEq, Eq, Object)]
pub struct UserSsoCredential {
    pub provider: Option<String>,
    pub email: String,
}

impl UserAuthCredential {
    pub const fn kind(&self) -> CredentialKind {
        match self {
            Self::Password(_) => CredentialKind::Password,
            Self::PublicKey(_) => CredentialKind::PublicKey,
            Self::Certificate(_) => CredentialKind::Certificate,
            Self::Totp(_) => CredentialKind::Totp,
            Self::Sso(_) => CredentialKind::Sso,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Object, Default)]
pub struct UserRequireCredentialsPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<Vec<CredentialKind>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kubernetes: Option<Vec<CredentialKind>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh: Option<Vec<CredentialKind>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mysql: Option<Vec<CredentialKind>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postgres: Option<Vec<CredentialKind>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vnc: Option<Vec<CredentialKind>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rdp: Option<Vec<CredentialKind>>,
}

impl UserRequireCredentialsPolicy {
    #[must_use]
    pub fn upgrade_to_otp(&self, with_existing_credentials: &[UserAuthCredential]) -> Self {
        let mut copy = self.clone();

        if let Some(policy) = &mut copy.http {
            policy.push(CredentialKind::Totp);
        } else {
            // Upgrade to OTP only if there is a password credential
            let mut kinds = vec![];
            if with_existing_credentials
                .iter()
                .any(|c| c.kind() == CredentialKind::Password)
            {
                kinds.push(CredentialKind::Password);
            }
            if !kinds.is_empty() {
                kinds.push(CredentialKind::Totp);
                copy.http = Some(kinds);
            }
        }

        if let Some(policy) = &mut copy.ssh {
            policy.push(CredentialKind::Totp);
        } else {
            // Upgrade to OTP only if there is a password or public key credential
            let mut kinds = vec![];
            if with_existing_credentials.iter().any(|c| {
                c.kind() == CredentialKind::Password || c.kind() == CredentialKind::PublicKey
            }) {
                kinds.push(CredentialKind::Password);
            }
            if !kinds.is_empty() {
                kinds.push(CredentialKind::Totp);
                copy.ssh = Some(kinds);
            }
        }
        copy
    }
}

#[derive(Debug, Clone, Object)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub description: String,
    pub credential_policy: Option<UserRequireCredentialsPolicy>,
    pub rate_limit_bytes_per_second: Option<i64>,
    pub ldap_server_id: Option<Uuid>,
    pub allowed_ip_ranges: Option<Vec<WarpgateIpNet>>,
}

#[derive(Debug, Clone, Object)]
pub struct UserDetails {
    pub inner: User,
    pub credentials: Vec<UserAuthCredential>,
    pub roles: Vec<String>,
}

impl Deref for UserDetails {
    type Target = User;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Object)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub is_default: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Object)]
pub struct AdminRole {
    pub id: Uuid,
    pub name: String,
    pub description: String,

    pub targets_create: bool,
    pub targets_edit: bool,
    pub targets_delete: bool,

    pub users_create: bool,
    pub users_edit: bool,
    pub users_delete: bool,

    pub access_roles_create: bool,
    pub access_roles_edit: bool,
    pub access_roles_delete: bool,
    pub access_roles_assign: bool,

    pub sessions_view: bool,
    pub sessions_terminate: bool,

    pub recordings_view: bool,

    pub tickets_create: bool,
    pub tickets_delete: bool,

    pub config_edit: bool,

    pub admin_roles_manage: bool,

    pub ticket_requests_manage: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, JsonSchema, strum::EnumIter)]
#[serde(rename_all = "snake_case")]
pub enum AdminPermission {
    TargetsCreate,
    TargetsEdit,
    TargetsDelete,
    UsersCreate,
    UsersEdit,
    UsersDelete,
    AccessRolesCreate,
    AccessRolesEdit,
    AccessRolesDelete,
    AccessRolesAssign,
    SessionsView,
    SessionsTerminate,
    RecordingsView,
    TicketsCreate,
    TicketsDelete,
    ConfigEdit,
    AdminRolesManage,
    TicketRequestsManage,
}

impl AdminRole {
    pub const fn has_permission(&self, perm: AdminPermission) -> bool {
        match perm {
            AdminPermission::TargetsCreate => self.targets_create,
            AdminPermission::TargetsEdit => self.targets_edit,
            AdminPermission::TargetsDelete => self.targets_delete,
            AdminPermission::UsersCreate => self.users_create,
            AdminPermission::UsersEdit => self.users_edit,
            AdminPermission::UsersDelete => self.users_delete,
            AdminPermission::AccessRolesCreate => self.access_roles_create,
            AdminPermission::AccessRolesEdit => self.access_roles_edit,
            AdminPermission::AccessRolesDelete => self.access_roles_delete,
            AdminPermission::AccessRolesAssign => self.access_roles_assign,
            AdminPermission::SessionsView => self.sessions_view,
            AdminPermission::SessionsTerminate => self.sessions_terminate,
            AdminPermission::RecordingsView => self.recordings_view,
            AdminPermission::TicketsCreate => self.tickets_create,
            AdminPermission::TicketsDelete => self.tickets_delete,
            AdminPermission::ConfigEdit => self.config_edit,
            AdminPermission::AdminRolesManage => self.admin_roles_manage,
            AdminPermission::TicketRequestsManage => self.ticket_requests_manage,
        }
    }
}

use strum::IntoEnumIterator;

impl AdminPermission {
    /// The bit this permission occupies in an [`AdminPermissionSet`].
    const fn bit(self) -> u32 {
        1 << self as u32
    }
}

/// The set of admin permissions a principal holds, folded from their assigned roles once so
/// every consumer — the endpoint gate, the "is this an admin?" checks, and the UI
/// serialization — reads one value instead of re-deriving the model three different ways.
///
/// An administrator is a principal holding at least one permission: a role that grants nothing
/// confers no admin standing (there is no such thing as a permissionless admin).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminPermissionSet(u32);

impl AdminPermissionSet {
    /// No permissions — the principal is not an administrator.
    #[must_use]
    pub const fn none() -> Self {
        Self(0)
    }

    /// Every permission, e.g. for an admin token.
    #[must_use]
    pub fn all() -> Self {
        Self(AdminPermission::iter().fold(0, |bits, perm| bits | perm.bit()))
    }

    /// The union of the permissions granted by `roles`.
    #[must_use]
    pub fn from_roles(roles: impl IntoIterator<Item = AdminRole>) -> Self {
        let mut bits = 0;
        for role in roles {
            for perm in AdminPermission::iter() {
                if role.has_permission(perm) {
                    bits |= perm.bit();
                }
            }
        }
        Self(bits)
    }

    #[must_use]
    pub const fn contains(self, perm: AdminPermission) -> bool {
        self.0 & perm.bit() != 0
    }

    /// Holding any permission at all makes the principal an administrator.
    #[must_use]
    pub const fn is_admin(self) -> bool {
        self.0 != 0
    }
}

#[cfg(test)]
mod admin_permission_set_tests {
    use strum::IntoEnumIterator;
    use uuid::Uuid;

    use super::{AdminPermission, AdminPermissionSet, AdminRole};

    fn empty_role() -> AdminRole {
        AdminRole {
            id: Uuid::nil(),
            name: String::new(),
            description: String::new(),
            targets_create: false,
            targets_edit: false,
            targets_delete: false,
            users_create: false,
            users_edit: false,
            users_delete: false,
            access_roles_create: false,
            access_roles_edit: false,
            access_roles_delete: false,
            access_roles_assign: false,
            sessions_view: false,
            sessions_terminate: false,
            recordings_view: false,
            tickets_create: false,
            tickets_delete: false,
            config_edit: false,
            admin_roles_manage: false,
            ticket_requests_manage: false,
        }
    }

    #[test]
    fn empty_is_not_admin() {
        let set = AdminPermissionSet::from_roles([]);
        assert_eq!(set, AdminPermissionSet::none());
        assert!(!set.is_admin());
        assert!(!set.contains(AdminPermission::ConfigEdit));
    }

    #[test]
    fn unions_roles_and_reports_admin() {
        let mut a = empty_role();
        a.targets_create = true;
        let mut b = empty_role();
        b.config_edit = true;
        let set = AdminPermissionSet::from_roles([a, b]);
        assert!(set.is_admin());
        assert!(set.contains(AdminPermission::TargetsCreate));
        assert!(set.contains(AdminPermission::ConfigEdit));
        assert!(!set.contains(AdminPermission::UsersDelete));
    }

    #[test]
    fn all_contains_every_permission() {
        let all = AdminPermissionSet::all();
        for perm in AdminPermission::iter() {
            assert!(all.contains(perm), "missing {perm:?}");
        }
    }

    #[test]
    fn role_granting_nothing_is_not_admin() {
        let set = AdminPermissionSet::from_roles([empty_role()]);
        assert!(!set.is_admin());
        assert_eq!(set, AdminPermissionSet::none());
    }
}

#[derive(
    Debug, Deserialize, Serialize, Clone, Default, PartialEq, Eq, Copy, JsonSchema, clap::ValueEnum,
)]
pub enum SshHostKeyVerificationMode {
    #[serde(rename = "prompt")]
    #[default]
    Prompt,
    #[serde(rename = "auto_accept")]
    AutoAccept,
    #[serde(rename = "auto_reject")]
    AutoReject,
    #[serde(rename = "ignore")]
    Ignore,
}

#[derive(
    Debug, Deserialize, Serialize, Clone, Copy, Default, PartialEq, Eq, JsonSchema, clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

/// How Warpgate proves its own identity to Vault.
///
/// No method reads its credential from the config, deliberately: the point of
/// issuing target credentials on demand is that nothing long-lived sits on the
/// Warpgate host, and a value pasted into the config would put it straight
/// back. Kubernetes and AppRole read a file — a service account token mounted
/// and rotated by the kubelet, or a short-lived secret ID meant to arrive
/// response-wrapped from whatever provisions the host. AWS, GCP and Azure read
/// nothing durable at all: each proves the workload's own cloud identity, over
/// the instance metadata service or the provider's credential chain.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VaultAuth {
    Kubernetes {
        role: String,
        #[serde(default = "_default_vault_kubernetes_token_path")]
        token_path: PathBuf,
    },
    AppRole {
        // Vault treats this as public — half a credential, useless without the
        // secret ID. Wrapped anyway, so that every field here that is part of
        // an authentication is redacted by one rule rather than by a judgement
        // about which halves matter. A `///` comment would put this rationale
        // in `config-schema.json` as operator-facing documentation, which it is
        // not.
        #[schemars(with = "String")]
        role_id: Secret<String>,
        secret_id_path: PathBuf,
    },
    /// Signs an `sts:GetCallerIdentity` call with the default credential chain —
    /// on EC2 that is the instance role. Access keys in the environment work but
    /// put back the long-lived secret this exists to avoid.
    Aws {
        #[serde(default)]
        role: Option<String>,
        /// Bound into the signature so a captured request cannot be replayed
        /// against a different Vault. Must match the server's `iam_server_id_header_value`.
        #[serde(default)]
        server_id: Option<String>,
        /// Signs against a regional STS endpoint instead of the global one. Set
        /// this only when Vault is configured with a matching `sts_endpoint`:
        /// Vault replays the request globally by default, and a region-scoped
        /// signature is rejected there.
        #[serde(default)]
        region: Option<String>,
    },
    Azure {
        role: String,
        #[serde(default = "_default_azure_resource")]
        resource: String,
        #[serde(default = "_default_azure_imds")]
        metadata_address: String,
    },
    Gcp {
        role: String,
        #[serde(default = "_default_gcp_metadata")]
        metadata_address: String,
    },
}

impl VaultAuth {
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Kubernetes { .. } => "kubernetes",
            Self::AppRole { .. } => "approle",
            Self::Aws { .. } => "aws",
            Self::Azure { .. } => "azure",
            Self::Gcp { .. } => "gcp",
        }
    }
}

/// The longest a session certificate may be valid for.
///
/// Generous — a role would have to be badly misconfigured to exceed it — but the
/// point of this feature is a credential that is worthless a few minutes after
/// it is issued, and nothing else anywhere checks that.
///
/// Here rather than beside either user, because it is checked at both ends and
/// they are in different crates: `certificate_ttl` is refused against it when
/// the config loads, and a certificate that comes back exceeding it is refused
/// when it arrives. Two copies of one number is how they drift apart.
pub const MAX_CERTIFICATE_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, JsonSchema)]
pub struct VaultConfig {
    /// Base URL of the Vault server, e.g. `https://vault.internal:8200`.
    pub address: String,

    /// Mount point of the SSH secrets engine in signed-certificates mode.
    #[serde(default = "_default_vault_ssh_mount")]
    pub mount: String,

    /// Signing role used by targets that don't name one of their own.
    pub default_role: String,

    pub auth: VaultAuth,

    /// Lifetime asked for when signing. Vault clamps this to the role's
    /// `max_ttl`, so it can only shorten what the role already allows — set it
    /// to hold the window down without editing Vault. Left unset, the role's own
    /// TTL decides.
    #[serde(default, with = "humantime_serde::option")]
    #[schemars(with = "Option<String>")]
    pub certificate_ttl: Option<Duration>,

    #[serde(default = "_default_vault_timeout", with = "humantime_serde")]
    #[schemars(with = "String")]
    pub timeout: Duration,

    /// PEM file holding the CA that issued Vault's certificate, for a Vault
    /// behind a private CA.
    ///
    /// Added to the host's trust store rather than replacing it, so a
    /// misconfigured path cannot silently turn verification off — an
    /// unreadable or malformed file is a startup error. There is deliberately
    /// no switch to skip verification: the Vault token crosses this connection
    /// in a header, and unlike the HTTP and Kubernetes target paths, which
    /// offer `verify: false` for devices whose certificates cannot be fixed,
    /// there is no equivalent case here.
    #[serde(default)]
    pub ca_bundle: Option<PathBuf>,

    /// The signing CA the target trusts, in OpenSSH public-key format
    /// (`ssh-ed25519 AAAA…`), pinned so a certificate signed by anything else
    /// is refused before it is offered.
    ///
    /// Every other check on Vault's response asks whether the certificate is
    /// what was requested. This is the only one that asks *who signed it*. The
    /// target's `TrustedUserCAKeys` is the real enforcement and would refuse
    /// such a certificate anyway — but it does so after Warpgate has offered
    /// it, and the refusal that comes back names the target rather than the
    /// issuer that mis-signed. Pinning turns a confusing rejection into a
    /// precise one, and detects a role rebound to a different CA.
    ///
    /// Left unset, nothing is checked here.
    #[serde(default)]
    pub ca_public_key: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct SshConfig {
    #[serde(default = "_default_false")]
    pub enable: bool,

    #[serde(default = "_default_ssh_listen")]
    pub listen: ListenEndpoint,

    /// Accept HAProxy PROXY protocol v1/v2 headers from the listener's peer.
    #[serde(default)]
    pub proxy_protocol: bool,

    #[serde(default)]
    pub external_port: Option<u16>,

    #[serde(default)]
    pub external_host: Option<String>,

    #[serde(default = "_default_ssh_keys_path")]
    pub keys: String,

    /// Only seeds the `ssh_host_key_verification` parameter when the database
    /// row is first created; the admin UI owns the setting afterwards.
    #[serde(default)]
    pub host_key_verification: SshHostKeyVerificationMode,

    #[serde(default = "_default_ssh_inactivity_timeout", with = "humantime_serde")]
    #[schemars(with = "String")]
    pub inactivity_timeout: Duration,

    #[serde(default, with = "humantime_serde")]
    #[schemars(with = "Option<String>")]
    pub keepalive_interval: Option<Duration>,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            enable: false,
            listen: _default_ssh_listen(),
            proxy_protocol: false,
            keys: _default_ssh_keys_path(),
            host_key_verification: <_>::default(),
            external_port: None,
            external_host: None,
            inactivity_timeout: _default_ssh_inactivity_timeout(),
            keepalive_interval: None,
        }
    }
}

impl SshConfig {
    pub fn external_port(&self) -> u16 {
        self.external_port.unwrap_or_else(|| self.listen.port())
    }

    pub fn external_host(&self) -> Option<String> {
        self.external_host.clone()
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct SniCertificateConfig {
    pub certificate: String,
    pub key: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct HttpConfig {
    #[serde(default = "_default_http_listen")]
    pub listen: ListenEndpoint,

    /// Accept HAProxy PROXY protocol v1/v2 headers from the listener's peer.
    #[serde(default)]
    pub proxy_protocol: bool,

    #[serde(default)]
    pub external_port: Option<u16>,

    #[serde(default)]
    pub external_host: Option<String>,

    #[serde(default)]
    pub certificate: String,

    #[serde(default)]
    pub key: String,

    #[serde(default)]
    pub trust_x_forwarded_headers: bool,

    #[serde(default = "_default_session_max_age", with = "humantime_serde")]
    #[schemars(with = "String")]
    pub session_max_age: Duration,

    #[serde(default = "_default_cookie_max_age", with = "humantime_serde")]
    #[schemars(with = "String")]
    pub cookie_max_age: Duration,

    #[serde(default)]
    pub sni_certificates: Vec<SniCertificateConfig>,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            listen: _default_http_listen(),
            proxy_protocol: false,
            external_port: None,
            external_host: None,
            certificate: "".into(),
            key: "".into(),
            trust_x_forwarded_headers: false,
            session_max_age: _default_session_max_age(),
            cookie_max_age: _default_cookie_max_age(),
            sni_certificates: vec![],
        }
    }
}

impl HttpConfig {
    pub fn external_port(&self) -> u16 {
        self.external_port.unwrap_or_else(|| self.listen.port())
    }

    pub fn external_host(&self) -> Option<String> {
        self.external_host.clone()
    }
}

impl IntoTlsCertificateRelativePaths for HttpConfig {
    fn certificate_path(&self) -> PathBuf {
        self.certificate.as_str().into()
    }

    fn key_path(&self) -> PathBuf {
        self.key.as_str().into()
    }
}

impl IntoTlsCertificateRelativePaths for SniCertificateConfig {
    fn certificate_path(&self) -> PathBuf {
        self.certificate.as_str().into()
    }

    fn key_path(&self) -> PathBuf {
        self.key.as_str().into()
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct MySqlConfig {
    #[serde(default = "_default_false")]
    pub enable: bool,

    #[serde(default = "_default_mysql_listen")]
    pub listen: ListenEndpoint,

    /// Accept HAProxy PROXY protocol v1/v2 headers from the listener's peer.
    #[serde(default)]
    pub proxy_protocol: bool,

    #[serde(default)]
    pub external_port: Option<u16>,

    #[serde(default)]
    pub external_host: Option<String>,

    #[serde(default)]
    pub certificate: String,

    #[serde(default)]
    pub key: String,

    /// The server version advertised to clients during the handshake.
    /// We can't auto-match the target's version since the target is only known
    /// after the handshake, but clients use it to pick a protocol dialect.
    #[serde(default = "_default_mysql_advertised_version")]
    pub advertised_version: String,
}

impl Default for MySqlConfig {
    fn default() -> Self {
        Self {
            enable: false,
            listen: _default_mysql_listen(),
            proxy_protocol: false,
            external_port: None,
            external_host: None,
            certificate: "".into(),
            key: "".into(),
            advertised_version: _default_mysql_advertised_version(),
        }
    }
}

impl MySqlConfig {
    pub fn external_port(&self) -> u16 {
        self.external_port.unwrap_or_else(|| self.listen.port())
    }

    pub fn external_host(&self) -> Option<String> {
        self.external_host.clone()
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct KubernetesConfig {
    #[serde(default = "_default_false")]
    pub enable: bool,

    #[serde(default = "_default_kubernetes_listen")]
    pub listen: ListenEndpoint,

    /// Accept HAProxy PROXY protocol v1/v2 headers from the listener's peer.
    #[serde(default)]
    pub proxy_protocol: bool,

    #[serde(default)]
    pub external_port: Option<u16>,

    #[serde(default)]
    pub external_host: Option<String>,

    #[serde(default)]
    pub certificate: String,

    #[serde(default)]
    pub key: String,

    #[serde(default = "_default_session_max_age", with = "humantime_serde")]
    #[schemars(with = "String")]
    pub session_max_age: Duration,
}

impl Default for KubernetesConfig {
    fn default() -> Self {
        Self {
            enable: false,
            listen: _default_kubernetes_listen(),
            proxy_protocol: false,
            external_port: None,
            external_host: None,
            certificate: "".into(),
            key: "".into(),
            session_max_age: _default_session_max_age(),
        }
    }
}

impl KubernetesConfig {
    pub fn external_port(&self) -> u16 {
        self.external_port.unwrap_or_else(|| self.listen.port())
    }

    pub fn external_host(&self) -> Option<String> {
        self.external_host.clone()
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct PostgresConfig {
    #[serde(default = "_default_false")]
    pub enable: bool,

    #[serde(default = "_default_postgres_listen")]
    pub listen: ListenEndpoint,

    /// Accept HAProxy PROXY protocol v1/v2 headers from the listener's peer.
    #[serde(default)]
    pub proxy_protocol: bool,

    #[serde(default)]
    pub external_port: Option<u16>,

    #[serde(default)]
    pub external_host: Option<String>,

    #[serde(default)]
    pub certificate: String,

    #[serde(default)]
    pub key: String,
}

impl Default for PostgresConfig {
    fn default() -> Self {
        Self {
            enable: false,
            listen: _default_postgres_listen(),
            proxy_protocol: false,
            external_port: None,
            external_host: None,
            certificate: "".into(),
            key: "".into(),
        }
    }
}

impl PostgresConfig {
    pub fn external_port(&self) -> u16 {
        self.external_port.unwrap_or_else(|| self.listen.port())
    }

    pub fn external_host(&self) -> Option<String> {
        self.external_host.clone()
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct VncConfig {
    #[serde(default = "_default_false")]
    pub enable: bool,

    #[serde(default = "_default_vnc_listen")]
    pub listen: ListenEndpoint,

    /// Accept HAProxy PROXY protocol v1/v2 headers from the listener's peer.
    #[serde(default)]
    pub proxy_protocol: bool,

    #[serde(default)]
    pub external_port: Option<u16>,

    #[serde(default)]
    pub external_host: Option<String>,

    #[serde(default)]
    pub certificate: String,

    #[serde(default)]
    pub key: String,

    /// Enable Apple-DH (ARD / type 30) auth. It does not support TLS unlike VeNCrypt
    #[serde(default = "_default_false")]
    pub enable_ard_auth: bool,
}

impl Default for VncConfig {
    fn default() -> Self {
        Self {
            enable: false,
            listen: _default_vnc_listen(),
            proxy_protocol: false,
            external_port: None,
            external_host: None,
            certificate: "".into(),
            key: "".into(),
            enable_ard_auth: false,
        }
    }
}

impl VncConfig {
    pub fn external_port(&self) -> u16 {
        self.external_port.unwrap_or_else(|| self.listen.port())
    }

    pub fn external_host(&self) -> Option<String> {
        self.external_host.clone()
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct RdpConfig {
    #[serde(default = "_default_false")]
    pub enable: bool,

    #[serde(default = "_default_rdp_listen")]
    pub listen: ListenEndpoint,

    /// Accept HAProxy PROXY protocol v1/v2 headers from the listener's peer.
    #[serde(default)]
    pub proxy_protocol: bool,

    #[serde(default)]
    pub external_port: Option<u16>,

    #[serde(default)]
    pub external_host: Option<String>,

    #[serde(default)]
    pub certificate: String,

    #[serde(default)]
    pub key: String,
}

impl Default for RdpConfig {
    fn default() -> Self {
        Self {
            enable: false,
            listen: _default_rdp_listen(),
            proxy_protocol: false,
            external_port: None,
            external_host: None,
            certificate: "".into(),
            key: "".into(),
        }
    }
}

impl RdpConfig {
    pub fn external_port(&self) -> u16 {
        self.external_port.unwrap_or_else(|| self.listen.port())
    }

    pub fn external_host(&self) -> Option<String> {
        self.external_host.clone()
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct RecordingsConfig {
    #[serde(default = "_default_false")]
    pub enable: bool,

    #[serde(default = "_default_recordings_path")]
    pub path: String,
}

impl Default for RecordingsConfig {
    fn default() -> Self {
        Self {
            enable: false,
            path: _default_recordings_path(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct LogConfig {
    #[serde(default = "_default_retention", with = "humantime_serde")]
    #[schemars(with = "String")]
    pub retention: Duration,

    #[serde(default = "_default_audit_retention", with = "humantime_serde")]
    #[schemars(with = "String")]
    pub audit_retention: Duration,

    #[serde(default)]
    pub send_to: Option<String>,

    #[serde(default)]
    pub format: LogFormat,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            retention: _default_retention(),
            audit_retention: _default_audit_retention(),
            send_to: None,
            format: LogFormat::default(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct WarpgateConfigStore {
    #[serde(default)]
    pub sso_providers: Vec<SsoProviderConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recordings: Option<RecordingsConfig>,

    #[serde(default)]
    pub external_host: Option<String>,

    #[serde(default = "_default_database_url")]
    #[schemars(with = "String")]
    pub database_url: Secret<String>,

    /// Absent unless the deployment issues target credentials from Vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<VaultConfig>,

    #[serde(default)]
    pub ssh: SshConfig,

    #[serde(default)]
    pub http: HttpConfig,

    #[serde(default)]
    pub kubernetes: KubernetesConfig,

    #[serde(default)]
    pub mysql: MySqlConfig,

    #[serde(default)]
    pub postgres: PostgresConfig,

    #[serde(default)]
    pub vnc: VncConfig,

    #[serde(default)]
    pub rdp: RdpConfig,

    #[serde(default)]
    pub log: LogConfig,
}

impl Default for WarpgateConfigStore {
    fn default() -> Self {
        Self {
            sso_providers: vec![],
            recordings: <_>::default(),
            external_host: None,
            database_url: _default_database_url(),
            vault: None,
            ssh: <_>::default(),
            http: <_>::default(),
            kubernetes: <_>::default(),
            mysql: <_>::default(),
            postgres: <_>::default(),
            vnc: <_>::default(),
            rdp: <_>::default(),
            log: <_>::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct WarpgateConfig {
    pub store: WarpgateConfigStore,
}

impl WarpgateConfig {
    pub fn validate(&self) {
        if let Some(ref ext) = self.store.external_host
            && ext.contains(':')
        {
            emit_config_warning(
                "Your `external_host` config option contains a port - it will be ignored. Set the external port via the `http.external_port`, `ssh.external_port` or `mysql.external_port` options.".to_owned()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{SshConfig, WarpgateConfigStore};

    #[test]
    fn keepalive_interval_is_a_humantime_string() {
        let config = serde_json::from_str::<SshConfig>(r#"{"keepalive_interval": "1m"}"#).unwrap();
        assert_eq!(config.keepalive_interval, Some(Duration::from_secs(60)));
        assert!(
            serde_json::to_string(&config)
                .unwrap()
                .contains(r#""keepalive_interval":"1m""#)
        );
    }

    #[test]
    fn default_config_store_omits_recordings() {
        let config = serde_json::to_value(WarpgateConfigStore::default()).unwrap();
        let config = config.as_object().unwrap();

        assert!(!config.contains_key("recordings"));
    }
}

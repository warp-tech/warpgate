use std::collections::HashMap;

use poem_openapi::{Object, Union};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use warpgate_tls::TlsMode;

use super::defaults::*;
use crate::Secret;

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
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Union)]
#[serde(untagged)]
#[oai(discriminator_name = "kind", one_of)]
pub enum SSHTargetAuth {
    #[serde(rename = "password")]
    Password(SshTargetPasswordAuth),
    #[serde(rename = "publickey")]
    PublicKey(SshTargetPublicKeyAuth),
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct SshTargetPasswordAuth {
    pub password: Secret<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object, Default)]
pub struct SshTargetPublicKeyAuth {}

impl Default for SSHTargetAuth {
    fn default() -> Self {
        SSHTargetAuth::PublicKey(SshTargetPublicKeyAuth::default())
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

#[derive(Debug, Deserialize, Serialize, Clone, Object)]
pub struct TargetMySqlOptions {
    #[serde(default = "_default_empty_string")]
    pub host: String,

    #[serde(default = "_default_mysql_port")]
    pub port: u16,

    #[serde(default = "_default_username")]
    pub username: String,

    #[serde(default)]
    pub password: Option<String>,

    #[serde(default)]
    pub tls: Tls,
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
    pub password: Option<String>,

    #[serde(default)]
    pub tls: Tls,

    #[serde(default = "_default_postgres_idle_timeout_str")]
    pub idle_timeout: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Object, Default)]
pub struct TargetWebAdminOptions {}

// ========== RemoteRun Configuration Structs ==========

/// Shell execution sub-mode for RemoteRun
#[derive(Debug, Deserialize, Serialize, Clone, Object)]
pub struct RemoteRunShellOptions {
    /// Command to execute (e.g., "ssh -J user@bastion target@host")
    pub command: String,
    /// Optional jump host for SSH tunneling
    #[serde(default)]
    pub jump_host: Option<String>,
}

/// OpenStack VM spawner sub-mode for RemoteRun
#[derive(Debug, Deserialize, Serialize, Clone, Object)]
pub struct RemoteRunOpenStackOptions {
    /// OpenStack Identity API URL (e.g., "https://openstack.example.com:5000/v3")
    pub api_url: String,
    /// Flavor ID for the VM instance
    pub flavor_id: String,
    /// Image ID for the VM instance
    pub image_id: String,
    /// Network ID for the VM instance
    pub network_id: String,
    /// GitHub username to fetch SSH public keys from
    pub github_username: String,
    /// Timeout in seconds for VM provisioning (default: 300)
    #[serde(default = "_default_remoterun_timeout")]
    pub timeout_seconds: u32,
}

/// Kubernetes ephemeral pod sub-mode for RemoteRun
#[derive(Debug, Deserialize, Serialize, Clone, Object)]
pub struct RemoteRunKubernetesOptions {
    /// Path to kubeconfig file, or empty to use in-cluster config
    #[serde(default)]
    pub kubeconfig: Option<String>,
    /// Kubernetes namespace for the ephemeral pod
    pub namespace: String,
    /// Container image for the pod (e.g., "ceph/ceph:latest")
    pub pod_image: String,
    /// Command to run in the container (default: "/bin/bash")
    #[serde(default = "_default_remoterun_shell_command")]
    pub command: String,
    /// Timeout in seconds for pod creation (default: 300)
    #[serde(default = "_default_remoterun_timeout")]
    pub timeout_seconds: u32,
}

/// Union of all RemoteRun execution modes
#[derive(Debug, Deserialize, Serialize, Clone, Union)]
#[serde(tag = "mode")]
#[oai(discriminator_name = "mode", one_of)]
pub enum TargetRemoteRunOptions {
    #[serde(rename = "shell")]
    Shell(RemoteRunShellOptions),
    #[serde(rename = "openstack")]
    OpenStack(RemoteRunOpenStackOptions),
    #[serde(rename = "kubernetes")]
    Kubernetes(RemoteRunKubernetesOptions),
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
}

#[derive(Debug, Deserialize, Serialize, Clone, Union)]
#[oai(discriminator_name = "kind", one_of)]
pub enum TargetOptions {
    #[serde(rename = "ssh")]
    Ssh(TargetSSHOptions),
    #[serde(rename = "http")]
    Http(TargetHTTPOptions),
    #[serde(rename = "mysql")]
    MySql(TargetMySqlOptions),
    #[serde(rename = "postgres")]
    Postgres(TargetPostgresOptions),
    #[serde(rename = "web_admin")]
    WebAdmin(TargetWebAdminOptions),
    #[serde(rename = "remote_run")]
    RemoteRun(TargetRemoteRunOptions),
}

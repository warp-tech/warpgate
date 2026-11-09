use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use warpgate_common::{MaybeSecretRef, TargetOptions};
use warpgate_db_entities::TargetGroup::BootstrapThemeColor;

pub type DeserializeError = serde_path_to_error::Error<serde_json::Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub enum ApiVersion {
    #[serde(rename = "warpgate/v1")]
    V1,
}

/// One document of a Warpgate resource file
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema, strum::EnumDiscriminants)]
#[serde(tag = "kind")]
#[strum_discriminants(name(Kind), derive(Deserialize, Hash))]
#[allow(clippy::large_enum_variant)]
pub enum Resource {
    Target(Manifest<TargetSpec>),
    TargetGroup(Manifest<TargetGroupSpec>),
    Role(Manifest<RoleSpec>),
    SshClientKey(Manifest<SshClientKeySpec>),
}

impl Resource {
    // Deserialized with `Resource::from_value`: a derived `Deserialize` for an
    // internally tagged enum buffers the content before picking the variant, which
    // drops the path of every error inside it.
    pub fn from_value(value: &Value) -> Result<Self, DeserializeError> {
        #[derive(Deserialize)]
        struct Header {
            kind: Kind,
        }

        let Header { kind } = serde_path_to_error::deserialize(value)?;
        Ok(match kind {
            Kind::Target => {
                let mut value = value.clone();
                let references = value
                    .get_mut("spec")
                    .map(OptionReferences::take)
                    .unwrap_or_default();
                let mut manifest: Manifest<TargetSpec> = serde_path_to_error::deserialize(&value)?;
                manifest.spec.references = references;
                Self::Target(manifest)
            }
            Kind::TargetGroup => Self::TargetGroup(serde_path_to_error::deserialize(value)?),
            Kind::Role => Self::Role(serde_path_to_error::deserialize(value)?),
            Kind::SshClientKey => Self::SshClientKey(serde_path_to_error::deserialize(value)?),
        })
    }

    pub const fn metadata(&self) -> &Metadata {
        match self {
            Self::Target(m) => &m.metadata,
            Self::TargetGroup(m) => &m.metadata,
            Self::Role(m) => &m.metadata,
            Self::SshClientKey(m) => &m.metadata,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[schemars(rename = "{Spec}Manifest")]
pub struct Manifest<Spec> {
    pub api_version: ApiVersion,
    pub metadata: Metadata,
    pub spec: Spec,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub struct Metadata {
    #[schemars(length(min = 1))]
    pub name: String,
    /// Take over a row of the same name that was created by hand. Without
    /// it, such a row is a collision.
    #[serde(default)]
    pub adopt_existing: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub struct TargetSpec {
    #[serde(default)]
    pub description: String,
    /// TargetGroup name
    pub group: Option<String>,
    /// Role names that are allowed to access the target
    #[serde(default)]
    pub roles: Vec<String>,
    pub options: TargetOptions,
    pub rate_limit_bytes_per_second: Option<u32>,
    pub ticket_max_duration_seconds: Option<i64>,
    #[serde(default)]
    pub ticket_requests_disabled: bool,
    #[serde(default)]
    pub ticket_require_approval: bool,
    #[serde(default)]
    pub require_approval: bool,
    pub ticket_max_uses: Option<i16>,
    /// Names written in `options` where the database holds row IDs
    #[serde(skip)]
    pub references: OptionReferences,
}

/// A resource file refers to other resources by name, also inside
/// `TargetOptions`, whose fields for them are row IDs. The names live here
/// instead, and those ID fields stay empty until apply resolves them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OptionReferences {
    /// The SSH target to connect through, `options.ssh.jump_host` in a file
    pub jump_host: Option<String>,
    /// The SSH client key to authenticate with, `options.ssh.auth.key_id` in a file
    pub client_key: Option<String>,
}

impl OptionReferences {
    /// Where each name sits, relative to `spec`
    pub const JUMP_HOST: &str = "/options/ssh/jump_host";
    pub const CLIENT_KEY: &str = "/options/ssh/auth/key_id";

    /// Moves the names out of a target's spec, before it deserializes into
    /// fields that only hold IDs
    fn take(spec: &mut Value) -> Self {
        Self {
            jump_host: take_name(spec, Self::JUMP_HOST),
            client_key: take_name(spec, Self::CLIENT_KEY),
        }
    }

    /// Writes the names back where a file has them, into a serialized spec
    pub fn put(&self, spec: &mut Value) {
        for (pointer, name) in [
            (Self::JUMP_HOST, &self.jump_host),
            (Self::CLIENT_KEY, &self.client_key),
        ] {
            if let (Some(name), Some(slot)) = (name, spec.pointer_mut(pointer)) {
                *slot = Value::String(name.clone());
            }
        }
    }
}

fn take_name(spec: &mut Value, pointer: &str) -> Option<String> {
    let slot = spec.pointer_mut(pointer)?;
    match slot.take() {
        Value::String(name) => Some(name),
        other => {
            *slot = other;
            None
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub struct TargetGroupSpec {
    #[serde(default)]
    pub description: String,
    pub color: Option<BootstrapThemeColor>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub struct RoleSpec {
    #[serde(default)]
    pub description: String,
    /// Grant to every new user
    #[serde(default)]
    pub is_default: bool,
}

/// A key Warpgate authenticates to SSH targets with. `metadata.name` is its label.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub struct SshClientKeySpec {
    /// The private key in OpenSSH or PKCS#8 PEM format, without a passphrase,
    /// or a reference to one
    pub private_key: MaybeSecretRef,
    /// Offer the key to SSH targets that don't name one
    #[serde(default)]
    pub is_default: bool,
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use warpgate_common::{DatabaseTargetAuth, MaybeSecretRef};

    use super::*;

    #[test]
    fn deserializes_by_kind() {
        let resource = Resource::from_value(&json!({
            "apiVersion": "warpgate/v1",
            "kind": "Target",
            "metadata": {"name": "prod-db"},
            "spec": {
                "roles": ["dba"],
                "options": {"postgres": {
                    "host": "db.internal",
                    "auth": {"kind": "password", "password": "secret://vault/kv/db#pw"},
                }},
            },
        }))
        .unwrap();

        let Resource::Target(target) = resource else {
            panic!("{resource:?}");
        };
        assert_eq!(target.metadata.name, "prod-db");
        assert_eq!(target.spec.roles, vec!["dba".to_owned()]);
        let TargetOptions::Postgres(options) = target.spec.options else {
            panic!();
        };
        assert_eq!(options.port, 5432);
        let DatabaseTargetAuth::Password(auth) = options.auth else {
            panic!();
        };
        assert!(matches!(auth.password, MaybeSecretRef::Reference(_)));
    }
}

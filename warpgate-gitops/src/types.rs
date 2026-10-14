use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use warpgate_common::TargetOptions;
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
            Kind::Target => Self::Target(serde_path_to_error::deserialize(value)?),
            Kind::TargetGroup => Self::TargetGroup(serde_path_to_error::deserialize(value)?),
            Kind::Role => Self::Role(serde_path_to_error::deserialize(value)?),
        })
    }

    pub const fn metadata(&self) -> &Metadata {
        match self {
            Self::Target(m) => &m.metadata,
            Self::TargetGroup(m) => &m.metadata,
            Self::Role(m) => &m.metadata,
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
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
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

    #[test]
    fn errors_keep_their_path() {
        let error = |value| Resource::from_value(&value).unwrap_err();

        let e = error(json!({"apiVersion": "warpgate/v1", "kind": "Pod"}));
        assert_eq!(e.path().to_string(), "kind");
        assert!(e.inner().to_string().contains("unknown variant `Pod`"));

        let e = error(json!({"apiVersion": "warpgate/v2", "kind": "Role"}));
        assert_eq!(e.path().to_string(), "apiVersion");

        let e = error(json!({
            "apiVersion": "warpgate/v1",
            "kind": "Target",
            "metadata": {"name": "x"},
            "spec": {"options": {"ssh": {"host": "h", "port": "22"}}},
        }));
        assert_eq!(e.path().to_string(), "spec.options.ssh.port");
    }

    #[test]
    fn serializes_with_kind() {
        let role = Resource::Role(Manifest {
            api_version: ApiVersion::V1,
            metadata: Metadata {
                name: "dba".into(),
                labels: BTreeMap::new(),
            },
            spec: RoleSpec {
                description: String::new(),
                is_default: false,
            },
        });
        assert_eq!(
            serde_json::to_value(&role).unwrap(),
            json!({
                "apiVersion": "warpgate/v1",
                "kind": "Role",
                "metadata": {"name": "dba", "labels": {}},
                "spec": {"description": "", "is_default": false},
            })
        );
        assert_eq!(
            Resource::from_value(&serde_json::to_value(&role).unwrap()).unwrap(),
            role
        );
    }
}

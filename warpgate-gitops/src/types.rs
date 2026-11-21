use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use warpgate_resources::{
    OptionReferences, ResourceKind, RoleSpec, SshClientKeySpec, TargetGroupSpec, TargetSpec,
};

pub type DeserializeError = serde_path_to_error::Error<serde_json::Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub enum ApiVersion {
    #[serde(rename = "warpgate/v1")]
    V1,
}

/// One document of a Warpgate resource file
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(tag = "kind")]
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
            kind: ResourceKind,
        }

        let Header { kind } = serde_path_to_error::deserialize(value)?;
        Ok(match kind {
            ResourceKind::Target => {
                let mut value = value.clone();
                let references = value
                    .get_mut("spec")
                    .map(OptionReferences::take)
                    .unwrap_or_default();
                let mut manifest: Manifest<TargetSpec> = serde_path_to_error::deserialize(&value)?;
                manifest.spec.references = references;
                Self::Target(manifest)
            }
            ResourceKind::TargetGroup => {
                Self::TargetGroup(serde_path_to_error::deserialize(value)?)
            }
            ResourceKind::Role => Self::Role(serde_path_to_error::deserialize(value)?),
            ResourceKind::SshClientKey => {
                Self::SshClientKey(serde_path_to_error::deserialize(value)?)
            }
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

impl From<&Resource> for ResourceKind {
    fn from(resource: &Resource) -> Self {
        match resource {
            Resource::Target(_) => Self::Target,
            Resource::TargetGroup(_) => Self::TargetGroup,
            Resource::Role(_) => Self::Role,
            Resource::SshClientKey(_) => Self::SshClientKey,
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

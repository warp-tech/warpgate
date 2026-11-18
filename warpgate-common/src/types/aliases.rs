use std::borrow::Cow;

use poem_openapi::registry::{MetaSchemaRef, Registry};
use poem_openapi::types::{ParseError, ParseFromJSON, ParseResult, ToJSON, Type};
use poem_openapi::{NewType, Object};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// TODO reuse for other IDs
macro_rules! uuid_newtype {
    ($(#[$attr:meta])* $name:ident) => {
        $(#[$attr])*
        #[derive(
            Debug,
            Clone,
            Copy,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            Serialize,
            Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }

        impl From<$name> for sea_orm::Value {
            fn from(id: $name) -> Self {
                id.0.into()
            }
        }

        impl sea_orm::TryGetable for $name {
            fn try_get_by<I: sea_orm::ColIdx>(
                res: &sea_orm::QueryResult,
                index: I,
            ) -> Result<Self, sea_orm::TryGetError> {
                Uuid::try_get_by(res, index).map(Self)
            }
        }

        impl sea_orm::sea_query::ValueType for $name {
            fn try_from(
                v: sea_orm::Value,
            ) -> Result<Self, sea_orm::sea_query::ValueTypeErr> {
                <Uuid as sea_orm::sea_query::ValueType>::try_from(v).map(Self)
            }

            fn type_name() -> String {
                stringify!($name).to_owned()
            }

            fn array_type() -> sea_orm::sea_query::ArrayType {
                <Uuid as sea_orm::sea_query::ValueType>::array_type()
            }

            fn column_type() -> sea_orm::sea_query::ColumnType {
                <Uuid as sea_orm::sea_query::ValueType>::column_type()
            }
        }

        impl sea_orm::sea_query::Nullable for $name {
            fn null() -> sea_orm::Value {
                <Uuid as sea_orm::sea_query::Nullable>::null()
            }
        }

        impl sea_orm::TryFromU64 for $name {
            fn try_from_u64(n: u64) -> Result<Self, sea_orm::DbErr> {
                <Uuid as sea_orm::TryFromU64>::try_from_u64(n).map(Self)
            }
        }
    };
}

uuid_newtype!(
    #[derive(NewType)]
    UserSessionId
);
uuid_newtype!(
    #[derive(NewType)]
    TargetSessionId
);
uuid_newtype!(
    #[derive(NewType)]
    NodeId
);
uuid_newtype!(ProviderId);

impl ProviderId {
    pub const GITOPS: Self = Self(Uuid::nil());

    pub fn label(self) -> String {
        if self == Self::GITOPS {
            "GitOps".to_owned()
        } else {
            self.to_string()
        }
    }
}

/// A provider as the API returns it: its ID and display name
#[derive(Object)]
#[oai(rename = "Provider")]
struct ProviderRepr {
    id: Uuid,
    label: String,
}

impl Type for ProviderId {
    const IS_REQUIRED: bool = true;
    type RawValueType = Self;
    type RawElementValueType = Self;

    fn name() -> Cow<'static, str> {
        ProviderRepr::name()
    }

    fn schema_ref() -> MetaSchemaRef {
        ProviderRepr::schema_ref()
    }

    fn register(registry: &mut Registry) {
        ProviderRepr::register(registry);
    }

    fn as_raw_value(&self) -> Option<&Self::RawValueType> {
        Some(self)
    }

    fn raw_element_iter<'a>(
        &'a self,
    ) -> Box<dyn Iterator<Item = &'a Self::RawElementValueType> + 'a> {
        Box::new(std::iter::once(self))
    }
}

impl ParseFromJSON for ProviderId {
    fn parse_from_json(value: Option<serde_json::Value>) -> ParseResult<Self> {
        ProviderRepr::parse_from_json(value)
            .map(|provider| Self(provider.id))
            .map_err(|e| ParseError::custom(e.into_message()))
    }
}

impl ToJSON for ProviderId {
    fn to_json(&self) -> Option<serde_json::Value> {
        ProviderRepr {
            id: self.0,
            label: self.label(),
        }
        .to_json()
    }
}

/// Identity of a Warpgate protocol. Used wherever code branches on the
/// protocol (credential policies, auth states) so that a protocol can't be
/// misspelled or silently unmatched; the wire/DB/audit string form is
/// [`Protocol::name`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::EnumIter)]
pub enum Protocol {
    Http,
    Ssh,
    MySql,
    Postgres,
    Kubernetes,
    Vnc,
    Rdp,
}

impl Protocol {
    pub fn all() -> impl Iterator<Item = Self> {
        <Self as strum::IntoEnumIterator>::iter()
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Http => "HTTP",
            Self::Ssh => "SSH",
            Self::MySql => "MySQL",
            Self::Postgres => "PostgreSQL",
            Self::Kubernetes => "Kubernetes",
            Self::Vnc => "VNC",
            Self::Rdp => "RDP",
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

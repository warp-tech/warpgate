use poem_openapi::NewType;
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
            NewType,
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

uuid_newtype!(UserSessionId);
uuid_newtype!(TargetSessionId);
uuid_newtype!(NodeId);

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

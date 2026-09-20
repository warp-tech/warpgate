use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use async_trait::async_trait;
use poem_openapi::registry::{MetaSchemaRef, Registry};
use poem_openapi::types::{ParseError, ParseFromJSON, ToJSON};
use poem_openapi::{Enum, Object, Union};
use sea_orm::prelude::StringLen;
use sea_orm::{DeriveActiveEnum, EnumIter, FromJsonQueryResult};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Secret, StoredSecret, WarpgateError};

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("invalid secret reference '{0}': expected format secret://backend/mount/path#field")]
    InvalidRef(String),
    #[error("secret backend '{backend}' is not configured")]
    BackendNotConfigured { backend: String },
    #[error("secret not found at '{path}'")]
    NotFound { path: String },
    #[error("secret backend name '{0}' is invalid: use letters, digits, '.', '_' or '-'")]
    InvalidBackendName(String),
    #[error("path '{path}' is outside the paths allowed for secret backend '{backend}'")]
    PathNotAllowed { backend: String, path: String },
    #[error("secret backend error: {0}")]
    Backend(String),
}

/// The product behind a backend. Both speak the same API; the distinction is
/// informational.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Enum, EnumIter, DeriveActiveEnum,
)]
#[serde(rename_all = "lowercase")]
#[oai(rename_all = "lowercase")]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum BackendType {
    #[sea_orm(string_value = "vault")]
    Vault,
    #[sea_orm(string_value = "openbao")]
    OpenBao,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Object)]
pub struct VaultTokenAuth {
    /// Blank in responses; blank in an update, keeps the stored token
    pub token: StoredSecret,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Object)]
pub struct VaultAppRoleAuth {
    #[oai(validator(min_length = 1, max_length = 255))]
    pub role_id: String,
    /// Blank in responses; blank in an update, keeps the stored secret ID
    pub secret_id: StoredSecret,
    /// Auth mount; `null` uses `approle`
    #[oai(validator(min_length = 1, max_length = 255))]
    pub mount: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Object)]
pub struct VaultKubernetesAuth {
    #[oai(validator(min_length = 1, max_length = 255))]
    pub role: String,
    /// Auth mount; `null` uses `kubernetes`
    #[oai(validator(min_length = 1, max_length = 255))]
    pub mount: Option<String>,
}

/// How a backend logs in to Vault. Stored as one JSON column with the secret
/// encrypted at rest; the API carries the same shape with the secret blanked
/// (see [`Self::redacted`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Union, FromJsonQueryResult)]
#[serde(tag = "method")]
#[oai(rename = "SecretBackendAuth", discriminator_name = "method", one_of)]
pub enum VaultAuthConfig {
    Token(VaultTokenAuth),
    AppRole(VaultAppRoleAuth),
    Kubernetes(VaultKubernetesAuth),
}

impl VaultAuthConfig {
    /// The login secret; a Kubernetes login presents the pod's service
    /// account token instead and has none.
    pub const fn secret(&self) -> Option<&StoredSecret> {
        match self {
            Self::Token(auth) => Some(&auth.token),
            Self::AppRole(auth) => Some(&auth.secret_id),
            Self::Kubernetes(_) => None,
        }
    }

    pub const fn secret_mut(&mut self) -> Option<&mut StoredSecret> {
        match self {
            Self::Token(auth) => Some(&mut auth.token),
            Self::AppRole(auth) => Some(&mut auth.secret_id),
            Self::Kubernetes(_) => None,
        }
    }

    /// The login with its secret blanked, for API responses
    pub fn redacted(&self) -> Self {
        let mut redacted = self.clone();
        if let Some(secret) = redacted.secret_mut() {
            *secret = StoredSecret::default();
        }
        redacted
    }
}

/// Everything needed to talk to one backend; assembled from its stored row.
#[derive(Debug, Clone)]
pub struct SecretBackendConfig {
    pub name: String,
    pub address: String,
    pub namespace: Option<String>,
    pub auth: VaultAuthConfig,
    pub tls_skip_verify: bool,
    /// KV path prefixes (`mount/path`) references may name; empty allows every
    /// path the backend's credentials can read.
    pub allowed_paths: Vec<String>,
}

pub const REFERENCE_SCHEME: &str = "secret://";

/// `secret://backend/mount/path[#field]`: an entry in a KV v2 engine of one
/// of the configured backends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRef {
    pub backend: String,
    /// The KV v2 engine's mount point
    pub mount: String,
    /// The entry within the mount, without the `data/` segment
    pub path: String,
    /// The entry field holding the value; a reference to the whole entry has none
    pub field: Option<String>,
}

impl SecretRef {
    /// `mount/path`, the form allowed-path prefixes are written in
    pub fn kv_path(&self) -> String {
        format!("{}/{}", self.mount, self.path)
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{REFERENCE_SCHEME}{}/{}/{}",
            self.backend, self.mount, self.path
        )?;
        if let Some(field) = &self.field {
            write!(f, "#{field}")?;
        }
        Ok(())
    }
}

impl FromStr for SecretRef {
    type Err = SecretError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = || SecretError::InvalidRef(s.to_string());
        let rest = s.strip_prefix(REFERENCE_SCHEME).ok_or_else(invalid)?;
        let (backend, rest) = rest.split_once('/').ok_or_else(invalid)?;
        validate_backend_name(backend)?;

        let (kv_path, field) = match rest.split_once('#') {
            Some((p, f)) if !f.is_empty() => (p, Some(f.to_string())),
            Some((p, _)) => (p, None),
            None => (rest, None),
        };
        let (mount, path) = kv_path.split_once('/').ok_or_else(invalid)?;
        if mount.is_empty() || path.is_empty() {
            return Err(invalid());
        }

        Ok(SecretRef {
            backend: backend.to_string(),
            mount: mount.to_string(),
            path: path.to_string(),
            field,
        })
    }
}

/// Something that can turn a [`SecretRef`] into the secret it names: a single
/// backend, or the registry routing to one.
#[async_trait]
pub trait SecretResolver: Send + Sync {
    async fn resolve(&self, reference: &SecretRef) -> Result<Secret<String>, SecretError>;
}

/// A backend name is a path segment of a reference, so it must be unambiguous
/// against the `/` and `#` separators.
pub fn validate_backend_name(name: &str) -> Result<(), SecretError> {
    if !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        Ok(())
    } else {
        Err(SecretError::InvalidBackendName(name.to_string()))
    }
}

/// A stored credential: either the value itself (encrypted at rest) or a
/// reference to a secret backend. Serialized as one string in both JSON and
/// database columns, so a column or field of this type is the single place
/// that decides which of the two a string is.
///
/// The only way to the credential is [`Self::resolve`], which needs a
/// resolver for the reference case, so no code path can use a reference as
/// if it were the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeSecretRef {
    Inline(StoredSecret),
    Reference(SecretRef),
    /// A stored string that starts with the reference scheme but does not
    /// parse. Kept verbatim, never treated as a credential and never
    /// encrypted, so it stays visible and correctable; resolving it fails.
    Malformed(String),
}

impl MaybeSecretRef {
    pub const fn as_reference(&self) -> Option<&SecretRef> {
        match self {
            Self::Reference(r) => Some(r),
            Self::Inline(_) | Self::Malformed(_) => None,
        }
    }

    /// The credential itself: the inline value decrypted, or the referenced secret fetched
    pub async fn resolve(
        &self,
        backend: &dyn SecretResolver,
    ) -> Result<Secret<String>, WarpgateError> {
        match self {
            Self::Inline(v) => Ok(v.reveal()?),
            Self::Reference(r) => Ok(backend.resolve(r).await?),
            Self::Malformed(raw) => Err(SecretError::InvalidRef(raw.clone()).into()),
        }
    }

    /// An already stored value. Unlike [`Self::from_str`], a malformed
    /// reference is kept rather than rejected: the row exists, and failing
    /// its whole read would take every other row down with it.
    fn from_stored(s: String) -> Self {
        Self::from_str(&s).unwrap_or_else(|_| Self::Malformed(s))
    }

    fn as_string(&self) -> String {
        match self {
            Self::Inline(v) => v.stored_value().to_owned(),
            Self::Reference(r) => r.to_string(),
            Self::Malformed(raw) => raw.clone(),
        }
    }
}

impl Default for MaybeSecretRef {
    fn default() -> Self {
        Self::Inline(StoredSecret::default())
    }
}

impl FromStr for MaybeSecretRef {
    type Err = SecretError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with(REFERENCE_SCHEME) {
            SecretRef::from_str(s).map(Self::Reference)
        } else {
            Ok(Self::Inline(StoredSecret::from(s.to_string())))
        }
    }
}

impl From<SecretRef> for MaybeSecretRef {
    fn from(r: SecretRef) -> Self {
        Self::Reference(r)
    }
}

/// Reads stored rows and config files, so it is lenient like `from_stored`;
/// API input goes through the strict [`ParseFromJSON`] instead.
impl<'de> Deserialize<'de> for MaybeSecretRef {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::from_stored(String::deserialize(d)?))
    }
}

impl Serialize for MaybeSecretRef {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.as_string().serialize(s)
    }
}

/// Stores a type in a text column, converting with `$to` on the way in and
/// `$from` on the way out.
macro_rules! text_column {
    ($t:ty, $to:expr, $from:expr) => {
        impl From<$t> for sea_orm::Value {
            fn from(v: $t) -> Self {
                ($to)(&v).into()
            }
        }

        impl sea_orm::TryGetable for $t {
            fn try_get_by<I: sea_orm::ColIdx>(
                res: &sea_orm::QueryResult,
                index: I,
            ) -> Result<Self, sea_orm::TryGetError> {
                let s = String::try_get_by(res, index)?;
                ($from)(s).map_err(|e: SecretError| {
                    sea_orm::TryGetError::DbErr(sea_orm::DbErr::Type(e.to_string()))
                })
            }
        }

        impl sea_orm::sea_query::ValueType for $t {
            fn try_from(v: sea_orm::Value) -> Result<Self, sea_orm::sea_query::ValueTypeErr> {
                let s = <String as sea_orm::sea_query::ValueType>::try_from(v)?;
                ($from)(s).map_err(|_: SecretError| sea_orm::sea_query::ValueTypeErr)
            }

            fn type_name() -> String {
                stringify!($t).to_owned()
            }

            fn array_type() -> sea_orm::sea_query::ArrayType {
                sea_orm::sea_query::ArrayType::String
            }

            fn column_type() -> sea_orm::sea_query::ColumnType {
                sea_orm::sea_query::ColumnType::Text
            }
        }

        impl sea_orm::sea_query::Nullable for $t {
            fn null() -> sea_orm::Value {
                <String as sea_orm::sea_query::Nullable>::null()
            }
        }
    };
}

text_column!(MaybeSecretRef, MaybeSecretRef::as_string, |s: String| Ok(
    MaybeSecretRef::from_stored(s)
));
text_column!(SecretRef, SecretRef::to_string, |s: String| s
    .parse::<SecretRef>());

impl poem_openapi::types::Type for MaybeSecretRef {
    const IS_REQUIRED: bool = true;
    type RawValueType = String;
    type RawElementValueType = String;

    fn name() -> Cow<'static, str> {
        String::name()
    }

    fn schema_ref() -> MetaSchemaRef {
        String::schema_ref()
    }

    fn register(registry: &mut Registry) {
        String::register(registry);
    }

    fn as_raw_value(&self) -> Option<&Self::RawValueType> {
        match self {
            Self::Inline(v) => v.as_raw_value(),
            Self::Reference(_) | Self::Malformed(_) => None,
        }
    }

    fn raw_element_iter<'a>(
        &'a self,
    ) -> Box<dyn Iterator<Item = &'a Self::RawElementValueType> + 'a> {
        Box::new(self.as_raw_value().into_iter())
    }

    fn is_empty(&self) -> bool {
        match self {
            Self::Inline(v) => poem_openapi::types::Type::is_empty(v),
            Self::Reference(_) | Self::Malformed(_) => false,
        }
    }

    fn is_none(&self) -> bool {
        false
    }
}

impl ParseFromJSON for MaybeSecretRef {
    fn parse_from_json(value: Option<serde_json::Value>) -> poem_openapi::types::ParseResult<Self> {
        let s = String::parse_from_json(value).map_err(|e| ParseError::custom(e.into_message()))?;
        MaybeSecretRef::from_str(&s).map_err(|e| ParseError::custom(e.to_string()))
    }
}

impl ToJSON for MaybeSecretRef {
    fn to_json(&self) -> Option<serde_json::Value> {
        Some(serde_json::Value::String(self.as_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REFERENCE: &str = "secret://vault-prod/secret/db#password";

    #[test]
    fn parses_reference_without_field() {
        let r: SecretRef = "secret://vault-prod/secret/myapp".parse().unwrap();
        assert_eq!(r.field, None);
        assert_eq!(r.mount, "secret");
        assert_eq!(r.path, "myapp");
    }

    #[test]
    fn parses_backend_mount_path_and_field() {
        let r: SecretRef = "secret://vault-prod/kv/prod/myapp#password"
            .parse()
            .unwrap();
        assert_eq!(r.backend, "vault-prod");
        assert_eq!(r.mount, "kv");
        assert_eq!(r.path, "prod/myapp");
        assert_eq!(r.kv_path(), "kv/prod/myapp");
        assert_eq!(r.field, Some("password".to_string()));
    }

    #[test]
    fn trailing_hash_produces_no_field() {
        let r: SecretRef = "secret://vault-prod/secret/myapp#".parse().unwrap();
        assert_eq!(r.field, None);
        assert_eq!(r.kv_path(), "secret/myapp");
    }

    #[test]
    fn malformed_references_are_rejected() {
        for raw in [
            "vault-prod/secret/myapp",
            "://vault-prod/secret/myapp",
            "secret://vault-prod",
            "secret://vault-prod/",
            "secret://vault-prod/secret",
            "secret://vault-prod/secret/",
            "secret://vault-prod//myapp",
            "vault://vault-prod/secret/myapp",
        ] {
            assert!(
                matches!(SecretRef::from_str(raw), Err(SecretError::InvalidRef(_))),
                "{raw}"
            );
        }
    }

    #[test]
    fn backend_name_with_separators_is_invalid() {
        for name in ["a#b", "a:b", "a b", "a/b", ""] {
            assert!(matches!(
                validate_backend_name(name),
                Err(SecretError::InvalidBackendName(_))
            ));
        }
        assert!(validate_backend_name("vault-prod.eu_1").is_ok());
        assert!(matches!(
            SecretRef::from_str("secret://a:b/secret/x"),
            Err(SecretError::InvalidBackendName(_))
        ));
        assert!(matches!(
            SecretRef::from_str("secret:///secret/myapp"),
            Err(SecretError::InvalidBackendName(_))
        ));
    }

    #[test]
    fn display_round_trips() {
        for raw in ["secret://vault-prod/secret/myapp", REFERENCE] {
            assert_eq!(SecretRef::from_str(raw).unwrap().to_string(), raw);
        }
    }

    #[test]
    fn plain_string_is_inline() {
        let v = MaybeSecretRef::from_str("hunter2").unwrap();
        assert_eq!(v.as_reference(), None);
        assert!(matches!(v, MaybeSecretRef::Inline(_)));
    }

    #[test]
    fn reference_scheme_is_a_reference() {
        let v = MaybeSecretRef::from_str(REFERENCE).unwrap();
        assert_eq!(v.as_reference().unwrap().to_string(), REFERENCE);
        assert!(matches!(
            MaybeSecretRef::from_str("secret://"),
            Err(SecretError::InvalidRef(_))
        ));
    }

    #[tokio::test]
    async fn stored_malformed_reference_is_kept_and_does_not_resolve() {
        let raw = "secret://broken";
        let v = MaybeSecretRef::from_stored(raw.to_owned());
        assert_eq!(v, MaybeSecretRef::Malformed(raw.to_owned()));
        assert_eq!(v.as_string(), raw);
        assert_eq!(
            serde_json::from_str::<MaybeSecretRef>(&format!("\"{raw}\"")).unwrap(),
            v
        );
        assert!(matches!(
            v.resolve(&StubBackend).await,
            Err(WarpgateError::SecretBackend(SecretError::InvalidRef(_)))
        ));
    }

    #[tokio::test]
    async fn default_is_empty_inline() {
        let v = MaybeSecretRef::default();
        assert_eq!(v.resolve(&NoBackend).await.unwrap().expose_secret(), "");
    }

    #[test]
    fn serializes_as_the_plain_string() {
        for raw in ["hunter2", REFERENCE] {
            let v = MaybeSecretRef::from_str(raw).unwrap();
            assert_eq!(serde_json::to_string(&v).unwrap(), format!("\"{raw}\""));
            let back: MaybeSecretRef = serde_json::from_str(&format!("\"{raw}\"")).unwrap();
            assert_eq!(back, v);
            let value: sea_orm::Value = v.clone().into();
            assert_eq!(value, sea_orm::Value::from(raw));
        }
    }

    struct StubBackend;

    #[async_trait]
    impl SecretResolver for StubBackend {
        async fn resolve(&self, reference: &SecretRef) -> Result<Secret<String>, SecretError> {
            Ok(Secret::new(format!("resolved:{reference}")))
        }
    }

    struct NoBackend;

    #[async_trait]
    impl SecretResolver for NoBackend {
        async fn resolve(&self, reference: &SecretRef) -> Result<Secret<String>, SecretError> {
            Err(SecretError::BackendNotConfigured {
                backend: reference.backend.clone(),
            })
        }
    }

    #[tokio::test]
    async fn resolve_inline_returns_value_without_touching_backend() {
        let v = MaybeSecretRef::from_str("hunter2").unwrap();
        assert_eq!(
            v.resolve(&NoBackend).await.unwrap().expose_secret(),
            "hunter2"
        );
    }

    #[tokio::test]
    async fn resolve_reference_forwards_to_backend() {
        let v = MaybeSecretRef::from_str(REFERENCE).unwrap();
        assert_eq!(
            v.resolve(&StubBackend).await.unwrap().expose_secret(),
            &format!("resolved:{REFERENCE}")
        );
        assert!(matches!(
            v.resolve(&NoBackend).await,
            Err(WarpgateError::SecretBackend(
                SecretError::BackendNotConfigured { .. }
            ))
        ));
    }
}

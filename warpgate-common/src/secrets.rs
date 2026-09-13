use std::borrow::Cow;
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use async_trait::async_trait;
use poem_openapi::Enum;
use poem_openapi::registry::{MetaSchemaRef, Registry};
use poem_openapi::types::{ParseError, ParseFromJSON, ToJSON};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Secret, StoredSecret, WarpgateError};

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("invalid secret reference '{0}': expected format scheme://backend/path#field")]
    InvalidRef(String),
    #[error("secret backend '{backend}' is not configured")]
    BackendNotConfigured { backend: String },
    #[error("secret not found at '{path}'")]
    NotFound { path: String },
    #[error("secret backend name '{0}' is invalid: use letters, digits, '.', '_' or '-'")]
    InvalidBackendName(String),
    #[error("path '{path}' is outside the paths allowed for secret backend '{backend}'")]
    PathNotAllowed { backend: String, path: String },
    #[error("secret reference '{0}' was used before being resolved")]
    Unresolved(String),
    #[error("secret backend error: {0}")]
    Backend(String),
}

/// The kind of server behind a backend; also the scheme of references to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Enum)]
#[serde(rename_all = "lowercase")]
#[oai(rename_all = "lowercase")]
pub enum BackendType {
    Vault,
    OpenBao,
}

impl BackendType {
    pub const ALL: [Self; 2] = [Self::Vault, Self::OpenBao];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Vault => "vault",
            Self::OpenBao => "openbao",
        }
    }
}

impl FromStr for BackendType {
    type Err = SecretError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|t| t.as_str() == s)
            .ok_or_else(|| SecretError::Backend(format!("unknown backend type '{s}'")))
    }
}

impl fmt::Display for BackendType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Enum)]
#[serde(rename_all = "snake_case")]
#[oai(rename_all = "snake_case")]
pub enum VaultAuthMethod {
    Token,
    AppRole,
    Kubernetes,
}

impl VaultAuthMethod {
    pub const ALL: [Self; 3] = [Self::Token, Self::AppRole, Self::Kubernetes];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::AppRole => "app_role",
            Self::Kubernetes => "kubernetes",
        }
    }

    /// The Vault auth mount the method logs in at unless overridden.
    pub const fn default_mount(self) -> &'static str {
        match self {
            Self::Token => "",
            Self::AppRole => "approle",
            Self::Kubernetes => "kubernetes",
        }
    }
}

impl FromStr for VaultAuthMethod {
    type Err = SecretError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|m| m.as_str() == s)
            .ok_or_else(|| SecretError::Backend(format!("unknown auth method '{s}'")))
    }
}

pub const DEFAULT_KUBERNETES_JWT_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

#[derive(Debug, Clone)]
pub enum VaultAuthConfig {
    Token {
        token: Secret<String>,
    },
    AppRole {
        role_id: String,
        secret_id: Secret<String>,
        mount: String,
    },
    Kubernetes {
        role: String,
        jwt_path: PathBuf,
        mount: String,
    },
}

#[derive(Debug, Clone, Default)]
pub struct VaultTlsConfig {
    pub skip_verify: bool,
}

/// Everything needed to talk to one backend; assembled from its stored row.
#[derive(Debug, Clone)]
pub struct SecretBackendConfig {
    pub name: String,
    pub backend_type: BackendType,
    pub address: String,
    pub namespace: Option<String>,
    pub auth: VaultAuthConfig,
    pub tls: VaultTlsConfig,
    /// KV path prefixes (`mount/path`) references may name; empty allows every
    /// path the backend's credentials can read.
    pub allowed_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRef {
    pub scheme: BackendType,
    pub backend: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}/{}", self.scheme, self.backend, self.path)?;
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
        let (scheme, after_scheme) = s.split_once("://").ok_or_else(invalid)?;
        let scheme = BackendType::from_str(scheme).map_err(|_| invalid())?;

        let (backend, path_and_field) = after_scheme.split_once('/').ok_or_else(invalid)?;
        validate_backend_name(backend)?;

        let (path, field) = match path_and_field.split_once('#') {
            Some((p, f)) if !f.is_empty() => (p, Some(f.to_string())),
            Some((p, _)) => (p, None),
            None => (path_and_field, None),
        };
        if path.is_empty() {
            return Err(invalid());
        }

        Ok(SecretRef {
            scheme,
            backend: backend.to_string(),
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

    async fn health(&self) -> Result<(), SecretError>;
}

/// Whether a stored credential string names a secret in a backend rather than
/// holding the (possibly encrypted) value itself.
fn is_secret_reference(s: &str) -> bool {
    BackendType::ALL.iter().any(|scheme| {
        s.strip_prefix(scheme.as_str())
            .is_some_and(|rest| rest.starts_with("://"))
    })
}

/// A backend name is a path segment of a reference, so it must be unambiguous
/// against the `/`, `#` and `://` separators.
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeSecretRef {
    Inline(StoredSecret),
    Reference(SecretRef),
}

impl MaybeSecretRef {
    pub const fn as_reference(&self) -> Option<&SecretRef> {
        match self {
            Self::Inline(_) => None,
            Self::Reference(r) => Some(r),
        }
    }

    /// The decrypted inline value. A reference has to be resolved first (see
    /// [`Self::resolve`]); using one here is a programming error, not a
    /// configuration one, and fails loudly.
    pub fn reveal(&self) -> Result<Secret<String>, WarpgateError> {
        match self {
            Self::Inline(v) => Ok(v.reveal()?),
            Self::Reference(r) => Err(SecretError::Unresolved(r.to_string()).into()),
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
        }
    }

    /// A column value. A string that starts like a reference but does not parse as
    /// one is kept as an inline value: it can't name a secret, and failing the
    /// whole query would take every other row down with it.
    fn from_stored(s: String) -> Self {
        Self::from_str(&s).unwrap_or_else(|_| Self::Inline(StoredSecret::from(s)))
    }

    fn as_string(&self) -> String {
        match self {
            Self::Inline(v) => v.stored_value().to_owned(),
            Self::Reference(r) => r.to_string(),
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
        if is_secret_reference(s) {
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

impl<'de> Deserialize<'de> for MaybeSecretRef {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        MaybeSecretRef::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for MaybeSecretRef {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Inline(v) => v.serialize(s),
            Self::Reference(r) => r.to_string().serialize(s),
        }
    }
}

impl From<MaybeSecretRef> for sea_orm::Value {
    fn from(v: MaybeSecretRef) -> Self {
        v.as_string().into()
    }
}

impl sea_orm::TryGetable for MaybeSecretRef {
    fn try_get_by<I: sea_orm::ColIdx>(
        res: &sea_orm::QueryResult,
        index: I,
    ) -> Result<Self, sea_orm::TryGetError> {
        let s = String::try_get_by(res, index)?;
        Ok(Self::from_stored(s))
    }
}

impl sea_orm::sea_query::ValueType for MaybeSecretRef {
    fn try_from(v: sea_orm::Value) -> Result<Self, sea_orm::sea_query::ValueTypeErr> {
        let s = <String as sea_orm::sea_query::ValueType>::try_from(v)?;
        Ok(Self::from_stored(s))
    }

    fn type_name() -> String {
        "MaybeSecretRef".to_owned()
    }

    fn array_type() -> sea_orm::sea_query::ArrayType {
        sea_orm::sea_query::ArrayType::String
    }

    fn column_type() -> sea_orm::sea_query::ColumnType {
        sea_orm::sea_query::ColumnType::Text
    }
}

impl sea_orm::sea_query::Nullable for MaybeSecretRef {
    fn null() -> sea_orm::Value {
        <String as sea_orm::sea_query::Nullable>::null()
    }
}

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
            Self::Reference(_) => None,
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
            Self::Reference(_) => false,
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

    const REFERENCE: &str = "vault://vault-prod/secret/db#password";

    #[test]
    fn parses_reference_without_field() {
        let r: SecretRef = "vault://vault-prod/secret/myapp".parse().unwrap();
        assert_eq!(r.field, None);
        assert_eq!(r.scheme, BackendType::Vault);
    }

    #[test]
    fn parses_scheme_backend_path_and_field() {
        let r: SecretRef = "openbao://vault-prod/secret/prod/myapp#password"
            .parse()
            .unwrap();
        assert_eq!(r.scheme, BackendType::OpenBao);
        assert_eq!(r.backend, "vault-prod");
        assert_eq!(r.path, "secret/prod/myapp");
        assert_eq!(r.field, Some("password".to_string()));
    }

    #[test]
    fn trailing_hash_produces_no_field() {
        let r: SecretRef = "vault://vault-prod/secret/myapp#".parse().unwrap();
        assert_eq!(r.field, None);
        assert_eq!(r.path, "secret/myapp");
    }

    #[test]
    fn malformed_references_are_rejected() {
        for raw in [
            "vault-prod/secret/myapp",
            "://vault-prod/secret/myapp",
            "vault://vault-prod",
            "vault://vault-prod/",
            "http://vault-prod/secret/myapp",
            "valut://vault-prod/secret/myapp",
        ] {
            assert!(
                matches!(SecretRef::from_str(raw), Err(SecretError::InvalidRef(_))),
                "{raw}"
            );
        }
        assert!(!is_secret_reference("http://vault-prod/secret/myapp"));
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
            SecretRef::from_str("vault://a:b/secret/x"),
            Err(SecretError::InvalidBackendName(_))
        ));
        assert!(matches!(
            SecretRef::from_str("vault:///secret/myapp"),
            Err(SecretError::InvalidBackendName(_))
        ));
    }

    #[test]
    fn display_round_trips() {
        for raw in ["vault://vault-prod/secret/myapp", REFERENCE] {
            assert_eq!(SecretRef::from_str(raw).unwrap().to_string(), raw);
        }
    }

    #[test]
    fn plain_string_is_inline() {
        let v = MaybeSecretRef::from_str("hunter2").unwrap();
        assert_eq!(v.as_reference(), None);
        assert_eq!(v.reveal().unwrap().expose_secret(), "hunter2");
    }

    #[test]
    fn reference_schemes_are_references() {
        for raw in [REFERENCE, "openbao://b/p"] {
            let v = MaybeSecretRef::from_str(raw).unwrap();
            assert_eq!(v.as_reference().unwrap().to_string(), raw);
            assert!(matches!(
                v.reveal(),
                Err(WarpgateError::SecretBackend(SecretError::Unresolved(_)))
            ));
        }
        assert!(matches!(
            MaybeSecretRef::from_str("vault://"),
            Err(SecretError::InvalidRef(_))
        ));
    }

    #[test]
    fn default_is_empty_inline() {
        let v = MaybeSecretRef::default();
        assert_eq!(v.reveal().unwrap().expose_secret(), "");
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

        async fn health(&self) -> Result<(), SecretError> {
            Ok(())
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

        async fn health(&self) -> Result<(), SecretError> {
            Ok(())
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

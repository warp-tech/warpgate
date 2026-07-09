use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use poem_openapi::registry::{MetaSchemaRef, Registry};
use poem_openapi::types::{ParseError, ParseFromJSON, ToJSON};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::Secret;

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("invalid secret reference '{0}': expected format scheme://path or scheme://path#field")]
    InvalidRef(String),
    #[error(
        "secret backend '{backend}' is not configured; add it under `secrets.backends` in warpgate.yaml"
    )]
    BackendNotConfigured { backend: String },
    #[error("secret not found at '{path}'")]
    NotFound { path: String },
    #[error("this backend does not support write-back")]
    StoreNotSupported,
    #[error("secret backend error: {0}")]
    Backend(String),
}

pub struct SecretValue(String);

impl SecretValue {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<secret>")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRef {
    pub scheme: String,
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
        let (scheme, after_scheme) = s
            .split_once("://")
            .ok_or_else(|| SecretError::InvalidRef(s.to_string()))?;
        if scheme.is_empty() || after_scheme.is_empty() {
            return Err(SecretError::InvalidRef(s.to_string()));
        }

        let (backend, path_and_field) = after_scheme
            .split_once('/')
            .ok_or_else(|| SecretError::InvalidRef(s.to_string()))?;
        if backend.is_empty() {
            return Err(SecretError::InvalidRef(s.to_string()));
        }

        let (path, field) = if let Some((p, f)) = path_and_field.split_once('#') {
            if f.is_empty() {
                (p.to_string(), None)
            } else {
                (p.to_string(), Some(f.to_string()))
            }
        } else {
            (path_and_field.to_string(), None)
        };

        Ok(SecretRef {
            scheme: scheme.to_string(),
            backend: backend.to_string(),
            path,
            field,
        })
    }
}

#[async_trait]
pub trait SecretBackend: Send + Sync {

    async fn resolve(&self, reference: &SecretRef) -> Result<SecretValue, SecretError>;

    async fn store(
        &self,
        reference: &SecretRef,
        value: &SecretValue,
    ) -> Result<(), SecretError> {
        let _ = (reference, value);
        Err(SecretError::StoreNotSupported)
    }

    async fn health(&self) -> Result<(), SecretError>;

    async fn health_for(&self, _name: &str) -> Result<(), SecretError> {
        self.health().await
    }

    async fn reload(&self, _config: &crate::SecretsConfig) {}
}

pub type SecretBackendRef = Arc<dyn SecretBackend>;


pub struct DbSecretBackend;

#[async_trait]
impl SecretBackend for DbSecretBackend {
    async fn resolve(&self, reference: &SecretRef) -> Result<SecretValue, SecretError> {
        Err(SecretError::BackendNotConfigured {
            backend: reference.backend.clone(),
        })
    }

    async fn health(&self) -> Result<(), SecretError> {
        Ok(())
    }
}

const REFERENCE_SCHEMES: &[&str] = &["vault://", "openbao://"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeSecretRef {
    Inline(Secret<String>),
    Reference(SecretRef),
}

impl MaybeSecretRef {

    pub fn as_reference(&self) -> Option<&SecretRef> {
        match self {
            Self::Inline(_) => None,
            Self::Reference(r) => Some(r),
        }
    }

    pub async fn resolve(&self, backend: &dyn SecretBackend) -> Result<Secret<String>, SecretError> {
        match self {
            Self::Inline(v) => Ok(v.clone()),
            Self::Reference(r) => backend
                .resolve(r)
                .await
                .map(|v| Secret::new(v.expose().to_string())),
        }
    }
}

impl Default for MaybeSecretRef {
    fn default() -> Self {
        Self::Inline(Secret::new(String::new()))
    }
}

impl FromStr for MaybeSecretRef {
    type Err = SecretError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if REFERENCE_SCHEMES.iter().any(|prefix| s.starts_with(prefix)) {
            SecretRef::from_str(s).map(Self::Reference)
        } else {
            Ok(Self::Inline(Secret::new(s.to_string())))
        }
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
            Self::Inline(v) => Some(v.expose_secret()),
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
            Self::Inline(v) => v.expose_secret().is_empty(),
            Self::Reference(_) => false,
        }
    }

    fn is_none(&self) -> bool {
        false
    }
}

impl ParseFromJSON for MaybeSecretRef {
    fn parse_from_json(value: Option<serde_json::Value>) -> poem_openapi::types::ParseResult<Self> {
        let s = String::parse_from_json(value)
            .map_err(|e| ParseError::custom(e.into_message()))?;
        MaybeSecretRef::from_str(&s).map_err(|e| ParseError::custom(e.to_string()))
    }
}

impl ToJSON for MaybeSecretRef {
    fn to_json(&self) -> Option<serde_json::Value> {
        match self {
            Self::Inline(v) => Some(serde_json::Value::String(v.expose_secret().clone())),
            Self::Reference(r) => Some(serde_json::Value::String(r.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_reference_without_field() {
        let r: SecretRef = "vault://vault-prod/secret/myapp".parse().unwrap();
        assert_eq!(r.field, None);
    }

    #[test]
    fn parses_reference_with_field() {
        let r: SecretRef = "vault://vault-prod/secret/myapp#password".parse().unwrap();
        assert_eq!(r.field, Some("password".to_string()));
    }

    #[test]
    fn trailing_hash_produces_no_field() {
        let r: SecretRef = "vault://vault-prod/secret/myapp#".parse().unwrap();
        assert_eq!(r.field, None);
        assert_eq!(r.path, "secret/myapp");
    }

    #[test]
    fn parses_scheme_backend_and_path() {
        let r: SecretRef = "openbao://vault-prod/secret/prod/myapp#password"
            .parse()
            .unwrap();
        assert_eq!(r.scheme, "openbao");
        assert_eq!(r.backend, "vault-prod");
        assert_eq!(r.path, "secret/prod/myapp");
        assert_eq!(r.field, Some("password".to_string()));
    }

    #[test]
    fn missing_scheme_separator_is_invalid() {
        let err = SecretRef::from_str("vault-prod/secret/myapp").unwrap_err();
        assert!(matches!(err, SecretError::InvalidRef(_)));
    }

    #[test]
    fn empty_scheme_is_invalid() {
        let err = SecretRef::from_str("://vault-prod/secret/myapp").unwrap_err();
        assert!(matches!(err, SecretError::InvalidRef(_)));
    }

    #[test]
    fn missing_path_separator_is_invalid() {
        // no '/' after the backend name, so backend/path can't be split
        let err = SecretRef::from_str("vault://vault-prod").unwrap_err();
        assert!(matches!(err, SecretError::InvalidRef(_)));
    }

    #[test]
    fn empty_backend_name_is_invalid() {
        let err = SecretRef::from_str("vault:///secret/myapp").unwrap_err();
        assert!(matches!(err, SecretError::InvalidRef(_)));
    }

    #[test]
    fn empty_field_after_hash_is_none_not_empty_string() {
        let r: SecretRef = "vault://vault-prod/secret/myapp#".parse().unwrap();
        assert_ne!(r.field, Some(String::new()));
    }

    #[test]
    fn display_round_trips_without_field() {
        let r: SecretRef = "vault://vault-prod/secret/myapp".parse().unwrap();
        assert_eq!(r.to_string(), "vault://vault-prod/secret/myapp");
    }

    #[test]
    fn display_round_trips_with_field() {
        let r: SecretRef = "vault://vault-prod/secret/myapp#password".parse().unwrap();
        assert_eq!(r.to_string(), "vault://vault-prod/secret/myapp#password");
    }

    #[test]
    fn maybe_secret_ref_plain_string_is_inline() {
        let v = MaybeSecretRef::from_str("hunter2").unwrap();
        match &v {
            MaybeSecretRef::Inline(s) => assert_eq!(s.expose_secret(), "hunter2"),
            MaybeSecretRef::Reference(_) => panic!("expected Inline"),
        }
        assert_eq!(v.as_reference(), None);
    }

    #[test]
    fn maybe_secret_ref_vault_prefix_is_reference() {
        let v = MaybeSecretRef::from_str("vault://vault-prod/secret/db#password").unwrap();
        assert!(matches!(v, MaybeSecretRef::Reference(_)));
        assert_eq!(
            v.as_reference().unwrap().to_string(),
            "vault://vault-prod/secret/db#password"
        );
    }

    #[test]
    fn maybe_secret_ref_openbao_prefix_is_reference() {
        let v = MaybeSecretRef::from_str("openbao://b/p").unwrap();
        assert!(matches!(v, MaybeSecretRef::Reference(_)));
    }

    #[test]
    fn maybe_secret_ref_malformed_reference_prefix_errors() {
        // starts with a reference scheme but is not a well-formed SecretRef
        let err = MaybeSecretRef::from_str("vault://").unwrap_err();
        assert!(matches!(err, SecretError::InvalidRef(_)));
    }

    #[test]
    fn maybe_secret_ref_default_is_empty_inline() {
        let v = MaybeSecretRef::default();
        match v {
            MaybeSecretRef::Inline(s) => assert_eq!(s.expose_secret(), ""),
            MaybeSecretRef::Reference(_) => panic!("expected Inline"),
        }
    }

    #[test]
    fn maybe_secret_ref_inline_serializes_as_plain_string() {
        let v = MaybeSecretRef::Inline(Secret::new("hunter2".to_string()));
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, "\"hunter2\"");
    }

    #[test]
    fn maybe_secret_ref_reference_serializes_as_uri_string() {
        let v = MaybeSecretRef::from_str("vault://vault-prod/secret/db#password").unwrap();
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, "\"vault://vault-prod/secret/db#password\"");
    }

    #[test]
    fn maybe_secret_ref_deserialize_round_trips() {
        for raw in ["hunter2", "vault://vault-prod/secret/db#password"] {
            let json = serde_json::to_string(raw).unwrap();
            let v: MaybeSecretRef = serde_json::from_str(&json).unwrap();
            let round_tripped = match &v {
                MaybeSecretRef::Inline(s) => s.expose_secret().clone(),
                MaybeSecretRef::Reference(r) => r.to_string(),
            };
            assert_eq!(round_tripped, raw);
        }
    }

    struct StubBackend;

    #[async_trait]
    impl SecretBackend for StubBackend {
        async fn resolve(&self, reference: &SecretRef) -> Result<SecretValue, SecretError> {
            Ok(SecretValue::new(format!("resolved:{reference}")))
        }

        async fn health(&self) -> Result<(), SecretError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn resolve_inline_returns_value_without_touching_backend() {
        let v = MaybeSecretRef::from_str("hunter2").unwrap();
        let resolved = v.resolve(&DbSecretBackend).await.unwrap();
        assert_eq!(resolved.expose_secret(), "hunter2");
    }

    #[tokio::test]
    async fn resolve_reference_forwards_to_backend() {
        let v = MaybeSecretRef::from_str("vault://vault-prod/secret/db#password").unwrap();
        let resolved = v.resolve(&StubBackend).await.unwrap();
        assert_eq!(
            resolved.expose_secret(),
            "resolved:vault://vault-prod/secret/db#password"
        );
    }

    #[tokio::test]
    async fn resolve_reference_against_unconfigured_backend_errors() {
        let v = MaybeSecretRef::from_str("vault://vault-prod/secret/db#password").unwrap();
        let err = v.resolve(&DbSecretBackend).await.unwrap_err();
        assert!(matches!(err, SecretError::BackendNotConfigured { backend } if backend == "vault-prod"));
    }

    #[tokio::test]
    async fn db_secret_backend_health_is_always_ok() {
        assert!(DbSecretBackend.health().await.is_ok());
    }

    #[tokio::test]
    async fn db_secret_backend_health_for_delegates_to_health() {
        // default health_for() implementation ignores the name and delegates to health()
        assert!(DbSecretBackend.health_for("anything").await.is_ok());
    }

    #[test]
    fn secret_value_debug_is_redacted() {
        let v = SecretValue::new("hunter2");
        assert_eq!(format!("{v:?}"), "<secret>");
    }

    #[test]
    fn secret_value_expose_returns_plaintext() {
        let v = SecretValue::new("hunter2");
        assert_eq!(v.expose(), "hunter2");
    }
}

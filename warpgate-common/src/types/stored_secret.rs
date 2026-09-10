use std::borrow::Cow;
use std::fmt::Debug;

use delegate::delegate;
use poem_openapi::registry::{MetaSchemaRef, Registry};
use poem_openapi::types::{ParseFromJSON, ToJSON};
use serde::{Deserialize, Serialize};

use crate::Secret;
use crate::encryption::{EncryptionError, idempotent_maybe_decrypt};

/// A wrapper for a (maybe) encrypted credential
#[derive(PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StoredSecret(Secret<String>);

impl StoredSecret {
    /// Wraps a value in whatever form it already has.
    /// Encryption happens when saving, not here
    pub const fn new(value: Secret<String>) -> Self {
        Self(value)
    }

    /// Decrypted credential value
    pub fn reveal(&self) -> Result<Secret<String>, EncryptionError> {
        idempotent_maybe_decrypt(self.0.expose_secret()).map(Secret::new)
    }
}

impl Default for StoredSecret {
    fn default() -> Self {
        Self::new(Secret::new(String::new()))
    }
}

impl From<String> for StoredSecret {
    fn from(v: String) -> Self {
        Self::new(Secret::new(v))
    }
}

impl Debug for StoredSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<secret>")
    }
}

impl poem_openapi::types::Type for StoredSecret {
    const IS_REQUIRED: bool = <Secret<String> as poem_openapi::types::Type>::IS_REQUIRED;
    type RawValueType = <Secret<String> as poem_openapi::types::Type>::RawValueType;
    type RawElementValueType = <Secret<String> as poem_openapi::types::Type>::RawElementValueType;

    fn name() -> Cow<'static, str> {
        Secret::<String>::name()
    }
    fn schema_ref() -> MetaSchemaRef {
        Secret::<String>::schema_ref()
    }
    fn register(registry: &mut Registry) {
        Secret::<String>::register(registry);
    }

    delegate! {
        to self.0 {
            fn as_raw_value(&self) -> Option<&Self::RawValueType>;
            fn raw_element_iter(
                &'_ self,
            ) -> Box<dyn Iterator<Item = &'_ Self::RawElementValueType> + '_>;
            fn is_empty(&self) -> bool;
            fn is_none(&self) -> bool;
        }
    }
}

impl ParseFromJSON for StoredSecret {
    fn parse_from_json(value: Option<serde_json::Value>) -> poem_openapi::types::ParseResult<Self> {
        Secret::<String>::parse_from_json(value)
            .map(Self::new)
            .map_err(|e| poem_openapi::types::ParseError::custom(e.into_message()))
    }
}

impl ToJSON for StoredSecret {
    fn to_json(&self) -> Option<serde_json::Value> {
        self.0.to_json()
    }
}

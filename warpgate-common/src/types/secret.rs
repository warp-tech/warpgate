use std::borrow::Cow;
use std::fmt::Debug;

use bytes::Bytes;
use data_encoding::HEXLOWER;
use delegate::delegate;
use poem_openapi::registry::{MetaSchemaRef, Registry};
use poem_openapi::types::{ParseError, ParseFromJSON, ToJSON};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::helpers::rng::get_crypto_rng;

#[derive(PartialEq, Eq, Clone)]
pub struct Secret<T>(T);

impl Secret<String> {
    pub fn random() -> Self {
        Secret::new(HEXLOWER.encode(&Bytes::from_iter(get_crypto_rng().gen::<[u8; 32]>())))
    }
}

impl<T> Secret<T> {
    pub const fn new(v: T) -> Self {
        Self(v)
    }

    pub fn expose_secret(&self) -> &T {
        &self.0
    }
}

impl<T> From<T> for Secret<T> {
    fn from(v: T) -> Self {
        Self::new(v)
    }
}

impl<'de, T> Deserialize<'de> for Secret<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = Deserialize::deserialize::<D>(deserializer)?;
        Ok(Self::new(v))
    }
}

impl<T> Serialize for Secret<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<T> Debug for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<secret>")
    }
}

impl<T: poem_openapi::types::Type> poem_openapi::types::Type for Secret<T> {
    const IS_REQUIRED: bool = T::IS_REQUIRED;
    type RawValueType = T::RawValueType;
    type RawElementValueType = T::RawElementValueType;

    fn name() -> Cow<'static, str> {
        T::name()
    }
    fn schema_ref() -> MetaSchemaRef {
        T::schema_ref()
    }
    fn register(registry: &mut Registry) {
        T::register(registry)
    }

    delegate! {
        to self.0 {
            fn as_raw_value(&self) -> Option<&Self::RawValueType>;
            fn raw_element_iter<'a>(
                &'a self,
            ) -> Box<dyn Iterator<Item = &'a Self::RawElementValueType> + 'a>;
            fn is_empty(&self) -> bool;
            fn is_none(&self) -> bool;
        }
    }
}

impl<T: ParseFromJSON> ParseFromJSON for Secret<T> {
    fn parse_from_json(value: Option<serde_json::Value>) -> poem_openapi::types::ParseResult<Self> {
        T::parse_from_json(value)
            .map(Self::new)
            .map_err(|e| ParseError::custom(e.into_message()))
    }
}

impl<T: ToJSON> ToJSON for Secret<T> {
    fn to_json(&self) -> Option<serde_json::Value> {
        self.0.to_json()
    }
}

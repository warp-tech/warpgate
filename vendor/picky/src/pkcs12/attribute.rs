use crate::pkcs12::Pkcs12Error;
use picky_asn1::restricted_string::BmpString;
use picky_asn1::wrapper::OctetStringAsn1;
use picky_asn1_der::Asn1RawDer;
use picky_asn1_x509::oid::ObjectIdentifier;
use picky_asn1_x509::pkcs12::Pkcs12Attribute as Pkcs12AttributeAsn1;
use serde::{Deserialize, Serialize};

/// Represents a PKCS#12 attributes which can be used to store additional information about safe
/// bag contents (e.g. private key or certificate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkcs12Attribute {
    kind: Pkcs12AttributeKind,
    inner: Pkcs12AttributeAsn1,
}

impl Pkcs12Attribute {
    pub(crate) fn from_asn1(asn1: Pkcs12AttributeAsn1) -> Self {
        let kind = match &asn1 {
            Pkcs12AttributeAsn1::FriendlyName(value) => Pkcs12AttributeKind::FriendlyName(value.clone()),
            Pkcs12AttributeAsn1::LocalKeyId(value) => Pkcs12AttributeKind::LocalKeyId(value.0.clone()),
            Pkcs12AttributeAsn1::Unknown { oid, value } => Pkcs12AttributeKind::Custom(CustomPkcs12Attribute {
                oid: oid.clone(),
                value: value.clone(),
            }),
        };

        Self { kind, inner: asn1 }
    }

    /// Creates a new `friendly name` attribute. This attribute is used to store a human-readable
    /// name of the safe bag contents (e.g. certificate name).
    pub fn new_friendly_name(value: BmpString) -> Self {
        let kind = Pkcs12AttributeKind::FriendlyName(value);
        let inner = kind.to_inner();
        Self { kind, inner }
    }

    /// Creates a new `local key id` attribute. This attribute is used to indicate relation between
    /// private key and certificate (when set to same value on both objects).
    pub fn new_local_key_id(value: impl Into<Vec<u8>>) -> Self {
        let kind = Pkcs12AttributeKind::LocalKeyId(value.into());
        let inner = kind.to_inner();
        Self { kind, inner }
    }

    /// Create a new custom attribute (e.g. Microsoft-specific attributes).
    pub fn new_custom(attr: CustomPkcs12Attribute) -> Self {
        let kind = Pkcs12AttributeKind::Custom(attr);
        let inner = kind.to_inner();
        Self { kind, inner }
    }

    pub fn kind(&self) -> &Pkcs12AttributeKind {
        &self.kind
    }

    pub fn inner(&self) -> &Pkcs12AttributeAsn1 {
        &self.inner
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pkcs12AttributeKind {
    FriendlyName(BmpString),
    LocalKeyId(Vec<u8>),
    Custom(CustomPkcs12Attribute),
}

impl Pkcs12AttributeKind {
    pub(crate) fn to_inner(&self) -> Pkcs12AttributeAsn1 {
        match self {
            Self::FriendlyName(value) => Pkcs12AttributeAsn1::FriendlyName(value.clone()),
            Self::LocalKeyId(value) => Pkcs12AttributeAsn1::LocalKeyId(OctetStringAsn1::from(value.clone())),
            Self::Custom(value) => Pkcs12AttributeAsn1::Unknown {
                oid: value.oid.clone(),
                value: value.value.clone(),
            },
        }
    }
}

impl From<Pkcs12AttributeAsn1> for Pkcs12AttributeKind {
    fn from(value: Pkcs12AttributeAsn1) -> Self {
        match value {
            Pkcs12AttributeAsn1::FriendlyName(value) => Self::FriendlyName(value),
            Pkcs12AttributeAsn1::LocalKeyId(value) => Self::LocalKeyId(value.0),
            Pkcs12AttributeAsn1::Unknown { oid, value } => CustomPkcs12Attribute { oid, value }.into(),
        }
    }
}

impl From<CustomPkcs12Attribute> for Pkcs12AttributeKind {
    fn from(value: CustomPkcs12Attribute) -> Self {
        Self::Custom(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomPkcs12Attribute {
    oid: ObjectIdentifier,
    value: Vec<Asn1RawDer>,
}

impl CustomPkcs12Attribute {
    /// Get attribute oid.
    pub fn oid(&self) -> &ObjectIdentifier {
        &self.oid
    }

    pub fn new_empty(oid: ObjectIdentifier) -> Self {
        Self { oid, value: Vec::new() }
    }

    pub fn has_value(&self) -> bool {
        !self.value.is_empty()
    }

    pub fn new_raw(oid: ObjectIdentifier, value: Vec<Asn1RawDer>) -> Self {
        Self { oid, value }
    }

    /// Creates a new custom attribute from any DER-serializable value. Ut is advised to use types
    /// from `picky-asn1-der` crate.
    pub fn new_single_value<T: Serialize>(oid: ObjectIdentifier, value: &T) -> Result<Self, Pkcs12Error> {
        let encoded = picky_asn1_der::to_vec(value)?;
        Ok(Self {
            oid,
            value: vec![Asn1RawDer(encoded)],
        })
    }

    /// Creates a new custom attribute from multiple any DER-serializable value (PKCS#12 allows
    /// attribute to have list of values). It is advised to use types from `picky-asn1-der` crate.
    pub fn new_multiple_values<'a, T: Serialize + 'a>(
        oid: ObjectIdentifier,
        values: impl IntoIterator<Item = &'a T>,
    ) -> Result<Self, Pkcs12Error> {
        let mut encoded_values = Vec::new();
        for value in values {
            let encoded = picky_asn1_der::to_vec(value)?;
            encoded_values.push(Asn1RawDer(encoded));
        }
        Ok(Self {
            oid,
            value: encoded_values,
        })
    }

    /// Convert inner value to any DER-deserializable value. It is advised to use types from
    /// `picky-asn1-der` crate.
    pub fn to_single_value<'a, T: Deserialize<'a>>(&'a self) -> Result<T, Pkcs12Error> {
        if self.value.len() != 1 {
            return Err(Pkcs12Error::UnexpectedAttributeValuesCount {
                expected: 1,
                actual: self.value.len(),
            });
        }
        let deserialized = picky_asn1_der::from_bytes(&self.value[0].0)?;
        Ok(deserialized)
    }

    /// Convert inner value to multiple DER-deserializable values. It is advised to use types from
    /// `picky-asn1-der` crate.
    pub fn to_multiple_values<'a, T: Deserialize<'a>>(&'a self) -> Result<Vec<T>, Pkcs12Error> {
        let values_result: Result<Vec<_>, _> = self
            .value
            .iter()
            .map(|value| picky_asn1_der::from_bytes(&value.0))
            .collect();
        values_result.map_err(Into::into)
    }

    pub fn raw_data(&self) -> &[Asn1RawDer] {
        &self.value
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use expect_test::expect;

    fn fake_oid() -> ObjectIdentifier {
        "1.3.6.1.4.1.311.17.1".to_string().try_into().unwrap()
    }

    #[test]
    fn single_custom_attribute_roundtrip() {
        let value = BmpString::from_str("Microsoft Software Key Storage Provider").unwrap();
        let attr = CustomPkcs12Attribute::new_single_value(fake_oid(), &value).unwrap();
        let decoded = attr.to_single_value::<BmpString>().unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn single_custom_attribute_roundtrip_no_value() {
        let attr = CustomPkcs12Attribute::new_empty(fake_oid());
        assert!(!attr.has_value());
        let decoded = attr.to_single_value::<BmpString>();
        expect![[r#"
            Err(
                UnexpectedAttributeValuesCount {
                    expected: 1,
                    actual: 0,
                },
            )
        "#]]
        .assert_debug_eq(&decoded);
    }

    #[test]
    fn single_custom_attribute_roundtrip_too_many_values() {
        let value = vec![OctetStringAsn1(vec![0x01]), OctetStringAsn1(vec![0x02])];
        let attr = CustomPkcs12Attribute::new_multiple_values(fake_oid(), &value).unwrap();
        let decoded = attr.to_single_value::<BmpString>();
        expect![[r#"
            Err(
                UnexpectedAttributeValuesCount {
                    expected: 1,
                    actual: 2,
                },
            )
        "#]]
        .assert_debug_eq(&decoded);
    }

    #[test]
    fn multiple_custom_attributes_roundtrip() {
        let value = vec![
            OctetStringAsn1(vec![0x01, 0x02, 0x03]),
            OctetStringAsn1(vec![0x04, 0x05, 0x06]),
        ];

        let attr = CustomPkcs12Attribute::new_multiple_values(fake_oid(), &value).unwrap();
        let decoded = attr.to_multiple_values::<OctetStringAsn1>().unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn multiple_custom_attributes_empty_list_allowed() {
        let value: Vec<OctetStringAsn1> = vec![];
        let attr = CustomPkcs12Attribute::new_multiple_values(fake_oid(), &value).unwrap();
        let decoded = attr.to_multiple_values::<OctetStringAsn1>().unwrap();
        assert_eq!(decoded, value);
    }
}

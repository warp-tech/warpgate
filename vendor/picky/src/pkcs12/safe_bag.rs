use crate::key::PrivateKey;
use crate::pkcs12::{Pkcs12Attribute, Pkcs12CryptoContext, Pkcs12Encryption, Pkcs12Error, Pkcs12ParsingParams};
use crate::x509::Cert;
use picky_asn1::wrapper::OctetStringAsn1;
use picky_asn1_der::Asn1RawDer;
use picky_asn1_x509::oid::ObjectIdentifier;
use picky_asn1_x509::pkcs12::{
    CertificateBag as CertificateBagAsn1, EncryptedKeyBag as EncryptedKeyBagAsn1,
    Pkcs12Attribute as Pkcs12AttributeAsn1, SafeBag as SafeBagAsn1, SafeBagKind as SafeBagKindAsn1,
    SafeContents as SafeContentsAsn1, SecretBag as SecretBagAsn1,
};
use serde::{Deserialize, Serialize};

/// PFX safe bag, see module docs for more information
#[derive(Debug, Clone)]
pub struct SafeBag {
    kind: SafeBagKind,
    attributes: Vec<Pkcs12Attribute>,
    inner: SafeBagAsn1,
}

impl SafeBag {
    /// Create new safe bag holding a private key
    pub fn new_key(key: PrivateKey, attributes: Vec<Pkcs12Attribute>) -> Result<Self, Pkcs12Error> {
        // Convert to `PrivateKeyInfo` structure in DER representation
        let der_data = key.to_pkcs8()?;

        let inner = SafeBagAsn1 {
            kind: SafeBagKindAsn1::Key(Asn1RawDer(der_data)),
            attributes: attributes_to_asn1(&attributes),
        };

        Ok(Self {
            kind: SafeBagKind::PrivateKey(key),
            attributes,
            inner,
        })
    }

    /// Create new safe bag with encrypted key. Note that attributes are not encrypted.
    pub fn new_encrypted_key(
        key: PrivateKey,
        attributes: Vec<Pkcs12Attribute>,
        encryption: Pkcs12Encryption,
        crypto_context: &Pkcs12CryptoContext,
    ) -> Result<Self, Pkcs12Error> {
        let der_data = key.to_pkcs8()?;
        let encrypted = encryption.encrypt(&der_data, crypto_context)?;

        let inner = SafeBagAsn1 {
            kind: SafeBagKindAsn1::EncryptedKey(EncryptedKeyBagAsn1 {
                algorithm: encryption.inner().clone(),
                encrypted_data: OctetStringAsn1(encrypted),
            }),
            attributes: attributes_to_asn1(&attributes),
        };

        Ok(Self {
            kind: SafeBagKind::EncryptedPrivateKey { encryption, key },
            attributes,
            inner,
        })
    }

    /// Create new safe bag with certificate
    pub fn new_certificate(cert: Cert, attributes: Vec<Pkcs12Attribute>) -> Result<Self, Pkcs12Error> {
        let der_data = cert.to_der()?;

        let inner = SafeBagAsn1 {
            kind: SafeBagKindAsn1::Certificate(CertificateBagAsn1::X509(OctetStringAsn1(der_data))),
            attributes: attributes_to_asn1(&attributes),
        };

        Ok(Self {
            kind: SafeBagKind::Certificate(cert),
            attributes,
            inner,
        })
    }

    /// Creates new [`SecretSafeBag`] bag
    pub fn new_secret(secret: SecretSafeBag, attributes: Vec<Pkcs12Attribute>) -> Self {
        let inner = SafeBagAsn1 {
            kind: SafeBagKindAsn1::Secret(SecretBagAsn1 {
                type_id: secret.oid.clone(),
                value: secret.data.clone(),
            }),
            attributes: attributes_to_asn1(&attributes),
        };

        Self {
            kind: SafeBagKind::Secret(secret),
            attributes,
            inner,
        }
    }

    /// Creates safe bag with nested safe bag list.
    pub fn new_nested(safe_bags: Vec<SafeBag>, attributes: Vec<Pkcs12Attribute>) -> Self {
        let safe_contents = SafeContentsAsn1(safe_bags.iter().map(|sb| sb.inner.clone()).collect());

        let inner = SafeBagAsn1 {
            kind: SafeBagKindAsn1::SafeContents(safe_contents),
            attributes: attributes_to_asn1(&attributes),
        };

        Self {
            kind: SafeBagKind::Nested(safe_bags),
            attributes,
            inner,
        }
    }

    /// PKCS#12 allows for arbitrary SafeBags to be included in the PKCS#12 file as long as they
    /// a unique OID.
    pub fn new_custom(oid: ObjectIdentifier, value: Asn1RawDer, attributes: Vec<Pkcs12Attribute>) -> Self {
        let inner = SafeBagAsn1 {
            kind: SafeBagKindAsn1::Unknown { type_id: oid, value },
            attributes: attributes_to_asn1(&attributes),
        };

        Self {
            kind: SafeBagKind::Unknown,
            attributes,
            inner,
        }
    }

    pub(crate) fn from_asn1(
        safe_bag: SafeBagAsn1,
        crypto_context: &Pkcs12CryptoContext,
        parsing_params: &Pkcs12ParsingParams,
    ) -> Result<Self, Pkcs12Error> {
        let attributes = safe_bag
            .attributes
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(Pkcs12Attribute::from_asn1)
            .collect::<Vec<_>>();

        let to_unparsed = |inner, attributes| Self {
            kind: SafeBagKind::Unknown,
            attributes,
            inner,
        };

        let kind = match &safe_bag.kind {
            SafeBagKindAsn1::Key(Asn1RawDer(der_data)) => {
                let key = match PrivateKey::from_pkcs8(&der_data) {
                    Ok(key) => key,
                    Err(_) if parsing_params.skip_soft_parsing_errors => {
                        return Ok(to_unparsed(safe_bag, attributes));
                    }
                    Err(e) => return Err(e.into()),
                };

                SafeBagKind::PrivateKey(key)
            }
            SafeBagKindAsn1::EncryptedKey(encrypted_key) => {
                let encryption = match Pkcs12Encryption::from_asn1(encrypted_key.algorithm.clone()) {
                    Ok(encryption) => encryption,
                    Err(_) if parsing_params.skip_decryption_errors => {
                        return Ok(to_unparsed(safe_bag, attributes));
                    }
                    Err(e) => return Err(e),
                };

                let der_data = match encryption.decrypt(&encrypted_key.encrypted_data.0, crypto_context) {
                    Ok(der_data) => der_data,
                    Err(_) if parsing_params.skip_decryption_errors => {
                        return Ok(to_unparsed(safe_bag, attributes));
                    }
                    Err(e) => return Err(e),
                };

                let key = match PrivateKey::from_pkcs8(&der_data) {
                    Ok(key) => key,
                    Err(_) if parsing_params.skip_soft_parsing_errors => {
                        return Ok(to_unparsed(safe_bag, attributes));
                    }
                    Err(e) => return Err(e.into()),
                };

                SafeBagKind::EncryptedPrivateKey { encryption, key }
            }
            SafeBagKindAsn1::Certificate(CertificateBagAsn1::X509(OctetStringAsn1(der_data))) => {
                let cert = match Cert::from_der(&der_data) {
                    Ok(cert) => cert,
                    Err(_) if parsing_params.skip_soft_parsing_errors => {
                        return Ok(to_unparsed(safe_bag, attributes));
                    }
                    Err(e) => return Err(e.into()),
                };

                SafeBagKind::Certificate(cert)
            }
            SafeBagKindAsn1::Secret(SecretBagAsn1 { type_id, value }) => {
                let secret = SecretSafeBag {
                    oid: type_id.clone(),
                    data: value.clone(),
                };

                SafeBagKind::Secret(secret)
            }
            SafeBagKindAsn1::SafeContents(safe_contents) => {
                let safe_bags = safe_contents
                    .0
                    .iter()
                    .map(|sb| Self::from_asn1(sb.clone(), crypto_context, parsing_params))
                    .collect::<Result<Vec<_>, _>>()?;

                SafeBagKind::Nested(safe_bags)
            }
            SafeBagKindAsn1::Crl(_)
            | SafeBagKindAsn1::Certificate(CertificateBagAsn1::Unknown { .. })
            | SafeBagKindAsn1::Unknown { .. } => {
                return Ok(to_unparsed(safe_bag, attributes));
            }
        };

        Ok(Self {
            kind,
            attributes,
            inner: safe_bag,
        })
    }

    /// Adds a PKCS12 attribute to this safe bag.
    ///
    /// Note that there is an additional performance cost: the inner DER representation must be updated.
    pub fn add_attribute(&mut self, attribute: Pkcs12Attribute) {
        self.attributes.push(attribute);
        self.inner.attributes = attributes_to_asn1(&self.attributes);
    }

    pub fn attributes(&self) -> &[Pkcs12Attribute] {
        &self.attributes
    }

    pub fn kind(&self) -> &SafeBagKind {
        &self.kind
    }

    pub fn into_kind(self) -> SafeBagKind {
        self.kind
    }

    pub fn inner(&self) -> &SafeBagAsn1 {
        &self.inner
    }

    pub fn into_inner(self) -> SafeBagAsn1 {
        self.inner
    }
}

/// Parsed safe bag representation.
#[derive(Debug)]
pub enum SafeBagKind {
    PrivateKey(PrivateKey),
    EncryptedPrivateKey {
        encryption: Pkcs12Encryption,
        key: PrivateKey,
    },
    Certificate(Cert),
    Secret(SecretSafeBag),
    Nested(Vec<SafeBag>),
    Unknown,
}

impl Clone for SafeBagKind {
    fn clone(&self) -> Self {
        match self {
            Self::PrivateKey(key) => Self::PrivateKey(key.clone()),
            Self::EncryptedPrivateKey { encryption, key } => Self::EncryptedPrivateKey {
                encryption: encryption.duplicate(),
                key: key.clone(),
            },
            Self::Certificate(cert) => Self::Certificate(cert.clone()),
            Self::Secret(secret) => Self::Secret(secret.clone()),
            Self::Nested(nested) => Self::Nested(nested.clone()),
            Self::Unknown => Self::Unknown,
        }
    }
}

/// Secret bag which could contain any user-defined data, as long as it could be DER-encoded.
/// It is advised to use types from `picky-asn1-der` crate.
#[derive(Debug, Clone)]
pub struct SecretSafeBag {
    oid: ObjectIdentifier,
    data: Asn1RawDer,
}

impl SecretSafeBag {
    pub fn new_raw(oid: ObjectIdentifier, data: Asn1RawDer) -> Self {
        Self { oid, data }
    }

    /// Create new secret bag from serializable data.
    pub fn new<T: Serialize>(oid: ObjectIdentifier, value: &T) -> Result<Self, Pkcs12Error> {
        let encoded = picky_asn1_der::to_vec(value)?;
        Ok(Self {
            oid,
            data: Asn1RawDer(encoded),
        })
    }

    pub fn oid(&self) -> &ObjectIdentifier {
        &self.oid
    }

    pub fn raw_data(&self) -> &[u8] {
        &self.data.0
    }

    /// Get secret bag data as deserialized type.
    pub fn get_data<'a, T: Deserialize<'a>>(&'a self) -> Result<T, Pkcs12Error> {
        let deserialized = picky_asn1_der::from_bytes(&self.data.0)?;
        Ok(deserialized)
    }
}

fn attributes_to_asn1(attributes: &[Pkcs12Attribute]) -> Option<Vec<Pkcs12AttributeAsn1>> {
    if attributes.is_empty() {
        None
    } else {
        Some(attributes.iter().map(|a| a.inner().clone()).collect())
    }
}

use crate::pkcs12::{Pkcs12CryptoContext, Pkcs12Encryption, Pkcs12Error, Pkcs12ParsingParams, SafeBag};
use picky_asn1::wrapper::OctetStringAsn1;
use picky_asn1_x509::pkcs12::{
    EncryptedSafeContents as EncryptedSafeContentsAsn1, SafeContents as SafeContentsAsn1,
    SafeContentsContentInfo as SafeContentsContentInfoAsn1,
};

/// Top-level PFX container object, which holds list of safe bags and could be encrypted or not.
#[derive(Debug, Clone)]
pub struct SafeContents {
    kind: SafeContentsKind,
    inner: SafeContentsContentInfoAsn1,
}

impl SafeContents {
    pub(crate) fn from_asn1(
        inner: SafeContentsContentInfoAsn1,
        crypto_context: &Pkcs12CryptoContext,
        parsing_params: &Pkcs12ParsingParams,
    ) -> Result<Self, Pkcs12Error> {
        let to_unparsed = |inner| Self {
            kind: SafeContentsKind::Unknown,
            inner,
        };

        let kind = match &inner {
            SafeContentsContentInfoAsn1::Data(data) => {
                let safe_bags = data
                    .0
                    .iter()
                    .map(|sb| SafeBag::from_asn1(sb.clone(), crypto_context, parsing_params))
                    .collect::<Result<Vec<_>, _>>()?;

                Self {
                    kind: SafeContentsKind::SafeBags(safe_bags),
                    inner,
                }
            }
            SafeContentsContentInfoAsn1::EncryptedData(encrypted) => {
                let encryption = match Pkcs12Encryption::from_asn1(encrypted.algorithm.clone()) {
                    Ok(encryption) => encryption,
                    Err(_) if parsing_params.skip_decryption_errors => {
                        return Ok(to_unparsed(inner));
                    }
                    Err(e) => {
                        return Err(e);
                    }
                };

                let encrypted_content = match encrypted.encrypted_content.as_ref() {
                    Some(content) => content.0.as_slice(),
                    None => {
                        return Ok(Self {
                            // No content to decrypt
                            kind: SafeContentsKind::EncryptedSafeBags {
                                encryption,
                                safe_bags: vec![],
                            },
                            inner,
                        });
                    }
                };

                let decrypted = match encryption.decrypt(encrypted_content, crypto_context) {
                    Ok(decrypted) => decrypted,
                    Err(_) if parsing_params.skip_decryption_errors => {
                        return Ok(to_unparsed(inner));
                    }
                    Err(e) => {
                        return Err(e);
                    }
                };

                let safe_bags_asn1 = match picky_asn1_der::from_bytes::<SafeContentsAsn1>(&decrypted) {
                    Ok(safe_contents) => safe_contents.0,
                    Err(_) if parsing_params.skip_decryption_errors => {
                        return Ok(to_unparsed(inner));
                    }
                    Err(e) => {
                        return Err(e.into());
                    }
                };

                let safe_bags = safe_bags_asn1
                    .into_iter()
                    .map(|sb| SafeBag::from_asn1(sb, crypto_context, parsing_params))
                    .collect::<Result<Vec<_>, _>>()?;

                Self {
                    kind: SafeContentsKind::EncryptedSafeBags { encryption, safe_bags },
                    inner,
                }
            }
            SafeContentsContentInfoAsn1::Unknown { .. } => return Ok(to_unparsed(inner)),
        };

        Ok(kind)
    }

    pub fn new(safe_bags: Vec<SafeBag>) -> Self {
        let safe_contents = SafeContentsAsn1(safe_bags.iter().map(|sb| sb.inner().clone()).collect());
        Self {
            kind: SafeContentsKind::SafeBags(safe_bags),
            inner: SafeContentsContentInfoAsn1::Data(safe_contents),
        }
    }

    pub fn new_encrypted(
        safe_bags: Vec<SafeBag>,
        encryption: Pkcs12Encryption,
        crypto_context: &Pkcs12CryptoContext,
    ) -> Result<Self, Pkcs12Error> {
        let safe_contents = SafeContentsAsn1(safe_bags.iter().map(|sb| sb.inner().clone()).collect());
        let der_data = picky_asn1_der::to_vec(&safe_contents)?;
        let encrypted = encryption.encrypt(&der_data, crypto_context)?;

        let inner = SafeContentsContentInfoAsn1::EncryptedData(EncryptedSafeContentsAsn1 {
            algorithm: encryption.inner().clone(),
            encrypted_content: Some(OctetStringAsn1(encrypted)),
        });

        Ok(Self {
            kind: SafeContentsKind::EncryptedSafeBags { encryption, safe_bags },
            inner,
        })
    }

    pub fn kind(&self) -> &SafeContentsKind {
        &self.kind
    }

    pub fn into_kind(self) -> SafeContentsKind {
        self.kind
    }

    pub fn inner(&self) -> &SafeContentsContentInfoAsn1 {
        &self.inner
    }

    pub fn into_inner(self) -> SafeContentsContentInfoAsn1 {
        self.inner
    }
}

// Clippy triggers lint because of relatively big `Pkcs12Encryption` (~200 bytes) in comparison with
// `SafeContentsKind::Unknown` (0 bytes), but just to keep it consistent with other enums, we do allow
// such difference in size.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum SafeContentsKind {
    SafeBags(Vec<SafeBag>),
    EncryptedSafeBags {
        encryption: Pkcs12Encryption,
        safe_bags: Vec<SafeBag>,
    },
    Unknown,
}

impl Clone for SafeContentsKind {
    fn clone(&self) -> Self {
        match self {
            Self::SafeBags(bags) => Self::SafeBags(bags.clone()),
            Self::EncryptedSafeBags { encryption, safe_bags } => Self::EncryptedSafeBags {
                encryption: encryption.duplicate(),
                safe_bags: safe_bags.clone(),
            },
            Self::Unknown => Self::Unknown,
        }
    }
}

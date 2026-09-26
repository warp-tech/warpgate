use crate::key::ec::{EcdsaKeypair, EcdsaPublicKey, NamedEcCurve};
use crate::key::ed::{EdKeypair, EdPublicKey, NamedEdAlgorithm};
use crate::key::{EcCurve, EdAlgorithm, PrivateKey};
use crate::putty::PuttyError;
use crate::putty::key_value::PpkKeyAlgorithmValue;
use crate::putty::public_key::PuttyBasePublicKey;
use crate::ssh::SshPrivateKey;
use crate::ssh::decode::SshReadExt;
use crate::ssh::encode::SshWriteExt;
use crate::ssh::private_key::SshBasePrivateKey;
use crate::ssh::public_key::SshBasePublicKey;
use crypto_bigint::BoxedUint;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{RsaPrivateKey, RsaPublicKey};

/// PuTTY private key wrapper
pub(crate) struct PuttyPrivateKey {
    pub(crate) base: PuttyBasePrivateKey,
    pub(crate) comment: String,
}

impl PuttyPrivateKey {
    pub fn from_openssh(key: &SshPrivateKey) -> Result<Self, PuttyError> {
        let base = PuttyBasePrivateKey::from_openssh(&key.base_key)?;
        let comment = key.comment.clone();

        Ok(Self { base, comment })
    }

    /// Converts the key to an OpenSSH key (with or without encryption)
    pub fn to_openssh(&self, passphrase: Option<&str>) -> Result<SshPrivateKey, PuttyError> {
        let base = self.base.to_openssh()?;
        let comment = if self.comment.is_empty() {
            None
        } else {
            Some(self.comment.clone())
        };

        let key = match base {
            SshBasePrivateKey::Rsa(key) => key,
            SshBasePrivateKey::Ec(key) => key,
            SshBasePrivateKey::Ed(key) => key,
            SshBasePrivateKey::SkEcdsaSha2NistP256 { .. } | SshBasePrivateKey::SkEd25519 { .. } => {
                return Err(PuttyError::NotSupported { feature: "SK keys" });
            }
        };

        Ok(SshPrivateKey::h_picky_private_key_to_ssh_private_key(
            key,
            passphrase.map(From::from),
            comment,
        )?)
    }
}

pub(crate) struct PuttyBasePrivateKey {
    pub(crate) algorithm: PpkKeyAlgorithmValue,
    pub(crate) public_key: PuttyBasePublicKey,
    pub(crate) data: Vec<u8>,
}

impl PuttyBasePrivateKey {
    pub fn from_openssh(key: &SshBasePrivateKey) -> Result<Self, PuttyError> {
        let mut data = Vec::new();
        let cursor = &mut data;

        match key {
            SshBasePrivateKey::SkEcdsaSha2NistP256 { .. } | SshBasePrivateKey::SkEd25519 { .. } => {
                // Putty does not support SK keys
                Err(PuttyError::NotSupported { feature: "SK keys" })
            }
            SshBasePrivateKey::Rsa(key) => {
                let mut rsa_key = RsaPrivateKey::try_from(key)?;

                cursor.write_ssh_mpint(rsa_key.d())?;
                if rsa_key.primes().len() != 2 {
                    return Err(PuttyError::RsaInvalidPrimesCount {
                        count: rsa_key.primes().len(),
                    });
                }
                cursor.write_ssh_mpint(&rsa_key.primes()[0])?;
                cursor.write_ssh_mpint(&rsa_key.primes()[1])?;

                rsa_key.precompute().map_err(|_| PuttyError::RsaPrecompute)?;
                let qinv = rsa_key
                    .qinv()
                    .expect("BUG: should be precomuted above")
                    .retrieve()
                    .to_be_bytes_trimmed_vartime();
                cursor.write_ssh_bytes(&qinv)?;

                let ssh_public_key = SshBasePublicKey::Rsa(key.to_public_key()?);
                let public_key = PuttyBasePublicKey::from_openssh(&ssh_public_key)?;

                Ok(Self {
                    algorithm: PpkKeyAlgorithmValue::Rsa,
                    data,
                    public_key,
                })
            }
            SshBasePrivateKey::Ec(key) => {
                let ec_key = EcdsaKeypair::try_from(key)?;

                let secret = BoxedUint::from_be_slice_vartime(ec_key.secret());
                cursor.write_ssh_mpint(&secret)?;

                let algorithm = match ec_key.curve() {
                    NamedEcCurve::Known(EcCurve::NistP256) => PpkKeyAlgorithmValue::EcdsaSha2Nistp256,
                    NamedEcCurve::Known(EcCurve::NistP384) => PpkKeyAlgorithmValue::EcdsaSha2Nistp384,
                    NamedEcCurve::Known(EcCurve::NistP521) => PpkKeyAlgorithmValue::EcdsaSha2Nistp521,
                    _ => {
                        return Err(PuttyError::NotSupported {
                            feature: "unknown EC curve",
                        });
                    }
                };

                let ssh_public_key = SshBasePublicKey::Ec(key.to_public_key()?);
                let public_key = PuttyBasePublicKey::from_openssh(&ssh_public_key)?;

                Ok(Self {
                    algorithm,
                    data,
                    public_key,
                })
            }
            SshBasePrivateKey::Ed(key) => {
                let ed_key = EdKeypair::try_from(key)?;

                cursor.write_ssh_mpint(&BoxedUint::from_be_slice_vartime(ed_key.secret()))?;

                let algorithm = match ed_key.algorithm() {
                    NamedEdAlgorithm::Known(EdAlgorithm::Ed25519) => PpkKeyAlgorithmValue::Ed25519,
                    NamedEdAlgorithm::Known(EdAlgorithm::X25519) => {
                        return Err(PuttyError::NotSupported { feature: "X25519 keys" });
                    }
                    _ => {
                        return Err(PuttyError::NotSupported {
                            feature: "unknown EdDSA algorithm",
                        });
                    }
                };

                let ssh_public_key = SshBasePublicKey::Ed(key.to_public_key()?);
                let public_key = PuttyBasePublicKey::from_openssh(&ssh_public_key)?;

                Ok(Self {
                    algorithm,
                    data,
                    public_key,
                })
            }
        }
    }

    pub fn to_openssh(&self) -> Result<SshBasePrivateKey, PuttyError> {
        let ssh_public_key = self.public_key.to_openssh()?;
        let mut data = self.data.as_slice();

        match self.algorithm {
            PpkKeyAlgorithmValue::Rsa => {
                let public = match &ssh_public_key {
                    SshBasePublicKey::Rsa(rsa) => RsaPublicKey::try_from(rsa)?,
                    _ => return Err(PuttyError::PublicAndPrivateKeyMismatch),
                };

                let d = data.read_ssh_mpint()?;
                let p1 = data.read_ssh_mpint()?;
                let p2 = data.read_ssh_mpint()?;
                let _qinv = data.read_ssh_mpint()?;

                let private_key = PrivateKey::from_rsa_components(public.n(), public.e(), &d, &[p1, p2])?;

                Ok(SshBasePrivateKey::Rsa(private_key))
            }
            PpkKeyAlgorithmValue::EcdsaSha2Nistp256
            | PpkKeyAlgorithmValue::EcdsaSha2Nistp384
            | PpkKeyAlgorithmValue::EcdsaSha2Nistp521 => {
                let public = match &ssh_public_key {
                    SshBasePublicKey::Ec(rsa) => EcdsaPublicKey::try_from(rsa)?,
                    _ => return Err(PuttyError::PublicAndPrivateKeyMismatch),
                };

                let secret = data.read_ssh_mpint()?;

                let curve = match self.algorithm {
                    PpkKeyAlgorithmValue::EcdsaSha2Nistp256 => NamedEcCurve::Known(EcCurve::NistP256),
                    PpkKeyAlgorithmValue::EcdsaSha2Nistp384 => NamedEcCurve::Known(EcCurve::NistP384),
                    PpkKeyAlgorithmValue::EcdsaSha2Nistp521 => NamedEcCurve::Known(EcCurve::NistP521),
                    _ => unreachable!("BUG: algorithm is checked above"),
                };

                let private_key = PrivateKey::from_ec_encoded_components(
                    curve.into(),
                    &secret.to_be_bytes_trimmed_vartime(),
                    Some(public.encoded_point()),
                );

                Ok(SshBasePrivateKey::Ec(private_key))
            }
            PpkKeyAlgorithmValue::Ed25519 => {
                let public = match &ssh_public_key {
                    SshBasePublicKey::Ed(rsa) => EdPublicKey::try_from(rsa)?,
                    _ => return Err(PuttyError::PublicAndPrivateKeyMismatch),
                };

                let secret = data.read_ssh_mpint()?;

                let private_key = PrivateKey::from_ed_encoded_components(
                    NamedEdAlgorithm::Known(EdAlgorithm::Ed25519).into(),
                    &secret.to_be_bytes_trimmed_vartime(),
                    Some(public.data()),
                );

                Ok(SshBasePrivateKey::Ed(private_key))
            }
            _ => Err(PuttyError::NotSupported {
                feature: "unsupported key algorithm",
            }),
        }
    }

    pub fn to_inner_key(&self) -> Result<PrivateKey, PuttyError> {
        let inner = match self.to_openssh()? {
            SshBasePrivateKey::Rsa(key) => key,
            SshBasePrivateKey::Ec(key) => key,
            SshBasePrivateKey::Ed(key) => key,
            SshBasePrivateKey::SkEcdsaSha2NistP256 { .. } | SshBasePrivateKey::SkEd25519 { .. } => {
                return Err(PuttyError::NotSupported { feature: "SK keys" });
            }
        };

        Ok(inner)
    }
}

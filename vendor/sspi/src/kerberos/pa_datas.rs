use picky_krb::data_types::PaData;
use picky_krb::messages::AsRep;

use crate::kerberos::client::extractors::{extract_session_key_from_as_rep, extract_session_key_from_as_rep_with_key};
use crate::kerberos::client::generators::{
    GenerateAsPaDataOptions as AuthIdentityPaDataOptions, GenerateKeytabPaDataOptions,
    generate_pa_datas_for_as_req as generate_password_based,
    generate_pa_datas_for_as_req_with_key as generate_keytab_based,
};
use crate::kerberos::encryption_params::EncryptionParams;
#[cfg(feature = "scard")]
use crate::pk_init::{
    GenerateAsPaDataOptions as SmartCardPaDataOptions, generate_pa_datas_for_as_req as generate_private_key_based,
};
use crate::{Result, Secret};

// PA-DATAs are very different for the Kerberos logon using username+password and smart card.
// This enum provides a unified way to generate PA-DATAs based on the provided options.
pub(crate) enum AsReqPaDataOptions<'a> {
    AuthIdentity(AuthIdentityPaDataOptions<'a>),
    #[cfg(feature = "scard")]
    SmartCard(Box<SmartCardPaDataOptions<'a>>),
    Keytab(GenerateKeytabPaDataOptions),
}

impl AsReqPaDataOptions<'_> {
    pub(crate) fn generate(&mut self) -> Result<Vec<PaData>> {
        match self {
            AsReqPaDataOptions::AuthIdentity(options) => generate_password_based(options),
            #[cfg(feature = "scard")]
            AsReqPaDataOptions::SmartCard(options) => generate_private_key_based(options),
            AsReqPaDataOptions::Keytab(options) => generate_keytab_based(options),
        }
    }

    pub(crate) fn with_pre_auth(&mut self, pre_auth: bool) {
        match self {
            AsReqPaDataOptions::AuthIdentity(options) => options.with_pre_auth = pre_auth,
            #[cfg(feature = "scard")]
            AsReqPaDataOptions::SmartCard(options) => options.with_pre_auth = pre_auth,
            AsReqPaDataOptions::Keytab(options) => options.with_pre_auth = pre_auth,
        }
    }

    pub(crate) fn with_salt(&mut self, salt: Vec<u8>) {
        match self {
            AsReqPaDataOptions::AuthIdentity(options) => options.salt = salt,
            #[cfg(feature = "scard")]
            AsReqPaDataOptions::SmartCard(_) => {}
            // The keytab key is pre-derived; the KDC-supplied salt is irrelevant.
            AsReqPaDataOptions::Keytab(_) => {}
        }
    }
}

// ApRep session key extraction process is different for the Kerberos logon using username+password and smart card.
// This enum provides a unified way to extract session key from the AsRep.
#[derive(Debug)]
pub(super) enum AsRepSessionKeyExtractor<'a> {
    AuthIdentity {
        salt: &'a str,
        password: &'a str,
        enc_params: &'a EncryptionParams,
    },
    Keytab {
        key: &'a [u8],
        enc_params: &'a EncryptionParams,
    },
    #[cfg(feature = "scard")]
    SmartCard {
        dh_parameters: &'a mut crate::pk_init::DhParameters,
        enc_params: &'a mut EncryptionParams,
    },
}

impl AsRepSessionKeyExtractor<'_> {
    #[instrument(level = "trace", ret, skip(self))]
    pub(super) fn session_key(&mut self, as_rep: &AsRep) -> Result<Secret<Vec<u8>>> {
        match self {
            AsRepSessionKeyExtractor::AuthIdentity {
                salt,
                password,
                enc_params,
            } => extract_session_key_from_as_rep(as_rep, salt, password, enc_params),
            AsRepSessionKeyExtractor::Keytab { key, enc_params } => {
                extract_session_key_from_as_rep_with_key(as_rep, key, enc_params)
            }
            #[cfg(feature = "scard")]
            AsRepSessionKeyExtractor::SmartCard {
                dh_parameters,
                enc_params,
            } => {
                use picky_asn1_x509::signed_data::SignedData;
                use picky_krb::crypto::CipherSuite;
                use picky_krb::crypto::diffie_hellman::{DhNonce, generate_key};
                use picky_krb::pkinit::PaPkAsRep;

                use crate::pk_init::{Wrapper, extract_server_dh_public_key};
                use crate::pku2u::{
                    extract_pa_pk_as_rep, extract_server_nonce, validate_server_p2p_certificate, validate_signed_data,
                };
                use crate::{Error, ErrorKind, check_if_empty, pku2u};

                let dh_rep_info = match extract_pa_pk_as_rep(as_rep)? {
                    PaPkAsRep::DhInfo(dh) => dh.0,
                    PaPkAsRep::EncKeyPack(_) => {
                        return Err(Error::new(
                            ErrorKind::OperationNotSupported,
                            "encKeyPack is not supported for the PA-PK-AS-REP",
                        ));
                    }
                };

                let server_nonce = extract_server_nonce(&dh_rep_info)?;
                dh_parameters.server_nonce = Some(server_nonce);

                let wrapped_signed_data: Wrapper<SignedData> =
                    picky_asn1_der::from_bytes(&dh_rep_info.dh_signed_data.0)?;
                let signed_data = wrapped_signed_data.content.0;

                let rsa_public_key = validate_server_p2p_certificate(&signed_data)?;
                validate_signed_data(&signed_data, &rsa_public_key)?;

                let public_key = extract_server_dh_public_key(&signed_data)?;
                dh_parameters.other_public_key = Some(public_key);

                enc_params.encryption_type = Some(CipherSuite::try_from(as_rep.0.enc_part.0.etype.0.0.as_slice())?);

                let key = generate_key(
                    check_if_empty!(dh_parameters.other_public_key.as_ref(), "dh public key is not set"),
                    &dh_parameters.private_key,
                    &dh_parameters.modulus,
                    Some(DhNonce {
                        client_nonce: check_if_empty!(dh_parameters.client_nonce.as_ref(), "dh client none is not set"),
                        server_nonce: check_if_empty!(
                            dh_parameters.server_nonce.as_ref(),
                            "dh server nonce is not set"
                        ),
                    }),
                    check_if_empty!(enc_params.encryption_type.as_ref(), "encryption type is not set")
                        .cipher()
                        .as_ref(),
                )?;

                let session_key = pku2u::extract_session_key_from_as_rep(as_rep, &key, enc_params)?;

                Ok(session_key)
            }
        }
    }
}

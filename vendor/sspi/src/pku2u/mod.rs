mod cert_utils;
mod config;
mod extractors;
mod generators;
#[macro_use]
pub mod macros;
mod server;
mod validate;

use std::io::Write;
use std::str::FromStr;
use std::sync::LazyLock;

pub use cert_utils::validation::validate_server_p2p_certificate;
pub use config::{Pku2uConfig, Pku2uCredential, Pku2uPrivateKey};
pub use extractors::{extract_pa_pk_as_rep, extract_server_nonce, extract_session_key_from_as_rep};
pub use generators::{generate_authenticator, generate_authenticator_extension, generate_client_dh_parameters};
use picky_asn1_x509::Certificate;
use picky_asn1_x509::signed_data::SignedData;
use picky_krb::constants::gss_api::{AP_REQ_TOKEN_ID, AS_REQ_TOKEN_ID, AUTHENTICATOR_CHECKSUM_TYPE};
use picky_krb::constants::key_usages::{ACCEPTOR_SIGN, INITIATOR_SIGN};
use picky_krb::crypto::aes::{AesSize, checksum_sha_aes};
use picky_krb::crypto::diffie_hellman::{DhNonce, generate_key};
use picky_krb::crypto::{ChecksumSuite, CipherSuite, DecryptWithoutChecksum, EncryptWithoutChecksum};
use picky_krb::gss_api::{NegTokenTarg1, WrapToken};
use picky_krb::messages::{ApRep, AsRep};
use picky_krb::negoex::data_types::MessageType;
use picky_krb::negoex::messages::{Exchange, Nego, Verify};
use picky_krb::negoex::{NegoexMessage, RANDOM_ARRAY_SIZE};
use picky_krb::pkinit::{PaPkAsRep, Pku2uNegoRep, Pku2uNegoReqMetadata};
use rand::rngs::{StdRng, SysRng};
use rand_core::{Rng as _, SeedableRng as _};
use uuid::Uuid;
pub use validate::validate_signed_data;

use self::generators::{
    WELLKNOWN_REALM, generate_neg, generate_neg_token_init, generate_neg_token_targ, generate_pku2u_nego_req,
    generate_server_dh_parameters,
};
use crate::builders::{ChangePassword, FilledAcceptSecurityContext};
use crate::channel_bindings::ChannelBindings;
use crate::generator::{GeneratorAcceptSecurityContext, GeneratorInitSecurityContext, YieldPointLocal};
use crate::kerberos::client::extractors::{
    decrypt_ap_rep, extract_seq_number_from_ap_rep, extract_sub_session_key_from_ap_rep,
};
use crate::kerberos::client::generators::{
    ChecksumOptions, ChecksumValues, EncKey, GenerateAsReqOptions, GenerateAuthenticatorOptions, generate_ap_req,
    generate_as_req, generate_as_req_kdc_body, generate_nonce,
};
use crate::kerberos::{DEFAULT_ENCRYPTION_TYPE, EncryptionParams, RRC};
use crate::pk_init::{
    DhParameters, GenerateAsPaDataOptions, extract_server_dh_public_key, generate_pa_datas_for_as_req,
};
use crate::pku2u::cert_utils::validation::{extract_signing_certificate, validate_peer_p2p_certificate};
use crate::pku2u::extractors::{extract_krb_rep, extract_krb_result, extract_session_key_and_nonce_from_as_rep};
use crate::pku2u::generators::generate_as_req_username_from_certificate;
use crate::utils::{generate_random_symmetric_key, get_encryption_key, save_decrypted_data};
use crate::{
    AcceptSecurityContextResult, AcquireCredentialsHandleResult, AuthIdentity, AuthIdentityBuffers, BufferType,
    CertContext, CertEncodingType, CertTrustErrorStatus, CertTrustInfoStatus, CertTrustStatus, ClientResponseFlags,
    ContextNames, ContextSizes, CredentialUse, DecryptionFlags, EncryptionFlags, Error, ErrorKind,
    InitializeSecurityContextResult, PackageCapabilities, PackageInfo, Result, Secret, SecurityBuffer,
    SecurityBufferRef, SecurityPackageType, SecurityStatus, Sspi, SspiEx, SspiImpl,
};

pub const PKG_NAME: &str = "pku2u";

pub const AZURE_AD_DOMAIN: &str = "AzureAD";

/// Default NEGOEX authentication scheme
pub const DEFAULT_NEGOEX_AUTH_SCHEME: &str = "0d53335c-f9ea-4d0d-b2ec-4ae3786ec308";

const WRAP_SENT_BY_ACCEPTOR: u8 = 0x01;
const WRAP_SEALED: u8 = 0x02;
const WRAP_ACCEPTOR_SUBKEY: u8 = 0x04;
const ENCRYPTED_WRAP_EC: u16 = 16;
const INTEGRITY_ONLY_RRC: u16 = 12;
const PKU2U_SECURITY_TRAILER: usize = 76;
const NEGOEX_HEADER_LEN: usize = 40;
const NEGOEX_NEGO_HEADER_LEN: usize = 96;
const NEGOEX_EXCHANGE_HEADER_LEN: usize = 64;
const NEGOEX_VERIFY_HEADER_LEN: usize = 80;

pub static PACKAGE_INFO: LazyLock<PackageInfo> = LazyLock::new(|| PackageInfo {
    capabilities: PackageCapabilities::INTEGRITY
        | PackageCapabilities::PRIVACY
        | PackageCapabilities::CONNECTION
        | PackageCapabilities::IMPERSONATION
        | PackageCapabilities::GSS_COMPATIBLE
        | PackageCapabilities::MUTUAL_AUTH
        | PackageCapabilities::NEGOTIABLE2
        | PackageCapabilities::APP_CONTAINER_CHECKS,
    rpc_id: 31,
    max_token_len: 12_000,
    name: SecurityPackageType::Pku2u,
    comment: String::from("PKU2U Security Package"),
});

#[derive(Debug, Clone)]
pub enum Pku2uState {
    Negotiate,
    Preauthentication,
    AsExchange,
    ApExchange,
    PubKeyAuth,
    Credentials,
    Final,
}

#[derive(Debug, Clone)]
enum Pku2uMode {
    Client,
    Server,
}

#[derive(Debug, Clone)]
pub struct Pku2u {
    mode: Pku2uMode,
    config: Pku2uConfig,
    state: Pku2uState,
    encryption_params: EncryptionParams,
    auth_identity: Option<AuthIdentityBuffers>,
    conversation_id: Uuid,
    auth_scheme: Option<Uuid>,
    seq_number: u32,
    gss_seq_number: u32,
    remote_gss_seq_number: u32,
    request_nonce: Option<u32>,
    channel_bindings: Option<ChannelBindings>,
    peer_certificate: Option<Certificate>,
    peer_certificate_trusted: bool,
    peer_name: Option<crate::Username>,
    #[cfg(test)]
    certificate_validation_time: Option<time::OffsetDateTime>,
    dh_parameters: DhParameters,
    // all sent and received NEGOEX messages concatenated in one vector
    // we need it for the further checksum calculation
    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-negoex/9de2cde2-bd98-40a4-9efa-0f5a1d6cc88e
    // The checksum is performed on all previous NEGOEX messages in the context negotiation.
    negoex_messages: Vec<u8>,
    // two last GSS-API messages concatenated in one vector
    // we need it for the further authenticator checksum calculation
    // https://datatracker.ietf.org/doc/html/draft-zhu-pku2u-04#section-6
    // The checksum is performed on all previous NEGOEX messages in the context negotiation.
    gss_api_messages: Vec<u8>,
    negoex_random: [u8; RANDOM_ARRAY_SIZE],
    // Acceptor-only: the symmetric key used to encrypt the self-issued Kerberos Ticket embedded in
    // the AS-REP. Generated fresh when the acceptor builds the AS-REP and kept only so the acceptor
    // can later decrypt that same Ticket out of the initiator's AP-REQ. Never set for the client role
    // and never shared with the initiator (the Ticket is opaque to it).
    ticket_encryption_key: Option<Secret<Vec<u8>>>,
}

impl Pku2u {
    pub fn new_server_from_config(config: Pku2uConfig) -> Result<Self> {
        let mut rng = StdRng::try_from_rng(&mut SysRng)?;
        let mut negoex_random = [0; RANDOM_ARRAY_SIZE];
        rng.fill_bytes(&mut negoex_random);

        Ok(Self {
            mode: Pku2uMode::Server,
            config,
            state: Pku2uState::Preauthentication,
            encryption_params: EncryptionParams::default_for_server(),
            auth_identity: None,
            conversation_id: Uuid::default(),
            auth_scheme: Some(Uuid::from_str(DEFAULT_NEGOEX_AUTH_SCHEME).unwrap()),
            seq_number: 2,
            gss_seq_number: 0,
            remote_gss_seq_number: 0,
            request_nonce: None,
            channel_bindings: None,
            peer_certificate: None,
            peer_certificate_trusted: false,
            peer_name: None,
            #[cfg(test)]
            certificate_validation_time: None,
            // https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.3
            // Contains the nonce in the pkAuthenticator field in the request if the DH keys are NOT reused,
            // 0 otherwise.
            // generate dh parameters at the start in order to not waste time during authorization
            dh_parameters: generate_server_dh_parameters(&mut rng)?,
            negoex_messages: Vec::new(),
            gss_api_messages: Vec::new(),
            negoex_random,
            ticket_encryption_key: None,
        })
    }

    pub fn new_client_from_config(config: Pku2uConfig) -> Result<Self> {
        let mut rand = StdRng::try_from_rng(&mut SysRng)?;
        let mut negoex_random = [0; RANDOM_ARRAY_SIZE];
        rand.fill_bytes(&mut negoex_random);

        Ok(Self {
            mode: Pku2uMode::Client,
            config,
            state: Pku2uState::Negotiate,
            encryption_params: EncryptionParams::default_for_client(),
            auth_identity: None,
            conversation_id: Uuid::new_v4(),
            auth_scheme: None,
            seq_number: 0,
            gss_seq_number: 0,
            remote_gss_seq_number: 0,
            request_nonce: None,
            channel_bindings: None,
            peer_certificate: None,
            peer_certificate_trusted: false,
            peer_name: None,
            #[cfg(test)]
            certificate_validation_time: None,
            // https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.3
            // Contains the nonce in the pkAuthenticator field in the request if the DH keys are NOT reused,
            // 0 otherwise.
            // generate dh parameters at the start in order to not waste time during authorization
            dh_parameters: generate_client_dh_parameters(&mut rand),
            negoex_messages: Vec::new(),
            gss_api_messages: Vec::new(),
            negoex_random,
            ticket_encryption_key: None,
        })
    }

    pub fn config(&self) -> &Pku2uConfig {
        &self.config
    }

    fn certificate_validation_time(&self) -> time::OffsetDateTime {
        #[cfg(test)]
        if let Some(validation_time) = self.certificate_validation_time {
            return validation_time;
        }

        time::OffsetDateTime::now_utc()
    }

    pub fn next_seq_number(&mut self) -> u32 {
        let seq_num = self.seq_number;
        self.seq_number += 1;

        seq_num
    }

    fn next_gss_seq_number(&mut self) -> u32 {
        let seq_num = self.gss_seq_number;
        self.gss_seq_number += 1;

        seq_num
    }

    fn is_client(&self) -> bool {
        matches!(self.mode, Pku2uMode::Client)
    }

    fn read_channel_bindings(&mut self, input: Option<&[SecurityBuffer]>) -> Result<()> {
        if let Some(input) = input
            && let Ok(buffer) = SecurityBuffer::find_buffer(input, BufferType::ChannelBindings)
        {
            self.channel_bindings = Some(ChannelBindings::from_bytes(&buffer.buffer)?);
        }

        Ok(())
    }

    /// Selects, among this side's configured credentials (the primary [`Pku2uConfig::p2p_certificate`]
    /// followed by [`Pku2uConfig::additional_credentials`]), the first one whose own issuer appears in
    /// `trusted_issuers`. The initiator calls this with the acceptor's `AcceptorMetaData` so a
    /// multi-identity client picks a credential issued by an authority the acceptor trusts. The acceptor
    /// validates the initiator certificate separately against `trusted_client_certificates`.
    /// A `trusted_issuers` is empty when the peer advertises no metadata, in which case the
    /// currently-configured credential is kept as-is.
    fn select_credential_for_metadata(&mut self, trusted_issuers: &[Pku2uNegoReqMetadata]) -> Result<()> {
        if trusted_issuers.is_empty() {
            return Ok(());
        }

        let accepts = |certificate: &Certificate| -> Result<bool> {
            let issuer = picky_asn1_der::to_vec(&certificate.tbs_certificate.issuer)?;
            Ok(trusted_issuers.iter().any(|trusted| trusted.inner.0.0 == issuer))
        };

        if accepts(&self.config.p2p_certificate)? {
            return Ok(());
        }

        let selected = self
            .config
            .additional_credentials
            .iter()
            .find_map(|credential| match accepts(&credential.certificate) {
                Ok(true) => Some(Ok(credential.clone())),
                Ok(false) => None,
                Err(error) => Some(Err(error)),
            })
            .transpose()?
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Pku2uCertFailure,
                    "none of the configured PKU2U certificates is trusted by the peer",
                )
            })?;
        self.config.p2p_certificate = selected.certificate;
        self.config.private_key = selected.private_key;

        Ok(())
    }

    fn generate_mic(&self, sequence_number: u64, data: &[u8]) -> Result<Vec<u8>> {
        let key = get_encryption_key(&self.encryption_params)?;
        let aes_size = self.encryption_params.aes_size().unwrap_or(AesSize::Aes256);

        crate::kerberos::utils::generate_mic_token(self.is_client(), sequence_number, data.to_vec(), key, &aes_size)
    }

    fn verify_mic(&self, sequence_number: u64, token: &[u8], data: &[u8]) -> Result<()> {
        crate::kerberos::utils::validate_mic_token(
            self.is_client(),
            sequence_number,
            token,
            &self.encryption_params,
            data,
        )
    }

    fn ensure_message_protection_ready(&self) -> Result<()> {
        match self.state {
            Pku2uState::PubKeyAuth | Pku2uState::Credentials | Pku2uState::Final => Ok(()),
            _ => Err(Error::new(
                ErrorKind::OutOfSequence,
                format!("Pku2u context is not established: current state: {:?}", self.state),
            )),
        }
    }

    fn wrap_flags(&self, sealed: bool) -> u8 {
        let mut flags = if sealed { WRAP_SEALED } else { 0 };
        if !self.is_client() {
            flags |= WRAP_SENT_BY_ACCEPTOR;
        }
        if self.encryption_params.sub_session_key.is_some() {
            flags |= WRAP_ACCEPTOR_SUBKEY;
        }
        flags
    }

    fn validate_wrap_flags(&self, flags: u8) -> Result<()> {
        let expected_sender = u8::from(self.is_client());
        if flags & WRAP_SENT_BY_ACCEPTOR != expected_sender {
            return Err(Error::new(
                ErrorKind::InvalidToken,
                "invalid PKU2U Wrap token SentByAcceptor flag",
            ));
        }

        let expected_subkey = if self.encryption_params.sub_session_key.is_some() {
            WRAP_ACCEPTOR_SUBKEY
        } else {
            0
        };
        if flags & WRAP_ACCEPTOR_SUBKEY != expected_subkey {
            return Err(Error::new(
                ErrorKind::InvalidToken,
                "invalid PKU2U Wrap token AcceptorSubkey flag",
            ));
        }

        Ok(())
    }
}

fn collect_writable_data(message: &[SecurityBufferRef<'_>]) -> Vec<u8> {
    SecurityBufferRef::buffers_of_type_and_flags(message, BufferType::Data, crate::SecurityBufferFlags::NONE).fold(
        Vec::new(),
        |mut data, buffer| {
            data.extend_from_slice(buffer.data());
            data
        },
    )
}

fn collect_wrap_input(message: &[SecurityBufferRef<'_>]) -> Result<Vec<u8>> {
    let mut input = SecurityBufferRef::buf_data(message, BufferType::Token)
        .unwrap_or_default()
        .to_vec();
    if let Ok(stream) = SecurityBufferRef::buf_data(message, BufferType::Stream) {
        input.extend_from_slice(stream);
    } else {
        input.extend_from_slice(&collect_writable_data(message));
    }
    Ok(input)
}

fn write_writable_data(data: &[u8], message: &mut [SecurityBufferRef<'_>]) -> Result<()> {
    if SecurityBufferRef::buf_data(message, BufferType::Stream).is_ok() {
        return save_decrypted_data(data, message);
    }

    let expected_len: usize =
        SecurityBufferRef::buffers_of_type_and_flags(message, BufferType::Data, crate::SecurityBufferFlags::NONE)
            .map(SecurityBufferRef::buf_len)
            .sum();
    if expected_len != data.len() {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            format!(
                "PKU2U message data length does not match writable buffers: expected {expected_len}, got {}",
                data.len()
            ),
        ));
    }

    let mut remaining = data;
    for buffer in
        SecurityBufferRef::buffers_of_type_and_flags_mut(message, BufferType::Data, crate::SecurityBufferFlags::NONE)
    {
        let (current, rest) = remaining.split_at(buffer.buf_len());
        buffer.write_data(current)?;
        remaining = rest;
    }

    Ok(())
}

fn validate_inner_wrap_header(wrap_token: &WrapToken, inner_header: &[u8]) -> Result<()> {
    let mut expected = wrap_token.header();
    expected[6..8].fill(0);
    if inner_header != expected {
        return Err(Error::new(
            ErrorKind::MessageAltered,
            "PKU2U Wrap token encrypted header does not match its outer header",
        ));
    }
    Ok(())
}

fn read_negoex_u32(buffer: &[u8], offset: usize) -> Result<u32> {
    let bytes = buffer
        .get(offset..offset + 4)
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "NEGOEX message is truncated"))?;
    Ok(u32::from_le_bytes(
        bytes.try_into().expect("slice has exactly four bytes"),
    ))
}

fn validate_negoex_vector(
    message: &[u8],
    descriptor_offset: usize,
    element_size: usize,
    payload_start: usize,
) -> Result<(usize, usize)> {
    let offset = usize::try_from(read_negoex_u32(message, descriptor_offset)?)
        .map_err(|_| Error::new(ErrorKind::InvalidToken, "NEGOEX vector offset does not fit into usize"))?;
    let count = usize::try_from(read_negoex_u32(message, descriptor_offset + 4)?)
        .map_err(|_| Error::new(ErrorKind::InvalidToken, "NEGOEX vector count does not fit into usize"))?;
    if count == 0 {
        if offset > message.len() {
            return Err(Error::new(
                ErrorKind::InvalidToken,
                "empty NEGOEX vector points outside its message",
            ));
        }
        return Ok((offset, count));
    }

    let byte_len = count
        .checked_mul(element_size)
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "NEGOEX vector length overflows"))?;
    let end = offset
        .checked_add(byte_len)
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "NEGOEX vector range overflows"))?;
    if offset < payload_start || end > message.len() {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "NEGOEX vector points outside its message",
        ));
    }

    Ok((offset, count))
}

fn validate_negoex_message(
    buffer: &[u8],
    expected_type: MessageType,
    expected_header_len: usize,
) -> Result<(&[u8], &[u8])> {
    if buffer.len() < NEGOEX_HEADER_LEN {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "NEGOEX message header is truncated",
        ));
    }

    let actual_type = read_negoex_u32(buffer, 8)?;
    if actual_type != u32::from(&expected_type) {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            format!("unexpected NEGOEX message type {actual_type}"),
        ));
    }

    let header_len = usize::try_from(read_negoex_u32(buffer, 16)?)
        .map_err(|_| Error::new(ErrorKind::InvalidToken, "NEGOEX header length does not fit into usize"))?;
    let message_len = usize::try_from(read_negoex_u32(buffer, 20)?)
        .map_err(|_| Error::new(ErrorKind::InvalidToken, "NEGOEX message length does not fit into usize"))?;
    if header_len != expected_header_len || message_len < header_len || message_len > buffer.len() {
        return Err(Error::new(ErrorKind::InvalidToken, "invalid NEGOEX message length"));
    }

    Ok((&buffer[..message_len], &buffer[message_len..]))
}

fn decode_nego_message(buffer: &[u8], expected_type: MessageType) -> Result<(Nego, &[u8])> {
    let (message, tail) = validate_negoex_message(buffer, expected_type, NEGOEX_NEGO_HEADER_LEN)?;
    validate_negoex_vector(message, 80, 16, NEGOEX_NEGO_HEADER_LEN)?;
    let (extensions_offset, extensions_count) = validate_negoex_vector(message, 88, 12, NEGOEX_NEGO_HEADER_LEN)?;
    for index in 0..extensions_count {
        let extension_offset = extensions_offset + index * 12;
        validate_negoex_vector(message, extension_offset + 4, 1, NEGOEX_NEGO_HEADER_LEN)?;
    }

    Ok((Nego::decode(message)?, tail))
}

fn decode_exchange_message(buffer: &[u8], expected_type: MessageType) -> Result<(Exchange, &[u8])> {
    let (message, tail) = validate_negoex_message(buffer, expected_type, NEGOEX_EXCHANGE_HEADER_LEN)?;
    validate_negoex_vector(message, 56, 1, NEGOEX_EXCHANGE_HEADER_LEN)?;
    Ok((Exchange::decode(message)?, tail))
}

fn decode_verify_message(buffer: &[u8]) -> Result<(Verify, &[u8])> {
    let (message, tail) = validate_negoex_message(buffer, MessageType::Verify, NEGOEX_VERIFY_HEADER_LEN)?;
    if read_negoex_u32(message, 56)? != 20 {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "invalid NEGOEX checksum header length",
        ));
    }
    validate_negoex_vector(message, 68, 1, NEGOEX_VERIFY_HEADER_LEN)?;
    Ok((Verify::decode(message)?, tail))
}

fn ensure_no_negoex_tail(tail: &[u8]) -> Result<()> {
    if tail.is_empty() {
        Ok(())
    } else {
        Err(Error::new(
            ErrorKind::InvalidToken,
            "unexpected trailing NEGOEX message",
        ))
    }
}

fn decrypt_sealed_wrap(
    wrap_token: &WrapToken,
    key: &[u8],
    key_usage: i32,
    message: &mut [SecurityBufferRef<'_>],
    cipher: &dyn picky_krb::crypto::Cipher,
) -> Result<DecryptionFlags> {
    let mut encrypted = wrap_token.checksum.clone();
    if encrypted.is_empty() {
        return Err(Error::new(ErrorKind::DecryptFailure, "empty PKU2U sealed Wrap token"));
    }
    let encrypted_len = encrypted.len();
    encrypted.rotate_left((usize::from(wrap_token.rrc) + usize::from(wrap_token.ec)) % encrypted_len);

    let DecryptWithoutChecksum {
        plaintext: decrypted,
        confounder,
        checksum,
        ki: _,
    } = cipher.decrypt_no_checksum(key, key_usage, &encrypted)?;
    let suffix_len = usize::from(wrap_token.ec) + WrapToken::header_len();
    if decrypted.len() < suffix_len {
        return Err(Error::new(
            ErrorKind::DecryptFailure,
            "PKU2U sealed Wrap token is shorter than its EC and header",
        ));
    }

    let plaintext_len = decrypted.len() - suffix_len;
    let (plaintext, filler_and_header) = decrypted.split_at(plaintext_len);
    let (filler, inner_header) = filler_and_header.split_at(usize::from(wrap_token.ec));

    let has_stream = SecurityBufferRef::buf_data(message, BufferType::Stream).is_ok();
    let mut plaintext_offset = 0;
    let mut to_sign = if has_stream {
        let mut data = confounder;
        data.extend_from_slice(plaintext);
        plaintext_offset = plaintext.len();
        data
    } else {
        SecurityBufferRef::buffers_of_type(message, BufferType::Data).fold(confounder, |mut data, buffer| {
            if buffer.buffer_flags().intersects(
                crate::SecurityBufferFlags::SECBUFFER_READONLY
                    | crate::SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM,
            ) {
                data.extend_from_slice(buffer.data());
            } else {
                let end = plaintext_offset + buffer.buf_len();
                if let Some(plaintext) = plaintext.get(plaintext_offset..end) {
                    data.extend_from_slice(plaintext);
                    plaintext_offset = end;
                }
            }
            data
        })
    };
    let buffer_lengths_match = plaintext_offset == plaintext.len();
    to_sign.extend_from_slice(filler_and_header);

    if cipher.encryption_checksum(key, key_usage, &to_sign)? != checksum {
        return Err(Error::new(
            ErrorKind::MessageAltered,
            "invalid PKU2U sealed Wrap token checksum",
        ));
    }
    if !buffer_lengths_match {
        return Err(Error::new(ErrorKind::MessageAltered, "invalid PKU2U sealed Wrap token"));
    }
    if filler.iter().any(|byte| *byte != 0) {
        return Err(Error::new(ErrorKind::MessageAltered, "invalid PKU2U sealed Wrap token"));
    }
    validate_inner_wrap_header(wrap_token, inner_header)?;

    write_writable_data(plaintext, message)?;
    Ok(DecryptionFlags::empty())
}

fn decrypt_integrity_only_wrap(
    wrap_token: &WrapToken,
    key: &[u8],
    aes_size: &AesSize,
    key_usage: i32,
    message: &mut [SecurityBufferRef<'_>],
) -> Result<DecryptionFlags> {
    let mut payload = wrap_token.checksum.clone();
    if payload.is_empty() {
        return Err(Error::new(
            ErrorKind::DecryptFailure,
            "empty PKU2U integrity-only Wrap token",
        ));
    }
    let payload_len = payload.len();
    payload.rotate_left(usize::from(wrap_token.rrc) % payload_len);

    let checksum_len = usize::from(wrap_token.ec);
    if payload.len() < checksum_len {
        return Err(Error::new(
            ErrorKind::DecryptFailure,
            "PKU2U integrity-only Wrap token is shorter than its checksum",
        ));
    }
    let plaintext_len = payload.len() - checksum_len;
    let (plaintext, received_checksum) = payload.split_at(plaintext_len);

    let mut header = wrap_token.header();
    header[4..8].fill(0);
    let has_stream = SecurityBufferRef::buf_data(message, BufferType::Stream).is_ok();
    let mut plaintext_offset = 0;
    let mut to_sign = if has_stream {
        plaintext_offset = plaintext.len();
        plaintext.to_vec()
    } else {
        SecurityBufferRef::buffers_of_type(message, BufferType::Data).fold(Vec::new(), |mut data, buffer| {
            if buffer.buffer_flags().intersects(
                crate::SecurityBufferFlags::SECBUFFER_READONLY
                    | crate::SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM,
            ) {
                data.extend_from_slice(buffer.data());
            } else {
                let end = plaintext_offset + buffer.buf_len();
                if let Some(plaintext) = plaintext.get(plaintext_offset..end) {
                    data.extend_from_slice(plaintext);
                    plaintext_offset = end;
                }
            }
            data
        })
    };
    if plaintext_offset != plaintext.len() {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "PKU2U integrity-only data does not match writable buffer lengths",
        ));
    }
    to_sign.extend_from_slice(&header);

    let calculated_checksum = checksum_sha_aes(key, key_usage, &to_sign, aes_size)?;
    if calculated_checksum.len() != checksum_len {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            format!(
                "invalid PKU2U integrity-only checksum length: expected {}, got {checksum_len}",
                calculated_checksum.len()
            ),
        ));
    }
    if calculated_checksum.as_slice() != received_checksum {
        return Err(Error::new(
            ErrorKind::MessageAltered,
            "invalid PKU2U integrity-only Wrap token checksum",
        ));
    }

    write_writable_data(plaintext, message)?;
    Ok(DecryptionFlags::WRAP_NO_ENCRYPT)
}

impl Sspi for Pku2u {
    #[instrument(level = "debug", ret, fields(state = ?self.state), skip_all)]
    fn complete_auth_token(&mut self, _token: &mut [SecurityBuffer]) -> Result<SecurityStatus> {
        Ok(SecurityStatus::Ok)
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self, flags))]
    fn encrypt_message(
        &mut self,
        flags: EncryptionFlags,
        message: &mut [SecurityBufferRef<'_>],
    ) -> Result<SecurityStatus> {
        self.ensure_message_protection_ready()?;
        trace!(encryption_params = ?self.encryption_params);

        SecurityBufferRef::find_buffer(message, BufferType::Token)?;
        let plaintext = collect_writable_data(message);
        let cipher = self
            .encryption_params
            .encryption_type
            .as_ref()
            .unwrap_or(&DEFAULT_ENCRYPTION_TYPE)
            .cipher();
        let sequence_number = self.next_gss_seq_number();
        let key = get_encryption_key(&self.encryption_params)?;
        let key_usage = self.encryption_params.sspi_encrypt_key_usage;

        let mut wrap_token = WrapToken::with_seq_number(u64::from(sequence_number));
        let integrity_only = flags.contains(EncryptionFlags::WRAP_NO_ENCRYPT);
        wrap_token.flags = self.wrap_flags(!integrity_only);

        let raw_wrap_token = if integrity_only {
            let aes_size = self.encryption_params.aes_size().ok_or_else(|| {
                Error::new(
                    ErrorKind::UnsupportedFunction,
                    "PKU2U integrity-only Wrap tokens require an AES session key",
                )
            })?;
            let mut to_sign =
                SecurityBufferRef::buffers_of_type(message, BufferType::Data).fold(Vec::new(), |mut data, buffer| {
                    data.extend_from_slice(buffer.data());
                    data
                });
            to_sign.extend_from_slice(&wrap_token.header());

            let checksum = checksum_sha_aes(key.as_ref(), key_usage, &to_sign, &aes_size)?;
            let checksum_len = u16::try_from(checksum.len())?;
            let mut payload = plaintext;
            payload.extend_from_slice(&checksum);
            payload.rotate_right(usize::from(INTEGRITY_ONLY_RRC));

            wrap_token.ec = checksum_len;
            wrap_token.rrc = INTEGRITY_ONLY_RRC;
            wrap_token.set_checksum(payload);

            let mut encoded = Vec::with_capacity(WrapToken::header_len() + wrap_token.checksum.len());
            wrap_token.encode(&mut encoded)?;
            encoded
        } else {
            wrap_token.ec = ENCRYPTED_WRAP_EC;

            let mut payload = plaintext;
            payload.resize(payload.len() + usize::from(wrap_token.ec), 0);
            payload.extend_from_slice(&wrap_token.header());

            let EncryptWithoutChecksum {
                mut encrypted,
                confounder,
                ki: _,
            } = cipher.encrypt_no_checksum(key.as_ref(), key_usage, &payload)?;

            let mut to_sign =
                SecurityBufferRef::buffers_of_type(message, BufferType::Data).fold(confounder, |mut data, buffer| {
                    data.extend_from_slice(buffer.data());
                    data
                });
            to_sign.resize(to_sign.len() + usize::from(wrap_token.ec), 0);
            to_sign.extend_from_slice(&wrap_token.header());

            encrypted.extend_from_slice(&cipher.encryption_checksum(key.as_ref(), key_usage, &to_sign)?);
            encrypted.rotate_right(usize::from(RRC + wrap_token.ec));
            wrap_token.rrc = RRC;
            wrap_token.set_checksum(encrypted);

            let mut encoded = Vec::with_capacity(WrapToken::header_len() + wrap_token.checksum.len());
            wrap_token.encode(&mut encoded)?;
            encoded
        };

        let token_len = if integrity_only {
            WrapToken::header_len() + usize::from(wrap_token.ec)
        } else {
            PKU2U_SECURITY_TRAILER
        };
        if raw_wrap_token.len() < token_len {
            return Err(Error::new(ErrorKind::EncryptFailure, "PKU2U Wrap token is too short"));
        }
        let (token, data) = raw_wrap_token.split_at(token_len);
        SecurityBufferRef::find_buffer_mut(message, BufferType::Token)?.write_data(token)?;
        write_writable_data(data, message)?;

        Ok(SecurityStatus::Ok)
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn decrypt_message(&mut self, message: &mut [SecurityBufferRef<'_>]) -> Result<DecryptionFlags> {
        self.ensure_message_protection_ready()?;
        trace!(encryption_params = ?self.encryption_params);

        let encrypted = collect_wrap_input(message)?;
        let cipher = self
            .encryption_params
            .encryption_type
            .as_ref()
            .unwrap_or(&DEFAULT_ENCRYPTION_TYPE)
            .cipher();

        let key = get_encryption_key(&self.encryption_params)?;
        let key_usage = self.encryption_params.sspi_decrypt_key_usage;

        let wrap_token = WrapToken::decode(encrypted.as_slice())?;
        self.validate_wrap_flags(wrap_token.flags)?;
        if wrap_token.seq_num != u64::from(self.remote_gss_seq_number) {
            return Err(Error::new(
                ErrorKind::OutOfSequence,
                format!(
                    "invalid PKU2U Wrap token sequence number: expected {}, got {}",
                    self.remote_gss_seq_number, wrap_token.seq_num
                ),
            ));
        }

        let decryption_flags = if wrap_token.flags & WRAP_SEALED == 0 {
            let aes_size = self.encryption_params.aes_size().ok_or_else(|| {
                Error::new(
                    ErrorKind::UnsupportedFunction,
                    "PKU2U integrity-only Wrap tokens require an AES session key",
                )
            })?;
            decrypt_integrity_only_wrap(&wrap_token, key.as_ref(), &aes_size, key_usage, message)?
        } else {
            decrypt_sealed_wrap(&wrap_token, key.as_ref(), key_usage, message, cipher.as_ref())?
        };
        self.remote_gss_seq_number = self.remote_gss_seq_number.wrapping_add(1);

        match self.state {
            Pku2uState::PubKeyAuth => {
                self.state = Pku2uState::Credentials;
            }
            Pku2uState::Credentials => {
                self.state = Pku2uState::Final;
            }
            _ => {}
        }

        Ok(decryption_flags)
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn query_context_sizes(&mut self) -> Result<ContextSizes> {
        Ok(ContextSizes {
            max_token: PACKAGE_INFO.max_token_len,
            max_signature: 28,
            block: 1,
            security_trailer: PKU2U_SECURITY_TRAILER.try_into()?,
        })
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn query_context_names(&mut self) -> Result<ContextNames> {
        if let Some(username) = &self.peer_name {
            return Ok(ContextNames {
                username: username.clone(),
            });
        }

        if let Some(identity_buffers) = &self.auth_identity {
            let identity =
                AuthIdentity::try_from(identity_buffers).map_err(|e| Error::new(ErrorKind::InvalidParameter, e))?;

            Ok(ContextNames {
                username: identity.username,
            })
        } else {
            Err(Error::new(
                ErrorKind::NoCredentials,
                String::from("Requested Names, but no credentials were provided"),
            ))
        }
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn query_context_package_info(&mut self) -> Result<PackageInfo> {
        crate::query_security_package_info(SecurityPackageType::Pku2u)
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn query_context_cert_trust_status(&mut self) -> Result<CertTrustStatus> {
        self.ensure_message_protection_ready()?;
        Ok(if self.peer_certificate_trusted {
            CertTrustStatus {
                error_status: CertTrustErrorStatus::NO_ERROR,
                info_status: CertTrustInfoStatus::IS_PEER_TRUSTED,
            }
        } else {
            CertTrustStatus {
                error_status: CertTrustErrorStatus::IS_UNTRUSTED_ROOT,
                info_status: CertTrustInfoStatus::empty(),
            }
        })
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn query_context_remote_cert(&mut self) -> Result<CertContext> {
        self.ensure_message_protection_ready()?;
        let certificate = self
            .peer_certificate
            .clone()
            .ok_or_else(|| Error::new(ErrorKind::CertificateUnknown, "PKU2U peer certificate is not available"))?;
        Ok(CertContext {
            encoding_type: CertEncodingType::X509AsnEncoding,
            raw_cert: picky_asn1_der::to_vec(&certificate)?,
            cert: certificate,
        })
    }

    #[instrument(level = "debug", fields(state = ?self.state), skip(self))]
    fn query_context_session_key(&self) -> Result<crate::SessionKeys> {
        let session_key = get_encryption_key(&self.encryption_params)?;

        Ok(crate::SessionKeys {
            session_key: session_key.clone(),
        })
    }

    fn change_password(&mut self, _: ChangePassword<'_>) -> Result<crate::generator::GeneratorChangePassword<'_>> {
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "Pku2u does not support change pasword",
        ))
    }

    fn make_signature(
        &mut self,
        _flags: u32,
        message: &mut [SecurityBufferRef<'_>],
        sequence_number: u32,
    ) -> Result<()> {
        let data = SecurityBufferRef::buffers_of_type(message, BufferType::Data).fold(Vec::new(), |mut acc, buffer| {
            acc.extend_from_slice(buffer.data());
            acc
        });
        let signature = self.generate_mic(sequence_number.into(), &data)?;
        SecurityBufferRef::find_buffer_mut(message, BufferType::Token)?.write_data(&signature)
    }

    fn verify_signature(&mut self, message: &mut [SecurityBufferRef<'_>], sequence_number: u32) -> Result<u32> {
        let token = SecurityBufferRef::find_buffer(message, BufferType::Token)?
            .data()
            .to_vec();
        let data = SecurityBufferRef::buffers_of_type(message, BufferType::Data).fold(Vec::new(), |mut acc, buffer| {
            acc.extend_from_slice(buffer.data());
            acc
        });
        self.verify_mic(sequence_number.into(), &token, &data)?;

        Ok(0)
    }
}

impl SspiImpl for Pku2u {
    type CredentialsHandle = Option<AuthIdentityBuffers>;

    type AuthenticationData = AuthIdentity;

    #[instrument(level = "trace", ret, fields(state = ?self.state), skip(self))]
    fn acquire_credentials_handle_impl(
        &mut self,
        builder: crate::builders::FilledAcquireCredentialsHandle<'_, Self::CredentialsHandle, Self::AuthenticationData>,
    ) -> Result<AcquireCredentialsHandleResult<Self::CredentialsHandle>> {
        if builder.credential_use == CredentialUse::Outbound && builder.auth_data.is_none() {
            return Err(Error::new(
                ErrorKind::NoCredentials,
                String::from("The client must specify the auth data"),
            ));
        }

        self.auth_identity = builder.auth_data.cloned().map(AuthIdentityBuffers::from);

        Ok(AcquireCredentialsHandleResult {
            credentials_handle: self.auth_identity.clone(),
            expiry: None,
        })
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self, builder))]
    fn accept_security_context_impl<'a>(
        &'a mut self,
        builder: FilledAcceptSecurityContext<'a, Self::CredentialsHandle>,
    ) -> Result<GeneratorAcceptSecurityContext<'a>> {
        Ok(GeneratorAcceptSecurityContext::new(move |mut yield_point| async move {
            self.accept_security_context_impl(&mut yield_point, builder).await
        }))
    }

    fn initialize_security_context_impl<'ctx, 'b, 'g>(
        &'ctx mut self,
        builder: &'b mut crate::builders::FilledInitializeSecurityContext<'ctx, 'ctx, Self::CredentialsHandle>,
    ) -> Result<GeneratorInitSecurityContext<'g>>
    where
        'ctx: 'g,
        'b: 'g,
    {
        Ok(self.initialize_security_context_impl(builder).into())
    }
}

impl Pku2u {
    pub(crate) async fn accept_security_context_impl(
        &mut self,
        yield_point: &mut YieldPointLocal,
        builder: FilledAcceptSecurityContext<'_, <Self as SspiImpl>::CredentialsHandle>,
    ) -> Result<AcceptSecurityContextResult> {
        server::accept_security_context(self, yield_point, builder).await
    }

    #[instrument(ret, level = "debug", fields(state = ?self.state), skip_all)]
    pub(crate) fn initialize_security_context_impl(
        &mut self,
        builder: &mut crate::builders::FilledInitializeSecurityContext<'_, '_, <Self as SspiImpl>::CredentialsHandle>,
    ) -> Result<InitializeSecurityContextResult> {
        trace!(?builder);
        self.read_channel_bindings(builder.input.as_deref())?;

        let status = match self.state {
            Pku2uState::Negotiate => {
                let auth_scheme = Uuid::from_str(DEFAULT_NEGOEX_AUTH_SCHEME).unwrap();

                let mut mech_token = Vec::new();

                let snames = check_if_empty!(builder.target_name, "service target name is not provided")
                    .split('/')
                    .collect::<Vec<_>>();
                debug!(names = ?snames, "Service principal names");

                let nego = Nego::new(
                    MessageType::InitiatorNego,
                    self.conversation_id,
                    self.next_seq_number(),
                    self.negoex_random,
                    vec![auth_scheme],
                    vec![],
                );
                nego.encode(&mut mech_token)?;

                let exchange = Exchange::new(
                    MessageType::InitiatorMetaData,
                    self.conversation_id,
                    self.next_seq_number(),
                    auth_scheme,
                    picky_asn1_der::to_vec(&generate_pku2u_nego_req(&snames, &self.config)?)?,
                );
                exchange.encode(&mut mech_token)?;

                self.negoex_messages.extend_from_slice(&mech_token);

                let encoded_neg_token_init = picky_asn1_der::to_vec(&generate_neg_token_init(mech_token)?)?;

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
                output_token.buffer.write_all(&encoded_neg_token_init)?;

                self.state = Pku2uState::Preauthentication;

                SecurityStatus::ContinueNeeded
            }
            Pku2uState::Preauthentication => {
                let input = builder
                    .input
                    .as_ref()
                    .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Input buffers must be specified"))?;
                let input_token = SecurityBuffer::find_buffer(input, BufferType::Token)?;

                let neg_token_targ: NegTokenTarg1 = picky_asn1_der::from_bytes(&input_token.buffer)?;
                let buffer = neg_token_targ
                    .0
                    .response_token
                    .0
                    .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Missing response_token in NegTokenTarg"))?
                    .0
                    .0;

                self.negoex_messages.extend_from_slice(&buffer);

                let (acceptor_nego, acceptor_exchange_data) = decode_nego_message(&buffer, MessageType::AcceptorNego)?;
                trace!(?acceptor_nego, "NEGOEX ACCEPTOR NEGOTIATE");

                check_conversation_id!(acceptor_nego.header.conversation_id, self.conversation_id);
                check_sequence_number!(acceptor_nego.header.sequence_num, self.next_seq_number());

                // We support only one auth scheme. So the server must choose it otherwise it's an invalid behaviour
                if let Some(auth_scheme) = acceptor_nego.auth_schemes.first() {
                    if *auth_scheme == Uuid::from_str(DEFAULT_NEGOEX_AUTH_SCHEME).unwrap() {
                        self.auth_scheme = Some(*auth_scheme);
                    } else {
                        return Err(Error::new(
                            ErrorKind::InvalidToken,
                            format!(
                                "The server selected unsupported auth scheme {auth_scheme:?}. The only one supported auth scheme: {DEFAULT_NEGOEX_AUTH_SCHEME}"
                            ),
                        ));
                    }
                } else {
                    return Err(Error::new(
                        ErrorKind::InvalidToken,
                        "Server didn't send any auth scheme",
                    ));
                }

                let (acceptor_exchange, tail) =
                    decode_exchange_message(acceptor_exchange_data, MessageType::AcceptorMetaData)?;
                ensure_no_negoex_tail(tail)?;
                trace!(?acceptor_exchange, "NEGOEX ACCEPTOR EXCHANGE");

                check_conversation_id!(acceptor_exchange.header.conversation_id, self.conversation_id);
                check_sequence_number!(acceptor_exchange.header.sequence_num, self.next_seq_number());
                check_auth_scheme!(acceptor_exchange.auth_scheme, self.auth_scheme);
                let metadata: Pku2uNegoRep = picky_asn1_der::from_bytes(&acceptor_exchange.exchange)?;
                self.select_credential_for_metadata(&metadata.metadata.0.0)?;

                let mut mech_token = Vec::new();

                let snames = check_if_empty!(builder.target_name, "service target name is not provided")
                    .split('/')
                    .collect::<Vec<_>>();
                debug!(names = ?snames, "Service principal names");

                let next_seq_number = self.next_seq_number();
                let mut rng = StdRng::try_from_rng(&mut SysRng)?;
                let request_nonce = generate_nonce(&mut rng);
                self.request_nonce = Some(request_nonce);
                let kdc_req_body = generate_as_req_kdc_body(&GenerateAsReqOptions {
                    realm: WELLKNOWN_REALM,
                    username: &generate_as_req_username_from_certificate(&self.config.p2p_certificate)?,
                    cname_type: 0x80,
                    snames: &snames,
                    nonce: request_nonce,
                    hostname: &self.config.client_hostname,
                    context_requirements: builder.context_requirements,
                })?;
                let private_key = self.config.private_key.clone();
                let pa_datas = generate_pa_datas_for_as_req(&mut GenerateAsPaDataOptions {
                    p2p_cert: self.config.p2p_certificate.clone(),
                    kdc_req_body: &kdc_req_body,
                    dh_parameters: self.dh_parameters.clone(),
                    sign_data: Box::new(move |data_to_sign| {
                        private_key.sign(data_to_sign).map_err(|err| {
                            Error::new(
                                ErrorKind::InternalError,
                                format!("Cannot calculate signer info signature: {err:?}"),
                            )
                        })
                    }),
                    with_pre_auth: true,
                    authenticator_nonce: request_nonce,
                })?;
                let as_req = generate_as_req(pa_datas, kdc_req_body);

                let exchange_data = picky_asn1_der::to_vec(&generate_neg(as_req, AS_REQ_TOKEN_ID))?;
                self.gss_api_messages.extend_from_slice(&exchange_data);

                let exchange = Exchange::new(
                    MessageType::ApRequest,
                    self.conversation_id,
                    next_seq_number,
                    check_if_empty!(self.auth_scheme, "auth scheme is not set"),
                    exchange_data,
                );
                exchange.encode(&mut mech_token)?;

                self.negoex_messages.extend_from_slice(&mech_token);

                let response_token = picky_asn1_der::to_vec(&generate_neg_token_targ(mech_token, false)?)?;

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
                output_token.buffer.write_all(&response_token)?;

                self.state = Pku2uState::AsExchange;

                SecurityStatus::ContinueNeeded
            }
            Pku2uState::AsExchange => {
                let input = builder
                    .input
                    .as_ref()
                    .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Input buffers must be specified"))?;
                let input_token = SecurityBuffer::find_buffer(input, BufferType::Token)?;

                let neg_token_targ: NegTokenTarg1 = picky_asn1_der::from_bytes(&input_token.buffer)?;
                let buffer = neg_token_targ
                    .0
                    .response_token
                    .0
                    .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Missing response_token in NegTokenTarg"))?
                    .0
                    .0;

                self.negoex_messages.extend_from_slice(&buffer);

                let (acceptor_exchange, tail) = decode_exchange_message(&buffer, MessageType::ApRequest)?;
                ensure_no_negoex_tail(tail)?;
                trace!(?acceptor_exchange, "NEGOEX ACCEPTOR EXCHANGE MESSAGE");

                check_conversation_id!(acceptor_exchange.header.conversation_id, self.conversation_id);
                check_sequence_number!(acceptor_exchange.header.sequence_num, self.next_seq_number());
                check_auth_scheme!(acceptor_exchange.auth_scheme, self.auth_scheme);

                self.gss_api_messages.extend_from_slice(&acceptor_exchange.exchange);

                let (as_rep, _): (picky_krb::data_types::KrbResult<AsRep>, _) =
                    extract_krb_result(&acceptor_exchange.exchange)?;
                let as_rep = as_rep.map_err(Error::from)?;

                let dh_rep_info = match extract_pa_pk_as_rep(&as_rep)? {
                    PaPkAsRep::DhInfo(dh) => dh.0,
                    PaPkAsRep::EncKeyPack(_) => {
                        return Err(Error::new(
                            ErrorKind::OperationNotSupported,
                            "encKeyPack is not supported for the PA-PK-AS-REP",
                        ));
                    }
                };

                let server_nonce = extract_server_nonce(&dh_rep_info)?;
                self.dh_parameters.server_nonce = Some(server_nonce);

                let signed_data: SignedData = picky_asn1_der::from_bytes(&dh_rep_info.dh_signed_data.0)?;

                let rsa_public_key = validate_server_p2p_certificate(&signed_data)?;
                validate_signed_data(&signed_data, &rsa_public_key)?;
                let server_certificate = extract_signing_certificate(&signed_data)?;
                validate_peer_p2p_certificate(&server_certificate, self.certificate_validation_time())?;
                if !self.config.trusted_server_certificates.is_empty()
                    && !self.config.trusted_server_certificates.contains(&server_certificate)
                {
                    return Err(Error::new(
                        ErrorKind::Pku2uCertFailure,
                        "PKU2U acceptor certificate is not trusted",
                    ));
                }
                self.peer_certificate_trusted = self.config.trusted_server_certificates.contains(&server_certificate);
                self.peer_certificate = Some(server_certificate);

                let public_key = extract_server_dh_public_key(&signed_data)?;
                self.dh_parameters.other_public_key = Some(public_key);

                self.encryption_params.encryption_type =
                    Some(CipherSuite::try_from(as_rep.0.enc_part.0.etype.0.0.as_slice())?);

                let session_key = generate_key(
                    check_if_empty!(self.dh_parameters.other_public_key.as_ref(), "dh public key is not set"),
                    &self.dh_parameters.private_key,
                    &self.dh_parameters.modulus,
                    Some(DhNonce {
                        client_nonce: check_if_empty!(
                            self.dh_parameters.client_nonce.as_ref(),
                            "dh client none is not set"
                        ),
                        server_nonce: check_if_empty!(
                            self.dh_parameters.server_nonce.as_ref(),
                            "dh server nonce is not set"
                        ),
                    }),
                    check_if_empty!(
                        self.encryption_params.encryption_type.as_ref(),
                        "encryption type is not set"
                    )
                    .cipher()
                    .as_ref(),
                )?;
                trace!(?session_key, "Session key generated from DH components");

                let (session_key, response_nonce) =
                    extract_session_key_and_nonce_from_as_rep(&as_rep, &session_key, &self.encryption_params)?;
                let request_nonce = self
                    .request_nonce
                    .take()
                    .ok_or_else(|| Error::new(ErrorKind::OutOfSequence, "PKU2U AS-REQ nonce is not set"))?;
                if response_nonce != request_nonce {
                    return Err(Error::new(
                        ErrorKind::MessageAltered,
                        format!("PKU2U AS-REP nonce mismatch: expected {request_nonce}, got {response_nonce}"),
                    ));
                }
                self.encryption_params.session_key = Some(session_key);

                let exchange_seq_number = self.next_seq_number();
                let verify_seq_number = self.next_seq_number();
                self.gss_seq_number = exchange_seq_number;

                let enc_type = self
                    .encryption_params
                    .encryption_type
                    .as_ref()
                    .unwrap_or(&DEFAULT_ENCRYPTION_TYPE);
                let checksum_suite = enc_type.cipher().checksum_type();
                let mut rand = StdRng::try_from_rng(&mut SysRng)?;
                let authenticator_sub_key = generate_random_symmetric_key(enc_type, &mut rand);
                let mut checksum_value = ChecksumValues::default();
                checksum_value.set_flags(builder.context_requirements.into());

                let authenticator = generate_authenticator(GenerateAuthenticatorOptions {
                    kdc_rep: &as_rep.0,
                    seq_num: Some(exchange_seq_number),
                    sub_key: Some(EncKey {
                        key_type: enc_type.clone(),
                        key_value: authenticator_sub_key.clone(),
                    }),
                    checksum: Some(ChecksumOptions {
                        checksum_type: AUTHENTICATOR_CHECKSUM_TYPE.to_vec(),
                        checksum_value,
                    }),
                    channel_bindings: self.channel_bindings.as_ref(),
                    extensions: vec![generate_authenticator_extension(
                        &authenticator_sub_key,
                        &self.gss_api_messages,
                        &checksum_suite,
                    )?],
                })?;

                let ap_req = generate_ap_req(
                    as_rep.0.ticket.0,
                    check_if_empty!(self.encryption_params.session_key.as_ref(), "session key is not set"),
                    &authenticator,
                    &self.encryption_params,
                    builder.context_requirements.into(),
                )?;

                let mut mech_token = Vec::new();

                let exchange = Exchange::new(
                    MessageType::ApRequest,
                    self.conversation_id,
                    exchange_seq_number,
                    check_if_empty!(self.auth_scheme, "auth_scheme is not set"),
                    picky_asn1_der::to_vec(&generate_neg(ap_req, AP_REQ_TOKEN_ID))?,
                );
                exchange.encode(&mut mech_token)?;

                exchange.encode(&mut self.negoex_messages)?;

                let verify = Verify::new(
                    MessageType::Verify,
                    self.conversation_id,
                    verify_seq_number,
                    check_if_empty!(self.auth_scheme, "auth_scheme is not set"),
                    u32::from(&checksum_suite),
                    checksum_suite
                        .hasher()
                        .checksum(&authenticator_sub_key, INITIATOR_SIGN, &self.negoex_messages)?,
                );
                verify.encode(&mut mech_token)?;

                verify.encode(&mut self.negoex_messages)?;

                let encoded_neg_token_targ = picky_asn1_der::to_vec(&generate_neg_token_targ(mech_token, false)?)?;

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
                output_token.buffer.write_all(&encoded_neg_token_targ)?;

                self.state = Pku2uState::ApExchange;

                SecurityStatus::ContinueNeeded
            }
            Pku2uState::ApExchange => {
                let input = builder
                    .input
                    .as_ref()
                    .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Input buffers must be specified"))?;
                let input_token = SecurityBuffer::find_buffer(input, BufferType::Token)?;

                let neg_token_targ: NegTokenTarg1 = picky_asn1_der::from_bytes(&input_token.buffer)?;

                let buffer = neg_token_targ
                    .0
                    .response_token
                    .0
                    .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Missing response_token in NegTokenTarg"))?
                    .0
                    .0;

                let (acceptor_exchange, acceptor_verify_data) =
                    decode_exchange_message(&buffer, MessageType::ApRequest)?;
                trace!(?acceptor_exchange, "NEGOEX ACCEPTOR EXCHANGE MESSAGE");

                check_conversation_id!(acceptor_exchange.header.conversation_id, self.conversation_id);
                check_sequence_number!(acceptor_exchange.header.sequence_num, self.next_seq_number());
                check_auth_scheme!(acceptor_exchange.auth_scheme, self.auth_scheme);

                let exchange_message_len = buffer.len() - acceptor_verify_data.len();
                self.negoex_messages.extend_from_slice(&buffer[0..exchange_message_len]);

                let (acceptor_verify, tail) = decode_verify_message(acceptor_verify_data)?;
                ensure_no_negoex_tail(tail)?;
                trace!(?acceptor_exchange, "NEGOEX ACCEPTOR VERIFY MESSAGE");

                check_conversation_id!(acceptor_verify.header.conversation_id, self.conversation_id);
                check_sequence_number!(acceptor_verify.header.sequence_num, self.next_seq_number());
                check_auth_scheme!(acceptor_verify.auth_scheme, self.auth_scheme);

                let (ap_rep, _): (ApRep, _) = extract_krb_rep(&acceptor_exchange.exchange)?;

                let ap_rep_enc_part = decrypt_ap_rep(
                    &ap_rep,
                    check_if_empty!(self.encryption_params.session_key.as_ref(), "session key is not set"),
                    &self.encryption_params,
                )?;
                let sub_session_key = extract_sub_session_key_from_ap_rep(&ap_rep_enc_part)?;
                self.remote_gss_seq_number = extract_seq_number_from_ap_rep(&ap_rep_enc_part)?;

                self.encryption_params.sub_session_key = Some(sub_session_key);

                let checksum_type: usize = acceptor_verify.checksum.checksum_type.try_into().map_err(|_| {
                    Error::new(
                        ErrorKind::InvalidToken,
                        "NEGOEX checksum type is too big to fit into usize",
                    )
                })?;
                let checksum_suite = ChecksumSuite::try_from(checksum_type)?;
                let expected_checksum_suite = self
                    .encryption_params
                    .encryption_type
                    .as_ref()
                    .unwrap_or(&DEFAULT_ENCRYPTION_TYPE)
                    .cipher()
                    .checksum_type();
                if checksum_suite != expected_checksum_suite {
                    return Err(Error::new(
                        ErrorKind::InvalidToken,
                        format!(
                            "invalid NEGOEX checksum type: expected {expected_checksum_suite:?}, got {checksum_suite:?}"
                        ),
                    ));
                }
                let acceptor_checksum = checksum_suite.hasher().checksum(
                    check_if_empty!(
                        self.encryption_params.sub_session_key.as_ref(),
                        "sub-session key is not set"
                    )
                    .as_ref(),
                    ACCEPTOR_SIGN,
                    &self.negoex_messages,
                )?;
                if acceptor_verify.checksum.checksum_value != acceptor_checksum {
                    return Err(Error::new(
                        ErrorKind::MessageAltered,
                        "bad verify message signature from server",
                    ));
                }

                self.state = Pku2uState::PubKeyAuth;

                SecurityStatus::Ok
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::OutOfSequence,
                    format!("Got wrong PKU2U state: {:?}", self.state),
                ));
            }
        };

        trace!(output_buffers = ?builder.output);

        Ok(InitializeSecurityContextResult {
            status,
            flags: ClientResponseFlags::empty(),
            expiry: None,
        })
    }
}

impl SspiEx for Pku2u {
    #[instrument(level = "trace", ret, fields(state = ?self.state), skip(self))]
    fn custom_set_auth_identity(&mut self, identity: Self::AuthenticationData) -> Result<()> {
        self.auth_identity = Some(identity.into());

        Ok(())
    }

    fn verify_mic_token(&mut self, token: &[u8], data: &[u8], _: crate::private::Sealed) -> Result<()> {
        self.verify_mic(self.remote_gss_seq_number.into(), token, data)?;
        self.remote_gss_seq_number = self.remote_gss_seq_number.wrapping_add(1);
        Ok(())
    }

    fn generate_mic_token(&mut self, data: &[u8], _: crate::private::Sealed) -> Result<Vec<u8>> {
        let sequence_number = self.next_gss_seq_number();
        self.generate_mic(sequence_number.into(), data)
    }
}

#[cfg(feature = "__test-data")]
#[doc(hidden)]
pub fn fuzz_token(data: &[u8]) {
    use std::io::Cursor;

    use picky_krb::gss_api::{ApplicationTag0, GssApiNegInit, KrbMessage, MicToken};
    use picky_krb::messages::{ApReq, AsReq, KrbError};

    if let Ok(token) = picky_asn1_der::from_bytes::<ApplicationTag0<GssApiNegInit>>(data)
        && let Some(mech_token) = token.0.neg_token_init.0.mech_token.0
    {
        let mech_token = mech_token.0.0;
        if let Ok((_, tail)) = decode_nego_message(&mech_token, MessageType::InitiatorNego) {
            let _ = decode_exchange_message(tail, MessageType::InitiatorMetaData);
        }
        if let Ok((_, tail)) = decode_nego_message(&mech_token, MessageType::AcceptorNego) {
            let _ = decode_exchange_message(tail, MessageType::AcceptorMetaData);
        }
    }

    if let Ok(token) = picky_asn1_der::from_bytes::<NegTokenTarg1>(data)
        && let Some(response_token) = token.0.response_token.0
    {
        let response_token = response_token.0.0;
        if let Ok((_, tail)) = decode_exchange_message(&response_token, MessageType::ApRequest) {
            let _ = decode_verify_message(tail);
        }
    }

    let _ = extract_krb_result::<AsRep>(data);
    let _ = KrbMessage::<AsReq>::decode_application_krb_message(data);
    let _ = KrbMessage::<KrbError>::decode_application_krb_message(data);
    let _ = KrbMessage::<ApReq>::decode_application_krb_message(data);
    let _ = KrbMessage::<ApRep>::decode_application_krb_message(data);
    let _ = WrapToken::decode(Cursor::new(data));
    let _ = MicToken::decode(Cursor::new(data));
}

#[cfg(test)]
mod tests {
    use crypto_bigint::rand_core::TryRng;
    use picky::key::PrivateKey;
    use picky::oids;
    use picky_asn1_x509::Certificate;
    use picky_krb::constants::key_usages::{ACCEPTOR_SEAL, INITIATOR_SEAL};
    use picky_krb::crypto::CipherSuite;
    use picky_krb::gss_api::{ApplicationTag0, GssApiNegInit};
    use picky_krb::negoex::data_types::MessageType;
    use picky_krb::negoex::messages::{Exchange, Nego};
    use picky_krb::negoex::{NegoexMessage, RANDOM_ARRAY_SIZE};
    use rand::rngs::{StdRng, SysRng};
    use rand_core::{Rng as _, SeedableRng as _};
    use uuid::Uuid;

    use super::generators::{
        generate_as_req_username_from_certificate, generate_client_dh_parameters, generate_server_dh_parameters,
    };
    use super::{
        PACKAGE_INFO, PKG_NAME, PKU2U_SECURITY_TRAILER, Pku2uMode, WRAP_SENT_BY_ACCEPTOR, decode_exchange_message,
        decode_nego_message, validate_peer_p2p_certificate,
    };
    use crate::kerberos::EncryptionParams;
    use crate::{
        AuthIdentityBuffers, BufferType, CertTrustErrorStatus, ClientRequestFlags, DataRepresentation, EncryptionFlags,
        ErrorKind, Negotiate, NegotiateConfig, PackageCapabilities, Pku2u, Pku2uConfig, Pku2uState, Result,
        SecurityBuffer, SecurityBufferFlags, SecurityBufferRef, SecurityStatus, ServerRequestFlags, Sspi, SspiEx,
        SspiImpl,
    };

    #[test]
    fn negoex_decode_rejects_out_of_bounds_auth_scheme_vector() {
        let mut encoded = Vec::new();
        Nego::new(
            MessageType::InitiatorNego,
            Uuid::nil(),
            0,
            [0; RANDOM_ARRAY_SIZE],
            vec![Uuid::nil()],
            Vec::new(),
        )
        .encode(&mut encoded)
        .unwrap();
        encoded[80..84].copy_from_slice(&u32::MAX.to_le_bytes());

        assert_eq!(
            decode_nego_message(&encoded, MessageType::InitiatorNego)
                .unwrap_err()
                .error_type,
            ErrorKind::InvalidToken
        );
    }

    #[test]
    fn negoex_decode_rejects_out_of_bounds_exchange_vector() {
        let mut encoded = Vec::new();
        Exchange::new(MessageType::ApRequest, Uuid::nil(), 0, Uuid::nil(), vec![1])
            .encode(&mut encoded)
            .unwrap();
        encoded[56..60].copy_from_slice(&u32::MAX.to_le_bytes());

        assert_eq!(
            decode_exchange_message(&encoded, MessageType::ApRequest)
                .unwrap_err()
                .error_type,
            ErrorKind::InvalidToken
        );
    }

    #[test]
    fn negoex_decode_rejects_out_of_bounds_empty_vector() {
        let mut encoded = Vec::new();
        Exchange::new(MessageType::ApRequest, Uuid::nil(), 0, Uuid::nil(), Vec::new())
            .encode(&mut encoded)
            .unwrap();
        encoded[56..60].copy_from_slice(&u32::MAX.to_le_bytes());

        assert_eq!(
            decode_exchange_message(&encoded, MessageType::ApRequest)
                .unwrap_err()
                .error_type,
            ErrorKind::InvalidToken
        );
    }

    /// A real device-registration ("PKU2U") certificate + RSA private key pair, extracted from a live
    /// Windows PKU2U exchange, used by several tests below as a stand-in server/client identity.
    fn test_p2p_identity() -> (Certificate, PrivateKey) {
        let p2p_certificate: Certificate = picky_asn1_der::from_bytes(&[
            48, 130, 3, 213, 48, 130, 2, 189, 160, 3, 2, 1, 2, 2, 16, 32, 99, 134, 91, 60, 164, 166, 93, 186, 47, 71,
            107, 255, 241, 24, 166, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 48, 77, 49, 75, 48, 73, 6,
            3, 85, 4, 3, 30, 66, 0, 77, 0, 83, 0, 45, 0, 79, 0, 114, 0, 103, 0, 97, 0, 110, 0, 105, 0, 122, 0, 97, 0,
            116, 0, 105, 0, 111, 0, 110, 0, 45, 0, 80, 0, 50, 0, 80, 0, 45, 0, 65, 0, 99, 0, 99, 0, 101, 0, 115, 0,
            115, 0, 32, 0, 91, 0, 50, 0, 48, 0, 50, 0, 50, 0, 93, 48, 30, 23, 13, 50, 51, 48, 49, 50, 57, 49, 53, 52,
            57, 52, 57, 90, 23, 13, 50, 51, 48, 49, 50, 57, 49, 54, 53, 52, 52, 57, 90, 48, 129, 142, 49, 52, 48, 50,
            6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 36, 97, 57, 50, 53, 50, 52, 52, 56, 45, 57, 97, 98,
            55, 45, 52, 57, 98, 48, 45, 98, 98, 53, 99, 45, 102, 50, 102, 57, 50, 51, 99, 56, 52, 54, 55, 50, 49, 61,
            48, 59, 6, 3, 85, 4, 3, 12, 52, 83, 45, 49, 45, 49, 50, 45, 49, 45, 51, 56, 48, 51, 49, 54, 49, 53, 57, 51,
            45, 49, 51, 51, 49, 50, 56, 56, 57, 56, 50, 45, 50, 48, 56, 52, 57, 49, 53, 56, 52, 51, 45, 51, 50, 50, 57,
            49, 49, 53, 52, 57, 56, 49, 23, 48, 21, 6, 3, 85, 4, 3, 12, 14, 115, 57, 64, 100, 97, 116, 97, 97, 110,
            115, 46, 99, 111, 109, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1,
            15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 213, 241, 189, 199, 35, 187, 172, 209, 113, 53, 145, 42, 93, 142,
            53, 223, 26, 208, 110, 226, 178, 54, 187, 237, 181, 246, 230, 65, 42, 101, 36, 177, 121, 74, 97, 222, 146,
            163, 254, 112, 155, 150, 227, 182, 123, 122, 251, 64, 119, 186, 229, 68, 157, 67, 211, 189, 241, 217, 197,
            194, 143, 86, 210, 86, 178, 232, 140, 59, 99, 9, 98, 8, 164, 181, 4, 194, 5, 101, 191, 137, 140, 13, 158,
            67, 216, 195, 67, 112, 162, 234, 81, 168, 198, 255, 40, 90, 165, 5, 155, 231, 80, 238, 124, 43, 98, 117,
            181, 159, 195, 246, 146, 183, 221, 215, 129, 237, 67, 119, 100, 159, 35, 246, 189, 204, 50, 29, 25, 214,
            121, 69, 120, 253, 143, 248, 219, 162, 32, 205, 111, 13, 76, 123, 158, 242, 60, 0, 233, 159, 17, 143, 199,
            243, 230, 213, 14, 193, 148, 12, 27, 11, 7, 90, 140, 253, 72, 229, 24, 69, 40, 59, 2, 243, 194, 41, 248,
            204, 92, 102, 189, 220, 19, 185, 227, 113, 192, 162, 86, 132, 88, 233, 191, 131, 215, 219, 5, 63, 163, 34,
            55, 9, 209, 94, 255, 37, 32, 165, 163, 167, 133, 49, 105, 19, 85, 147, 227, 77, 189, 125, 140, 171, 127,
            121, 249, 217, 216, 226, 253, 190, 105, 234, 99, 129, 100, 135, 231, 3, 237, 88, 81, 102, 67, 17, 147, 84,
            233, 75, 124, 179, 16, 160, 203, 202, 196, 235, 191, 209, 2, 3, 1, 0, 1, 163, 111, 48, 109, 48, 14, 6, 3,
            85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 5, 160, 48, 41, 6, 3, 85, 29, 17, 4, 34, 48, 32, 160, 30, 6, 10, 43, 6,
            1, 4, 1, 130, 55, 20, 2, 3, 160, 16, 12, 14, 115, 57, 64, 100, 97, 116, 97, 97, 110, 115, 46, 99, 111, 109,
            48, 19, 6, 3, 85, 29, 37, 4, 12, 48, 10, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 48, 27, 6, 9, 43, 6, 1, 4, 1, 130,
            55, 21, 10, 4, 14, 48, 12, 48, 10, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13,
            1, 1, 11, 5, 0, 3, 130, 1, 1, 0, 162, 35, 243, 146, 152, 98, 219, 208, 111, 136, 212, 0, 12, 134, 196, 6,
            96, 113, 172, 17, 243, 26, 152, 107, 97, 89, 98, 235, 162, 130, 189, 228, 248, 44, 19, 41, 203, 8, 185, 83,
            207, 142, 69, 242, 172, 137, 162, 78, 54, 219, 47, 213, 113, 120, 143, 177, 44, 242, 7, 79, 88, 71, 26,
            134, 120, 77, 93, 81, 134, 253, 155, 50, 160, 79, 113, 196, 96, 53, 87, 132, 132, 117, 9, 202, 38, 15, 47,
            4, 247, 57, 153, 145, 211, 181, 46, 92, 232, 219, 186, 226, 12, 7, 52, 61, 104, 55, 136, 170, 53, 57, 95,
            224, 35, 39, 192, 47, 11, 75, 37, 117, 205, 1, 76, 242, 4, 96, 203, 50, 254, 239, 253, 27, 23, 73, 159,
            110, 232, 164, 119, 55, 207, 77, 66, 95, 23, 202, 149, 245, 235, 57, 80, 50, 171, 183, 15, 27, 223, 7, 32,
            155, 101, 139, 95, 167, 214, 90, 58, 199, 250, 127, 131, 12, 97, 61, 212, 12, 10, 245, 34, 136, 11, 215,
            25, 168, 55, 120, 187, 5, 219, 220, 205, 45, 242, 237, 227, 43, 43, 164, 247, 181, 194, 251, 14, 153, 222,
            33, 157, 8, 228, 144, 87, 207, 135, 243, 223, 233, 114, 139, 94, 122, 228, 80, 237, 90, 53, 83, 60, 251,
            11, 179, 147, 227, 101, 85, 96, 80, 44, 176, 158, 85, 102, 31, 228, 24, 117, 230, 26, 202, 127, 121, 177,
            26, 62, 17, 96, 9,
        ])
        .unwrap();
        let private_key = PrivateKey::from_pem_str(
            "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDV8b3HI7us0XE1
kSpdjjXfGtBu4rI2u+219uZBKmUksXlKYd6So/5wm5bjtnt6+0B3uuVEnUPTvfHZ
xcKPVtJWsuiMO2MJYgiktQTCBWW/iYwNnkPYw0NwoupRqMb/KFqlBZvnUO58K2J1
tZ/D9pK33deB7UN3ZJ8j9r3MMh0Z1nlFeP2P+NuiIM1vDUx7nvI8AOmfEY/H8+bV
DsGUDBsLB1qM/UjlGEUoOwLzwin4zFxmvdwTueNxwKJWhFjpv4PX2wU/oyI3CdFe
/yUgpaOnhTFpE1WT4029fYyrf3n52dji/b5p6mOBZIfnA+1YUWZDEZNU6Ut8sxCg
y8rE67/RAgMBAAECggEAERzG6zjGeCpAfeJgmx8W3AOPDG+BhbM+bkGTZT743Bh9
9R8i6GPJpEQtq4UbF1klbO48DGLv2+3jfGG/ECwHovuoch8F6ug2fMYl3UcFPm7I
DwbLsnjb2hSN3X48fIhDx9NNBxGIIdJui6+9WbVNQvuxkyjhLpmTyRKhV8XiYgCK
OkfCfBWOt/WTGdtuwPtDnvtZOA8Qm3L9Yf0BuqLQAqNZ6fihhwfi1bwLwzRTzC3x
rAfxCMv4dLdYCTee9/6fUWGwJ4SKYqlolVbcZmpFJ7/ByRzfgq0etVJJxKIDOZ8y
ba/bw8eLypdo4I9SSch/5x/WAS45bMarX4nmJKwUyQKBgQDxCHKmUdwuz1SDhYX/
H/Si87uZ31Hs/Spjp/mUumwuEgtkmm2hlgtQXmbYnc47nIQqWOu/L0Z9//2D5WHU
lhYk6S8xAN3dKyGPrYKaBzrh5FCzolprz0YK/N1do9Yu0hkshs73isMbpVHPTI9l
WuzDqsqfz27VS4XovZJQfjL2+wKBgQDjOq5l5rFkLbeHxEoIFoMdEQnRrr1bXkrj
Vf0QWN2fi4Y8/RVLUVNifkjoo4Aj3D7sgyT8ItCDyXtj9Rt5swKUW+rywgI44Fr2
DuOAyAXhzFd7GLw0HnE9jeKMQyeXW5igAppXWOMgS6eAo25vIIRL4UBaIC4/WVCz
jJ/aprkaowKBgQDR46ZauJwA0yBoKySlJkGUiKPLeVFRCqAYCdTnM3MypxnusB9Z
f1w4zwvGA5zsAf6BFc+sO1GqNPmhGmUXht6fo8Mpa/THPGDMSa6ZzEP1Iyk3U+Bj
UypONSXa/elr+h5bzMR7gQUnlM1ps+SGwSe9t4McqLh92ncwVawMlehxcwKBgBcG
jj+TNeyR2WQvltTk+xpJ7LXLwDJvBqWsw/0RFDwjllG9z5eXQRzc8SRp1QVNPy8W
RvwpxvljxFYns0YMxrkj61X4JOOAkJcYgSM+oaH04/R8WC3r28vCAe/2qh9jT77/
JIavYiyWnf2iEgG+yMkrpSq80hLnSQ84s8YjWOSDAoGBAOaVvL6VVq2BawI+Qt3s
9DlgTNtzpiJJCmUfwNd2yOPQJVq5trdA0DZeCQEc/psPWXBoyT01ptgcGHP+C/Da
xFnLp2UBrhxA9GYrpJ5i0onRmexQnTVSl5DDq07s+3dbr9YAKjrg9IDZYqLbdwP1
1pNtUBlMx+0X6wxVjMYulkRH
-----END PRIVATE KEY-----",
        )
        .unwrap();

        (p2p_certificate, private_key)
    }

    fn test_certificate_validation_time() -> time::OffsetDateTime {
        time::Date::from_calendar_date(2023, time::Month::January, 29)
            .unwrap()
            .with_hms(16, 0, 0)
            .unwrap()
            .assume_utc()
    }

    #[test]
    fn expired_peer_certificate_is_rejected() {
        let (certificate, _) = test_p2p_identity();

        assert_eq!(
            validate_peer_p2p_certificate(&certificate, time::OffsetDateTime::now_utc())
                .unwrap_err()
                .error_type,
            ErrorKind::Pku2uCertFailure
        );
    }

    #[test]
    fn stream_buffer_decryption() {
        let session_key = vec![
            137, 60, 120, 245, 164, 179, 76, 200, 242, 96, 57, 174, 111, 209, 90, 76, 58, 117, 55, 138, 81, 75, 110,
            235, 80, 228, 14, 238, 76, 128, 139, 81,
        ];
        let sub_session_key = vec![
            35, 147, 211, 63, 83, 48, 241, 34, 97, 95, 27, 106, 195, 18, 95, 91, 17, 45, 187, 6, 26, 195, 16, 108, 123,
            119, 121, 155, 58, 142, 204, 74,
        ];

        let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();

        let (p2p_certificate, private_key) = test_p2p_identity();

        let mut negoex_random = [0; RANDOM_ARRAY_SIZE];
        rng.fill_bytes(&mut negoex_random);

        let mut pku2u_server = Pku2u {
            mode: Pku2uMode::Server,
            config: Pku2uConfig {
                p2p_certificate: p2p_certificate.clone(),
                private_key: private_key.clone().into(),
                client_hostname: "hostname".into(),
                additional_credentials: Vec::new(),
                trusted_client_certificates: vec![p2p_certificate.clone()],
                trusted_server_certificates: Vec::new(),
            },
            state: Pku2uState::Final,
            encryption_params: EncryptionParams {
                encryption_type: Some(CipherSuite::Aes256CtsHmacSha196),
                session_key: Some(session_key.clone().into()),
                sub_session_key: Some(sub_session_key.clone().into()),
                sspi_encrypt_key_usage: INITIATOR_SEAL,
                sspi_decrypt_key_usage: ACCEPTOR_SEAL,
                ec: 0,
            },
            auth_identity: None,
            conversation_id: Uuid::new_v4(),
            auth_scheme: None,
            seq_number: 0,
            gss_seq_number: 0,
            remote_gss_seq_number: 0,
            request_nonce: None,
            channel_bindings: None,
            peer_certificate: None,
            peer_certificate_trusted: false,
            peer_name: None,
            certificate_validation_time: None,
            dh_parameters: generate_server_dh_parameters(&mut rng).unwrap(),
            negoex_messages: Vec::new(),
            gss_api_messages: Vec::new(),
            negoex_random,
            ticket_encryption_key: None,
        };

        let mut negoex_random = [0; RANDOM_ARRAY_SIZE];
        rng.try_fill_bytes(&mut negoex_random).unwrap();

        let mut pku2u_client = Pku2u {
            mode: Pku2uMode::Client,
            config: Pku2uConfig {
                p2p_certificate: p2p_certificate.clone(),
                private_key: private_key.into(),
                client_hostname: "hostname".into(),
                additional_credentials: Vec::new(),
                trusted_client_certificates: vec![p2p_certificate.clone()],
                trusted_server_certificates: Vec::new(),
            },
            state: Pku2uState::Final,
            encryption_params: EncryptionParams {
                encryption_type: Some(CipherSuite::Aes256CtsHmacSha196),
                session_key: Some(session_key.into()),
                sub_session_key: Some(sub_session_key.into()),
                sspi_encrypt_key_usage: ACCEPTOR_SEAL,
                sspi_decrypt_key_usage: INITIATOR_SEAL,
                ec: 0,
            },
            auth_identity: None,
            conversation_id: Uuid::new_v4(),
            auth_scheme: None,
            seq_number: 0,
            gss_seq_number: 0,
            remote_gss_seq_number: 0,
            request_nonce: None,
            channel_bindings: None,
            peer_certificate: None,
            peer_certificate_trusted: false,
            peer_name: None,
            certificate_validation_time: None,
            dh_parameters: generate_client_dh_parameters(&mut rng),
            negoex_messages: Vec::new(),
            gss_api_messages: Vec::new(),
            negoex_random,
            ticket_encryption_key: None,
        };

        assert_eq!(PKG_NAME, "pku2u");
        assert_eq!(PACKAGE_INFO.rpc_id, 31);
        assert_eq!(PACKAGE_INFO.max_token_len, 12_000);
        assert_eq!(
            PACKAGE_INFO.capabilities,
            PackageCapabilities::INTEGRITY
                | PackageCapabilities::PRIVACY
                | PackageCapabilities::CONNECTION
                | PackageCapabilities::IMPERSONATION
                | PackageCapabilities::GSS_COMPATIBLE
                | PackageCapabilities::MUTUAL_AUTH
                | PackageCapabilities::NEGOTIABLE2
                | PackageCapabilities::APP_CONTAINER_CHECKS
        );
        let sizes = pku2u_client.query_context_sizes().unwrap();
        assert_eq!(sizes.max_signature, 28);
        assert_eq!(sizes.block, 1);

        let mut negotiate = Negotiate::new_client(NegotiateConfig::new(
            Box::new(pku2u_client.config.clone()),
            Some(String::from("pku2u,!kerberos,!ntlm")),
            "hostname".into(),
        ))
        .unwrap();
        let mut credentials_handle = None;
        let mut input = [SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let mut output = [SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let mut builder = negotiate
            .initialize_security_context()
            .with_credentials_handle(&mut credentials_handle)
            .with_context_requirements(ClientRequestFlags::MUTUAL_AUTH)
            .with_target_data_representation(DataRepresentation::Native)
            .with_target_name("TERMSRV/host.example.com")
            .with_input(&mut input)
            .with_output(&mut output);
        <Negotiate as SspiImpl>::initialize_security_context_impl(&mut negotiate, &mut builder)
            .unwrap()
            .resolve_to_result()
            .unwrap();
        let token: ApplicationTag0<GssApiNegInit> = picky_asn1_der::from_bytes(&output[0].buffer).unwrap();
        let mech_types = token.0.neg_token_init.0.mech_types.0.unwrap().0;
        assert_eq!(mech_types.0[0].0, oids::negoex());

        let mic = pku2u_server
            .generate_mic_token(b"SPNEGO mech list", crate::private::Sealed)
            .unwrap();
        let mut tampered_client = pku2u_client.clone();
        pku2u_client
            .verify_mic_token(&mic, b"SPNEGO mech list", crate::private::Sealed)
            .unwrap();
        assert_eq!(
            tampered_client
                .verify_mic_token(&mic, b"tampered mech list", crate::private::Sealed)
                .unwrap_err()
                .error_type,
            ErrorKind::MessageAltered
        );

        let mut aes128_server = pku2u_server.clone();
        let mut aes128_client = pku2u_client.clone();
        for context in [&mut aes128_server, &mut aes128_client] {
            context.encryption_params.encryption_type = Some(CipherSuite::Aes128CtsHmacSha196);
            context.encryption_params.session_key = Some(vec![0x11; 16].into());
            context.encryption_params.sub_session_key = Some(vec![0x22; 16].into());
            context.gss_seq_number = 0;
            context.remote_gss_seq_number = 0;
        }
        let aes128_mic = aes128_server
            .generate_mic_token(b"AES-128 mech list", crate::private::Sealed)
            .unwrap();
        aes128_client
            .verify_mic_token(&aes128_mic, b"AES-128 mech list", crate::private::Sealed)
            .unwrap();

        let mut signature = vec![0; usize::try_from(sizes.max_signature).unwrap()];
        let mut signed_data = b"signed Pku2u message".to_vec();
        let mut signed_message = [
            SecurityBufferRef::token_buf(&mut signature),
            SecurityBufferRef::data_buf(&mut signed_data),
        ];
        pku2u_server.make_signature(0, &mut signed_message, 42).unwrap();
        pku2u_client.verify_signature(&mut signed_message, 42).unwrap();
        let [mut signature_buffer, mut data_buffer] = signed_message;
        let signature = signature_buffer.take_data();
        let data = data_buffer.take_data();
        data[0] ^= 1;
        let mut tampered_message = [
            SecurityBufferRef::token_buf(signature),
            SecurityBufferRef::data_buf(data),
        ];
        assert_eq!(
            pku2u_client
                .verify_signature(&mut tampered_message, 42)
                .unwrap_err()
                .error_type,
            ErrorKind::MessageAltered
        );

        let mut channel_bindings = vec![0; 36];
        channel_bindings[24..28].copy_from_slice(&4_u32.to_le_bytes());
        channel_bindings[28..32].copy_from_slice(&32_u32.to_le_bytes());
        channel_bindings[32..].copy_from_slice(&[1, 2, 3, 4]);
        let input = [SecurityBuffer::new(channel_bindings, BufferType::ChannelBindings)];
        pku2u_client.read_channel_bindings(Some(&input)).unwrap();
        assert_eq!(
            pku2u_client.channel_bindings.as_ref().unwrap().application_data,
            [1, 2, 3, 4]
        );

        let plain_message = b"some plain message";

        let mut token = [0; 1024];
        let mut data = plain_message.to_vec();
        let mut message = [
            SecurityBufferRef::token_buf(token.as_mut_slice()),
            SecurityBufferRef::data_buf(data.as_mut_slice()),
        ];

        pku2u_server
            .encrypt_message(EncryptionFlags::empty(), &mut message)
            .unwrap();

        let mut buffer = message[0].data().to_vec();
        buffer.extend_from_slice(message[1].data());

        let mut message = [
            SecurityBufferRef::stream_buf(&mut buffer),
            SecurityBufferRef::data_buf(&mut []),
        ];

        pku2u_client.decrypt_message(&mut message).unwrap();

        assert_eq!(message[1].data(), plain_message);

        let mut token = [0; 128];
        let mut first = b"first writable buffer".to_vec();
        let mut second = b"second writable buffer".to_vec();
        let mut message = [
            SecurityBufferRef::token_buf(&mut token),
            SecurityBufferRef::data_buf(&mut first),
            SecurityBufferRef::data_buf(&mut second),
        ];
        pku2u_server
            .encrypt_message(EncryptionFlags::empty(), &mut message)
            .unwrap();
        assert_eq!(message[0].data().len(), PKU2U_SECURITY_TRAILER);
        pku2u_client.decrypt_message(&mut message).unwrap();
        assert_eq!(message[1].data(), b"first writable buffer");
        assert_eq!(message[2].data(), b"second writable buffer");

        let mut token = [0; 64];
        let mut readonly = b"signed header".to_vec();
        let mut data = b"integrity-only payload".to_vec();
        let mut message = [
            SecurityBufferRef::token_buf(&mut token),
            SecurityBufferRef::data_buf(&mut readonly)
                .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
            SecurityBufferRef::data_buf(&mut data),
        ];
        pku2u_server
            .encrypt_message(EncryptionFlags::WRAP_NO_ENCRYPT, &mut message)
            .unwrap();
        assert_eq!(message[0].data().len(), 28);
        assert_eq!(message[1].data(), b"signed header");
        assert_eq!(message[2].data(), b"integrity-only payload");
        assert_eq!(
            pku2u_client.decrypt_message(&mut message).unwrap(),
            crate::DecryptionFlags::WRAP_NO_ENCRYPT
        );

        let mut token = [0; 128];
        let mut data = b"direction-bound payload".to_vec();
        let mut message = [
            SecurityBufferRef::token_buf(&mut token),
            SecurityBufferRef::data_buf(&mut data),
        ];
        pku2u_server
            .encrypt_message(EncryptionFlags::empty(), &mut message)
            .unwrap();
        let mut encoded_token = message[0].data().to_vec();
        let mut encoded_data = message[1].data().to_vec();
        encoded_token[2] ^= WRAP_SENT_BY_ACCEPTOR;
        let mut tampered_message = [
            SecurityBufferRef::token_buf(&mut encoded_token),
            SecurityBufferRef::data_buf(&mut encoded_data),
        ];
        assert_eq!(
            pku2u_client
                .decrypt_message(&mut tampered_message)
                .unwrap_err()
                .error_type,
            ErrorKind::InvalidToken
        );
    }

    /// Drives one `initialize_security_context` leg for `client`, feeding back `input` (the peer's
    /// previous message, or `None` for the very first leg) and returning `(status, output token)`.
    fn client_step(client: &mut Pku2u, input: Option<Vec<u8>>) -> Result<(SecurityStatus, Vec<u8>)> {
        let context_requirements = ClientRequestFlags::MUTUAL_AUTH
            | ClientRequestFlags::INTEGRITY
            | ClientRequestFlags::CONFIDENTIALITY
            | ClientRequestFlags::REPLAY_DETECT
            | ClientRequestFlags::SEQUENCE_DETECT;

        let mut credentials_handle: Option<AuthIdentityBuffers> = None;
        let mut input_buffer = [SecurityBuffer::new(input.unwrap_or_default(), BufferType::Token)];
        let mut output_buffer = [SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let mut builder = client
            .initialize_security_context()
            .with_credentials_handle(&mut credentials_handle)
            .with_context_requirements(context_requirements)
            .with_target_data_representation(DataRepresentation::Native)
            .with_target_name("server-host")
            .with_input(&mut input_buffer)
            .with_output(&mut output_buffer);
        let result =
            <Pku2u as SspiImpl>::initialize_security_context_impl(client, &mut builder)?.resolve_to_result()?;

        Ok((result.status, output_buffer[0].buffer.clone()))
    }

    /// Drives one `accept_security_context` leg for `server`, feeding it the peer's latest message and
    /// returning `(status, output token)`.
    fn server_step(server: &mut Pku2u, input: Vec<u8>) -> Result<(SecurityStatus, Vec<u8>)> {
        let mut credentials_handle: Option<AuthIdentityBuffers> = None;
        let mut input_buffer = [SecurityBuffer::new(input, BufferType::Token)];
        let mut output_buffer = [SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let builder = server
            .accept_security_context()
            .with_credentials_handle(&mut credentials_handle)
            .with_context_requirements(ServerRequestFlags::empty())
            .with_target_data_representation(DataRepresentation::Native)
            .with_input(&mut input_buffer)
            .with_output(&mut output_buffer);
        let result = <Pku2u as SspiImpl>::accept_security_context_impl(server, builder)?.resolve_to_result()?;

        Ok((result.status, output_buffer[0].buffer.clone()))
    }

    fn set_test_channel_bindings(context: &mut Pku2u, application_data: &[u8]) {
        let mut channel_bindings = vec![0; 32 + application_data.len()];
        channel_bindings[24..28].copy_from_slice(&u32::try_from(application_data.len()).unwrap().to_le_bytes());
        channel_bindings[28..32].copy_from_slice(&32_u32.to_le_bytes());
        channel_bindings[32..].copy_from_slice(application_data);
        let input = [SecurityBuffer::new(channel_bindings, BufferType::ChannelBindings)];
        context.read_channel_bindings(Some(&input)).unwrap();
    }

    /// End-to-end test: drives a real PKU2U client and a real PKU2U acceptor through every phase of
    /// the handshake — SPNEGO/NEGOEX `InitiatorNego`+`InitiatorMetaData`, the acceptor's
    /// `AcceptorNego`+`AcceptorMetaData`, the PKINIT AS-REQ/AS-REP (Diffie-Hellman key agreement,
    /// signed with each side's own certificate, and a self-issued Kerberos Ticket), and the mutual
    /// AP-REQ/AP-REP with NEGOEX `Verify` transcript signatures — using only the public `Sspi`/
    /// `SspiImpl` API (no internal state is peeked at or injected). Both sides use the same
    /// certificate/key pair (as if they were two devices registered through the same CA), matching
    /// `Pku2uConfig::p2p_certificate`'s "self-issued" trust model. Once both contexts report
    /// [`SecurityStatus::Ok`], it exercises sealed `Wrap` (`encrypt_message`/`decrypt_message`) and MIC
    /// (`generate_mic_token`/`verify_mic_token`) in both directions over the negotiated session.
    #[test]
    fn full_handshake_then_wrap_and_mic() {
        let (server_certificate, private_key) = test_p2p_identity();
        let mut client_certificate = server_certificate.clone();
        client_certificate.tbs_certificate.issuer = client_certificate.tbs_certificate.subject.clone();

        let client_config = Pku2uConfig::new(client_certificate.clone(), private_key.clone(), "client-host".into())
            .with_trusted_server_certificate(server_certificate.clone());
        let mut client = Pku2u::new_client_from_config(client_config).unwrap();
        let server_config = Pku2uConfig::new(server_certificate.clone(), private_key, "server-host".into())
            .with_trusted_client_certificate(client_certificate.clone());
        let mut server = Pku2u::new_server_from_config(server_config).unwrap();
        client.certificate_validation_time = Some(test_certificate_validation_time());
        server.certificate_validation_time = Some(test_certificate_validation_time());

        // Leg 1 (initiator -> acceptor): InitiatorNego + InitiatorMetaData.
        let (status, msg) = client_step(&mut client, None).unwrap();
        assert_eq!(status, SecurityStatus::ContinueNeeded);
        assert!(matches!(client.state, Pku2uState::Preauthentication));

        // Leg 2 (acceptor -> initiator): AcceptorNego + AcceptorMetaData.
        let (status, msg) = server_step(&mut server, msg).unwrap();
        assert_eq!(status, SecurityStatus::ContinueNeeded);
        assert!(matches!(server.state, Pku2uState::AsExchange));

        // Leg 3 (initiator -> acceptor): the PKINIT AS-REQ, signed with the initiator's certificate.
        let (status, msg) = client_step(&mut client, Some(msg)).unwrap();
        assert_eq!(status, SecurityStatus::ContinueNeeded);
        assert!(matches!(client.state, Pku2uState::AsExchange));

        // Leg 4 (acceptor -> initiator): the self-issued AS-REP (DH-signed with the acceptor's own
        // certificate) and Kerberos Ticket.
        let (status, msg) = server_step(&mut server, msg).unwrap();
        assert_eq!(status, SecurityStatus::ContinueNeeded);
        assert!(matches!(server.state, Pku2uState::ApExchange));
        assert!(server.encryption_params.session_key.is_some());
        assert!(server.ticket_encryption_key.is_some());

        // Leg 5 (initiator -> acceptor): AP-REQ + NEGOEX Verify (INITIATOR_SIGN).
        let (status, msg) = client_step(&mut client, Some(msg)).unwrap();
        assert_eq!(status, SecurityStatus::ContinueNeeded);
        assert!(matches!(client.state, Pku2uState::ApExchange));
        let mut replay_server = server.clone();
        let replay_msg = msg.clone();

        // Leg 6 (acceptor -> initiator): AP-REP + NEGOEX Verify (ACCEPTOR_SIGN). The acceptor's
        // context is fully established after validating the ticket, authenticator, channel bindings,
        // "Finished" checksum, and the initiator's transcript signature.
        let (status, msg) = server_step(&mut server, msg).unwrap();
        assert_eq!(status, SecurityStatus::Ok);
        assert!(matches!(server.state, Pku2uState::PubKeyAuth));
        assert_eq!(
            server_step(&mut replay_server, replay_msg).unwrap_err().error_type,
            ErrorKind::InvalidToken
        );

        // Leg 7: the initiator validates the acceptor's AP-REP/Verify and completes too. No further
        // output token is produced.
        let (status, msg) = client_step(&mut client, Some(msg)).unwrap();
        assert_eq!(status, SecurityStatus::Ok);
        assert!(matches!(client.state, Pku2uState::PubKeyAuth));
        assert!(msg.is_empty());
        assert_eq!(
            client.query_context_cert_trust_status().unwrap().error_status,
            CertTrustErrorStatus::NO_ERROR
        );
        assert_eq!(
            server.query_context_cert_trust_status().unwrap().error_status,
            CertTrustErrorStatus::NO_ERROR
        );
        assert_eq!(client.query_context_remote_cert().unwrap().cert, server_certificate);
        assert_eq!(server.query_context_remote_cert().unwrap().cert, client_certificate);
        assert_eq!(
            server.query_context_names().unwrap().username.inner(),
            generate_as_req_username_from_certificate(&client_certificate).unwrap()
        );

        // Both sides now agree on the same session key and sub-session key.
        assert_eq!(
            client.encryption_params.session_key.as_ref().unwrap().as_ref(),
            server.encryption_params.session_key.as_ref().unwrap().as_ref()
        );
        assert_eq!(
            client.encryption_params.sub_session_key.as_ref().unwrap().as_ref(),
            server.encryption_params.sub_session_key.as_ref().unwrap().as_ref()
        );

        // Sealed Wrap, initiator -> acceptor.
        let plaintext = b"hello from the PKU2U initiator";
        let mut token = vec![0u8; PKU2U_SECURITY_TRAILER];
        let mut data = plaintext.to_vec();
        let mut message = [
            SecurityBufferRef::token_buf(&mut token),
            SecurityBufferRef::data_buf(&mut data),
        ];
        client.encrypt_message(EncryptionFlags::empty(), &mut message).unwrap();
        server.decrypt_message(&mut message).unwrap();
        assert_eq!(message[1].data(), plaintext);

        // Sealed Wrap, acceptor -> initiator.
        let plaintext = b"hello from the PKU2U acceptor";
        let mut token = vec![0u8; PKU2U_SECURITY_TRAILER];
        let mut data = plaintext.to_vec();
        let mut message = [
            SecurityBufferRef::token_buf(&mut token),
            SecurityBufferRef::data_buf(&mut data),
        ];
        server.encrypt_message(EncryptionFlags::empty(), &mut message).unwrap();
        client.decrypt_message(&mut message).unwrap();
        assert_eq!(message[1].data(), plaintext);

        // MIC, initiator -> acceptor.
        let mic_payload = b"integrity-protected payload from the initiator";
        let mic = client.generate_mic_token(mic_payload, crate::private::Sealed).unwrap();
        server
            .verify_mic_token(&mic, mic_payload, crate::private::Sealed)
            .unwrap();

        // MIC, acceptor -> initiator.
        let mic_payload = b"integrity-protected payload from the acceptor";
        let mic = server.generate_mic_token(mic_payload, crate::private::Sealed).unwrap();
        // Verify against a tampered payload first, on a clone, so this check is independent of the
        // real verification's sequence-number bookkeeping below.
        let mut tampered_client = client.clone();
        assert_eq!(
            tampered_client
                .verify_mic_token(&mic, b"a different payload", crate::private::Sealed)
                .unwrap_err()
                .error_type,
            ErrorKind::MessageAltered
        );
        client
            .verify_mic_token(&mic, mic_payload, crate::private::Sealed)
            .unwrap();
    }

    #[test]
    fn handshake_rejects_mismatched_channel_bindings() {
        let (certificate, private_key) = test_p2p_identity();
        let mut client = Pku2u::new_client_from_config(
            Pku2uConfig::new(certificate.clone(), private_key.clone(), "client-host".into())
                .with_trusted_server_certificate(certificate.clone()),
        )
        .unwrap();
        let mut server = Pku2u::new_server_from_config(
            Pku2uConfig::new(certificate.clone(), private_key, "server-host".into())
                .with_trusted_client_certificate(certificate),
        )
        .unwrap();
        client.certificate_validation_time = Some(test_certificate_validation_time());
        server.certificate_validation_time = Some(test_certificate_validation_time());

        let (_, message) = client_step(&mut client, None).unwrap();
        let (_, message) = server_step(&mut server, message).unwrap();
        let (_, message) = client_step(&mut client, Some(message)).unwrap();
        let (_, message) = server_step(&mut server, message).unwrap();

        set_test_channel_bindings(&mut client, b"initiator binding");
        set_test_channel_bindings(&mut server, b"acceptor binding");
        let (_, message) = client_step(&mut client, Some(message)).unwrap();

        assert_eq!(
            server_step(&mut server, message).unwrap_err().error_type,
            ErrorKind::MessageAltered
        );
    }

    /// The acceptor must reject a tampered message instead of panicking or silently accepting it,
    /// whichever leg of the handshake it arrives on: a bit flip anywhere in the signed PKINIT AS-REQ
    /// invalidates its CMS signature (or its `paChecksum` content binding), and a bit flip in the
    /// AP-REQ invalidates either its encrypted `Authenticator` (AES-CTS-HMAC is itself
    /// tamper-evident) or the ticket/"Finished"/NEGOEX-transcript checks layered on top of it.
    #[test]
    fn handshake_rejects_tampered_messages() {
        let (p2p_certificate, private_key) = test_p2p_identity();

        for leg_to_tamper in 1..=3 {
            let mut client = Pku2u::new_client_from_config(Pku2uConfig::new(
                p2p_certificate.clone(),
                private_key.clone(),
                "client-host".into(),
            ))
            .unwrap();
            let mut server = Pku2u::new_server_from_config(Pku2uConfig::new(
                p2p_certificate.clone(),
                private_key.clone(),
                "server-host".into(),
            ))
            .unwrap();
            client.certificate_validation_time = Some(test_certificate_validation_time());
            server.certificate_validation_time = Some(test_certificate_validation_time());

            let (status, msg) = client_step(&mut client, None).unwrap();
            assert_eq!(status, SecurityStatus::ContinueNeeded);
            let msg = tamper(msg, leg_to_tamper == 1);

            let step = server_step(&mut server, msg);
            if leg_to_tamper == 1 {
                step.unwrap_err();
                continue;
            }
            let (status, msg) = step.unwrap();
            assert_eq!(status, SecurityStatus::ContinueNeeded);
            let msg = tamper(msg, leg_to_tamper == 2);

            let step = client_step(&mut client, Some(msg));
            if leg_to_tamper == 2 {
                step.unwrap_err();
                continue;
            }
            let (status, msg) = step.unwrap();
            assert_eq!(status, SecurityStatus::ContinueNeeded);
            let msg = tamper(msg, leg_to_tamper == 3);

            server_step(&mut server, msg).unwrap_err();
        }
    }

    /// Corrupts the last few bytes of `msg` (inverting each byte) when `should_tamper` is set,
    /// otherwise returns it unchanged. Per the NEGOEX wire format, fixed-size headers (including the
    /// offset/count fields of the `Vec`-like fields the wire encoding uses) always precede
    /// variable-length data, which is appended at the very end — so the tail of the buffer is always
    /// part of the innermost GSS-API payload (a signature, ciphertext, or ASN.1 string), never an
    /// offset/count field whose corruption could send a third-party NEGOEX decoder out of bounds.
    fn tamper(mut msg: Vec<u8>, should_tamper: bool) -> Vec<u8> {
        if should_tamper {
            let start = msg.len().saturating_sub(24);
            for byte in &mut msg[start..] {
                *byte ^= 0xFF;
            }
        }
        msg
    }
}

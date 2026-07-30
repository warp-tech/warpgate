use std::io::Write;

use picky_krb::constants::key_usages::{ACCEPTOR_SIGN, INITIATOR_SIGN};
use picky_krb::crypto::aes::{AesSize, checksum_sha_aes};
use picky_krb::gss_api::MicToken;
use serde::Serialize;

use crate::kerberos::encryption_params::EncryptionParams;
use crate::{Error, ErrorKind, Result, Secret};

pub(super) fn serialize_message<T: ?Sized + Serialize>(v: &T) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    // 4 bytes: length of the message
    data.write_all(&[0, 0, 0, 0])?;

    picky_asn1_der::to_writer(v, &mut data)?;

    let len = data.len() as u32 - 4;
    data[0..4].copy_from_slice(&len.to_be_bytes());

    Ok(data)
}

pub(super) fn validate_mic_token(
    is_client: bool,
    raw_token: &[u8],
    params: &EncryptionParams,
    mech_types: &[u8],
) -> Result<()> {
    let key_usage = if is_client { ACCEPTOR_SIGN } else { INITIATOR_SIGN };

    let token = MicToken::decode(raw_token)?;
    let token_flags = token.flags;

    // [Flags Field](https://datatracker.ietf.org/doc/html/rfc4121#section-4.2.2):
    //
    // The meanings of bits in this field (the least significant bit is bit
    // 0) are as follows:
    //        Bit    Name             Description
    //       --------------------------------------------------------------
    //        0   SentByAcceptor   When set, this flag indicates the sender
    //                             is the context acceptor.  When not set,
    //                             it indicates the sender is the context
    //                             initiator.
    if token_flags & 0b01 != u8::from(is_client) {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "invalid MIC token SentByAcceptor flag",
        ));
    }
    //        1   Sealed           When set in Wrap tokens, this flag
    //                             indicates confidentiality is provided
    //                             for.  It SHALL NOT be set in MIC tokens.
    if token_flags & 0b10 == 0b10 {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "the Sealed flag has not to be set in the MIC token",
        ));
    }

    let payload = [mech_types, token.header().as_slice()].concat();

    // The sub-session key is always preferred over the session key.
    let key = if let Some(key) = params.sub_session_key.as_ref() {
        key
    } else if let Some(key) = params.session_key.as_ref() {
        key
    } else {
        return Err(Error::new(ErrorKind::DecryptFailure, "unable to obtain decryption key"));
    };

    let checksum = checksum_sha_aes(
        key.as_ref(),
        key_usage,
        &payload,
        &params.aes_size().unwrap_or(AesSize::Aes256),
    )?;

    if checksum != token.checksum {
        return Err(Error::new(ErrorKind::MessageAltered, "bad checksum of the mic token"));
    }

    Ok(())
}

pub(super) fn generate_mic_token(
    is_client: bool,
    seq_number: u64,
    mut payload: Vec<u8>,
    session_key: &Secret<Vec<u8>>,
) -> Result<Vec<u8>> {
    let (mic_token, key_usage) = if is_client {
        (MicToken::with_initiator_flags(), INITIATOR_SIGN)
    } else {
        (MicToken::with_acceptor_flags(), ACCEPTOR_SIGN)
    };

    let mut mic_token = mic_token.with_seq_number(seq_number);

    payload.extend_from_slice(&mic_token.header());

    mic_token.set_checksum(checksum_sha_aes(
        session_key.as_ref(),
        key_usage,
        &payload,
        &AesSize::Aes256,
    )?);

    let mut mic_token_raw = Vec::new();
    mic_token.encode(&mut mic_token_raw)?;

    Ok(mic_token_raw)
}

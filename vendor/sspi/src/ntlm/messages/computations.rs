#[cfg(test)]
mod test;

use std::io::{self, Read, Write};
use std::sync::LazyLock;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use rand::rngs::{StdRng, SysRng};
use rand_core::{Rng as _, SeedableRng as _};
use time::OffsetDateTime;

use crate::channel_bindings::ChannelBindings;
use crate::crypto::{HASH_SIZE, compute_hmac_md5, compute_md4, compute_md5, compute_md5_channel_bindings_hash};
use crate::ntlm::messages::av_pair::*;
use crate::ntlm::{
    AuthIdentityBuffers, CHALLENGE_SIZE, LM_CHALLENGE_RESPONSE_BUFFER_SIZE, MESSAGE_INTEGRITY_CHECK_SIZE,
};
use crate::{NtlmHash, NtlmHashError, Secret, Utf16StringExt};

pub(super) const SINGLE_HOST_DATA_SIZE: usize = 48;

const NT_V2_RESPONSE_BASE_SIZE: usize = 28;

// The Single_Host_Data structure allows a client to send machine-specific information
// within an authentication exchange to services on the same machine. The client can
// produce additional information to be processed in an implementation-specific way when
// the client and server are on the same host. If the server and client platforms are
// different or if they are on different hosts, then the information MUST be ignored.
// Any fields after the MachineID field MUST be ignored on receipt.
pub(super) static SINGLE_HOST_DATA: LazyLock<[u8; SINGLE_HOST_DATA_SIZE]> = LazyLock::new(|| {
    let mut result = [0x00; SINGLE_HOST_DATA_SIZE];
    let mut buffer = io::Cursor::new(result.as_mut());

    buffer.write_u32::<LittleEndian>(SINGLE_HOST_DATA_SIZE as u32).unwrap(); //size
    buffer.write_u32::<LittleEndian>(0).unwrap(); //z4
    buffer.write_u32::<LittleEndian>(1).unwrap(); //data present
    buffer.write_u32::<LittleEndian>(0x2000).unwrap(); //custom_data
    buffer.write_all([0xaa; 32].as_ref()).unwrap(); //machine_id

    result
});

fn convert_to_file_time(end_date: OffsetDateTime) -> crate::Result<u64> {
    let start_date = time::Date::from_calendar_date(1601, time::Month::January, 1)
        .expect("hardcoded")
        .with_hms(0, 1, 1)
        .expect("hardcoded")
        .assume_utc();

    if start_date > end_date {
        Err(crate::Error::new(
            crate::ErrorKind::InternalError,
            format!(
                "Failed to convert system time to file time, where the start date: {start_date:?}, end date: {end_date:?}"
            ),
        ))
    } else {
        let duration = end_date - start_date;
        let whole_microseconds = duration.whole_microseconds();
        let file_time = u64::try_from(whole_microseconds).expect("whole_microseconds to u64 conversion") * 10;
        Ok(file_time)
    }
}

pub(super) fn get_challenge_target_info(timestamp: u64) -> crate::Result<Vec<u8>> {
    // Windows requires _DomainName, _ComputerName fields, but does not care what they are contain
    let av_pairs = vec![
        AvPair::NbDomainName(Vec::new()),
        AvPair::NbComputerName(Vec::new()),
        AvPair::DnsDomainName(Vec::new()),
        AvPair::DnsComputerName(Vec::new()),
        AvPair::Timestamp(timestamp),
        AvPair::EOL,
    ];

    Ok(AvPair::list_to_buffer(&av_pairs)?)
}

pub(super) fn get_authenticate_target_info(
    target_info: &[u8],
    channel_bindings: Option<&ChannelBindings>,
    send_single_host_data: bool,
) -> crate::Result<Vec<u8>> {
    let mut av_pairs = AvPair::buffer_to_av_pairs(target_info)?;

    av_pairs.retain(|av_pair| av_pair.as_u16() != AV_PAIR_EOL);

    // use_mic always true, when ntlm_v2 is true
    let flags_av_pair = AvPair::Flags(MsvAvFlags::MESSAGE_INTEGRITY_CHECK.bits());
    av_pairs.push(flags_av_pair);

    if send_single_host_data {
        let single_host_av_pair = AvPair::SingleHost(*SINGLE_HOST_DATA);
        av_pairs.push(single_host_av_pair);
    }

    // will not check suppress_extended_protection and
    // will not add channel bindings and service principal name
    // because it is not used anywhere

    if let Some(channel_bindings) = channel_bindings {
        av_pairs.push(AvPair::ChannelBindings(compute_md5_channel_bindings_hash(
            channel_bindings,
        )));
    }

    let mut authenticate_target_info = AvPair::list_to_buffer(&av_pairs)?;

    // NTLMv2
    // unknown 8-byte padding: AvEOL ([0x00; 4]) + reserved ([0x00; 4])
    authenticate_target_info.write_u64::<LittleEndian>(0x00)?;

    Ok(authenticate_target_info)
}

pub(super) fn generate_challenge() -> crate::Result<[u8; CHALLENGE_SIZE]> {
    let mut challenge = [0; CHALLENGE_SIZE];
    let mut rand = StdRng::try_from_rng(&mut SysRng)?;
    rand.fill_bytes(challenge.as_mut());
    Ok(challenge)
}

pub(super) fn now_file_time_timestamp() -> crate::Result<u64> {
    convert_to_file_time(OffsetDateTime::now_utc())
}

pub(crate) fn generate_signing_key(exported_session_key: &[u8], sign_magic: &[u8]) -> Secret<[u8; HASH_SIZE]> {
    let mut value = exported_session_key.to_vec();
    value.extend_from_slice(sign_magic);
    Secret::new(compute_md5(value.as_ref()))
}

pub(super) fn compute_message_integrity_check(
    negotiate_message: &[u8],
    challenge_message: &[u8],
    authenticate_message: &[u8],
    exported_session_key: &[u8],
) -> io::Result<[u8; MESSAGE_INTEGRITY_CHECK_SIZE]> {
    let mut message_integrity_check = negotiate_message.to_vec();
    message_integrity_check.extend_from_slice(challenge_message);
    message_integrity_check.extend_from_slice(authenticate_message);

    compute_hmac_md5(exported_session_key, message_integrity_check.as_ref())
}

pub(super) fn compute_ntlm_v2_hash(identity: &AuthIdentityBuffers) -> crate::Result<[u8; HASH_SIZE]> {
    if !identity.is_empty() {
        let password_bytes = identity.password.as_ref().0.as_bytes_le();
        let password_str = identity.password.as_ref().0.to_string();

        // Check if the password field contains an NT hash with the prefix.
        let hmac_key = if let Some(hash_hex) = password_str.strip_prefix(crate::ntlm::hash::NTLM_HASH_PREFIX) {
            let nt_hash: NtlmHash = hash_hex.parse().map_err(|e| match e {
                NtlmHashError::StringLength => crate::Error::new(
                    crate::ErrorKind::InvalidToken,
                    "NT hash must be exactly 32 hex characters",
                ),
                NtlmHashError::Hex => {
                    crate::Error::new(crate::ErrorKind::InvalidToken, "Invalid hex character in NT hash")
                }
                NtlmHashError::ByteLength => unreachable!(),
            })?;

            *nt_hash.as_bytes()
        } else {
            compute_md4(password_bytes)
        };

        let mut user_uppercase_with_domain = identity.user.to_uppercase().to_bytes_le();
        user_uppercase_with_domain.extend(identity.domain.as_bytes_le());

        Ok(compute_hmac_md5(&hmac_key, &user_uppercase_with_domain)?)
    } else {
        Err(crate::Error::new(
            crate::ErrorKind::InvalidToken,
            String::from("Got empty identity"),
        ))
    }
    // hash by the callback is not implemented because the callback never sets
}

pub(super) fn compute_lm_v2_response(
    client_challenge: &[u8],
    server_challenge: &[u8],
    ntlm_v2_hash: &[u8],
) -> crate::Result<[u8; LM_CHALLENGE_RESPONSE_BUFFER_SIZE]> {
    let mut lm_challenge_data = [0x00; CHALLENGE_SIZE * 2];
    lm_challenge_data[0..CHALLENGE_SIZE].clone_from_slice(server_challenge);
    lm_challenge_data[CHALLENGE_SIZE..].clone_from_slice(client_challenge);

    let mut lm_challenge_response = [0x00; LM_CHALLENGE_RESPONSE_BUFFER_SIZE];
    lm_challenge_response[0..HASH_SIZE].clone_from_slice(compute_hmac_md5(ntlm_v2_hash, &lm_challenge_data)?.as_ref());
    lm_challenge_response[HASH_SIZE..].clone_from_slice(client_challenge);
    Ok(lm_challenge_response)
}

pub(super) fn compute_ntlm_v2_response(
    client_challenge: &[u8],
    server_challenge: &[u8],
    target_info: &[u8],
    ntlm_v2_hash: &[u8],
    timestamp: u64,
) -> crate::Result<(Vec<u8>, [u8; HASH_SIZE])> {
    let mut ntlm_v2_temp = Vec::with_capacity(NT_V2_RESPONSE_BASE_SIZE);
    ntlm_v2_temp.write_u8(1)?; // RespType 1 byte
    ntlm_v2_temp.write_u8(1)?; // HighRespType 1 byte
    ntlm_v2_temp.write_u16::<LittleEndian>(0)?; // Reserved1 2 bytes
    ntlm_v2_temp.write_u32::<LittleEndian>(0)?; // Reserved2 4 bytes
    ntlm_v2_temp.write_u64::<LittleEndian>(timestamp)?; // Timestamp 8 bytes
    ntlm_v2_temp.extend(client_challenge); // ClientChallenge 8 bytes
    ntlm_v2_temp.write_u32::<LittleEndian>(0)?; // Reserved3 4 bytes
    ntlm_v2_temp.extend(target_info); // TargetInfo

    let mut nt_proof_input = server_challenge.to_vec();
    nt_proof_input.extend(ntlm_v2_temp.as_slice());
    let nt_proof = compute_hmac_md5(ntlm_v2_hash, nt_proof_input.as_ref())?;

    let mut nt_challenge_response = nt_proof.to_vec();
    nt_challenge_response.append(ntlm_v2_temp.as_mut());

    let key_exchange_key = compute_hmac_md5(ntlm_v2_hash, nt_proof.as_ref())?;

    Ok((nt_challenge_response, key_exchange_key))
}

pub(super) fn read_ntlm_v2_response(mut challenge_response: &[u8]) -> io::Result<(Vec<u8>, [u8; CHALLENGE_SIZE])> {
    let mut response = [0x00; HASH_SIZE];
    challenge_response.read_exact(response.as_mut())?;
    let _resp_type = challenge_response.read_u8()?;
    let _hi_resp_type = challenge_response.read_u8()?;
    let _reserved1 = challenge_response.read_u16::<LittleEndian>()?;
    let _reserved2 = challenge_response.read_u32::<LittleEndian>()?;
    let _timestamp = challenge_response.read_u64::<LittleEndian>()?;

    let mut client_challenge = [0x00; CHALLENGE_SIZE];
    challenge_response.read_exact(client_challenge.as_mut())?;
    let _reserved3 = challenge_response.read_u32::<LittleEndian>()?;

    let mut av_pairs = Vec::with_capacity(challenge_response.len());
    challenge_response.read_to_end(&mut av_pairs)?;

    Ok((av_pairs, client_challenge))
}

pub(super) fn get_av_flags_from_response(av_pairs: &[AvPair]) -> io::Result<MsvAvFlags> {
    if let Some(AvPair::Flags(value)) = av_pairs.iter().find(|&av_pair| av_pair.as_u16() == AV_PAIR_FLAGS) {
        Ok(MsvAvFlags::from_bits(*value).unwrap_or_else(MsvAvFlags::empty))
    } else {
        Ok(MsvAvFlags::empty())
    }
}

pub(super) fn get_challenge_timestamp_from_response(target_info: &[u8]) -> crate::Result<u64> {
    let av_pairs = AvPair::buffer_to_av_pairs(target_info)?;

    if let Some(AvPair::Timestamp(value)) = av_pairs.iter().find(|&av_pair| av_pair.as_u16() == AV_PAIR_TIMESTAMP) {
        Ok(*value)
    } else {
        now_file_time_timestamp()
    }
}

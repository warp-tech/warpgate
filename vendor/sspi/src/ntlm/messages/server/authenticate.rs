use std::io::{self, Read};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::crypto::compute_md5_channel_bindings_hash;
use crate::ntlm::messages::av_pair::{AV_PAIR_CHANNEL_BINDINGS, AvPair, MsvAvFlags};
use crate::ntlm::messages::computations::*;
use crate::ntlm::messages::{MessageFields, MessageTypes, read_ntlm_header, try_read_version};
use crate::ntlm::{
    AuthIdentityBuffers, AuthenticateMessage, ChannelBindings, ENCRYPTED_RANDOM_SESSION_KEY_SIZE,
    MESSAGE_INTEGRITY_CHECK_SIZE, Mic, NegotiateFlags, Ntlm, NtlmState,
};
use crate::{SecurityStatus, Utf16String, Utf16StringExt};

const HEADER_SIZE: usize = 64;

struct AuthenticateMessageFields {
    workstation: MessageFields,
    domain_name: MessageFields,
    encrypted_random_session_key: MessageFields,
    user_name: MessageFields,
    lm_challenge_response: MessageFields,
    nt_challenge_response: MessageFields,
}

pub(crate) fn read_authenticate(context: &mut Ntlm, mut stream: impl Read) -> crate::Result<SecurityStatus> {
    check_state(context.state)?;

    let mut buffer = Vec::with_capacity(HEADER_SIZE);
    stream.read_to_end(&mut buffer)?;
    let mut buffer = io::Cursor::new(buffer);

    read_ntlm_header(&mut buffer, MessageTypes::Authenticate)?;
    let (mut message_fields, flags) = read_header(&mut buffer)?;
    context.flags = flags;
    let _version = try_read_version(context.flags, &mut buffer)?;
    let mic = read_payload(flags, &mut message_fields, &mut buffer)?;
    let message = buffer.into_inner();

    let (authenticate_message, updated_identity) = process_message_fields(
        &context.identity,
        message_fields,
        mic,
        message,
        &context.channel_bindings,
    )?;
    context.identity = Some(updated_identity);
    context.authenticate_message = Some(authenticate_message);

    context.state = NtlmState::Completion;

    Ok(SecurityStatus::CompleteNeeded)
}

fn check_state(state: NtlmState) -> crate::Result<()> {
    if state != NtlmState::Authenticate {
        Err(crate::Error::new(
            crate::ErrorKind::OutOfSequence,
            "Read authenticate was fired but the state is not an Authenticate",
        ))
    } else {
        Ok(())
    }
}

fn read_header(mut buffer: impl Read) -> crate::Result<(AuthenticateMessageFields, NegotiateFlags)> {
    let mut lm_challenge_response = MessageFields::new();
    let mut nt_challenge_response = MessageFields::new();
    let mut domain_name = MessageFields::new();
    let mut user_name = MessageFields::new();
    let mut workstation = MessageFields::new();
    let mut encrypted_random_session_key = MessageFields::new();

    lm_challenge_response.read_from(&mut buffer)?;
    nt_challenge_response.read_from(&mut buffer)?;
    domain_name.read_from(&mut buffer)?;
    user_name.read_from(&mut buffer)?;
    workstation.read_from(&mut buffer)?;
    encrypted_random_session_key.read_from(&mut buffer)?;
    let negotiate_flags =
        NegotiateFlags::from_bits(buffer.read_u32::<LittleEndian>()?).unwrap_or_else(NegotiateFlags::empty);

    let negotiate_key_exchange = negotiate_flags.contains(NegotiateFlags::NTLM_SSP_NEGOTIATE_KEY_EXCH);
    if negotiate_key_exchange && encrypted_random_session_key.buffer.is_empty()
        || !negotiate_key_exchange && !encrypted_random_session_key.buffer.is_empty()
    {
        return Err(crate::Error::new(
            crate::ErrorKind::InvalidToken,
            "Negotiate key exchange flag is set but encrypted random session key \
                 is empty or the flag is not set but the key is not empty",
        ));
    }

    if negotiate_key_exchange && encrypted_random_session_key.buffer.len() != ENCRYPTED_RANDOM_SESSION_KEY_SIZE {
        return Err(crate::Error::new(
            crate::ErrorKind::InvalidToken,
            "Invalid encrypted random session key",
        ));
    }

    let message_fields = AuthenticateMessageFields {
        workstation,
        domain_name,
        encrypted_random_session_key,
        user_name,
        lm_challenge_response,
        nt_challenge_response,
    };

    Ok((message_fields, negotiate_flags))
}

fn read_payload<T>(
    negotiate_flags: NegotiateFlags,
    message_fields: &mut AuthenticateMessageFields,
    buffer: &mut io::Cursor<T>,
) -> crate::Result<Option<Mic>>
where
    io::Cursor<T>: Read + io::Seek,
{
    let mic = if negotiate_flags.contains(NegotiateFlags::NTLM_SSP_NEGOTIATE_TARGET_INFO) {
        let mic_offset = buffer.position() as u8;
        let mut mic_value = [0x00; MESSAGE_INTEGRITY_CHECK_SIZE];
        buffer.read_exact(&mut mic_value)?;
        Some(Mic::new(mic_value, mic_offset))
    } else {
        None
    };

    message_fields.domain_name.read_buffer_from_cursor(buffer)?;
    message_fields.user_name.read_buffer_from_cursor(buffer)?;
    message_fields.workstation.read_buffer_from_cursor(buffer)?;
    message_fields.lm_challenge_response.read_buffer_from_cursor(buffer)?;
    message_fields.nt_challenge_response.read_buffer_from_cursor(buffer)?;
    message_fields
        .encrypted_random_session_key
        .read_buffer_from_cursor(buffer)?;

    Ok(mic)
}

fn process_message_fields(
    identity: &Option<AuthIdentityBuffers>,
    message_fields: AuthenticateMessageFields,
    mic: Option<Mic>,
    authenticate_message: Vec<u8>,
    channel_bindings: &Option<ChannelBindings>,
) -> crate::Result<(AuthenticateMessage, AuthIdentityBuffers)> {
    if message_fields.nt_challenge_response.buffer.is_empty() {
        return Err(crate::Error::new(
            crate::ErrorKind::InvalidToken,
            "NtChallengeResponse cannot be empty",
        ));
    }

    let (target_info, client_challenge) = read_ntlm_v2_response(message_fields.nt_challenge_response.buffer.as_ref())?;

    let av_pairs = AvPair::buffer_to_av_pairs(target_info.as_ref())?;

    let mic = if mic.is_some() {
        let challenge_response_av_flags = get_av_flags_from_response(&av_pairs)?;
        if challenge_response_av_flags.contains(MsvAvFlags::MESSAGE_INTEGRITY_CHECK) {
            mic
        } else {
            None
        }
    } else {
        None
    };

    if let Some(AvPair::ChannelBindings(hash)) = av_pairs
        .iter()
        .find(|av_pair| av_pair.as_u16() == AV_PAIR_CHANNEL_BINDINGS)
        && let Some(channel_bindings) = channel_bindings.as_ref()
        && compute_md5_channel_bindings_hash(channel_bindings) != *hash
    {
        return Err(crate::Error::new(
            crate::ErrorKind::BadBindings,
            "Channel bindings hash mismatch",
        ));
    }

    // will not set workstation because it is not used anywhere

    let encrypted_random_session_key: Option<[u8; ENCRYPTED_RANDOM_SESSION_KEY_SIZE]> = match message_fields
        .encrypted_random_session_key
        .buffer
        .len()
    {
        0 => None,
        ENCRYPTED_RANDOM_SESSION_KEY_SIZE => {
            let mut encrypted_random_session_key = [0x00; ENCRYPTED_RANDOM_SESSION_KEY_SIZE];
            encrypted_random_session_key.clone_from_slice(message_fields.encrypted_random_session_key.buffer.as_ref());
            Some(encrypted_random_session_key)
        }
        key_len => {
            return Err(crate::Error::new(
                crate::ErrorKind::InvalidToken,
                format!(
                    "Encrypted random session key has wrong length. Expected {ENCRYPTED_RANDOM_SESSION_KEY_SIZE} bytes, got {key_len} bytes."
                ),
            ));
        }
    };

    let mut identity = if let Some(identity) = identity {
        identity.clone()
    } else {
        AuthIdentityBuffers::default()
    };

    if !message_fields.user_name.buffer.is_empty() {
        identity.user = Utf16String::from_bytes_le(message_fields.user_name.buffer)?;
    }
    if !message_fields.domain_name.buffer.is_empty() {
        identity.domain = Utf16String::from_bytes_le(message_fields.domain_name.buffer)?;
    }

    Ok((
        AuthenticateMessage::new(
            authenticate_message,
            mic,
            target_info,
            client_challenge,
            encrypted_random_session_key,
        ),
        identity,
    ))
}

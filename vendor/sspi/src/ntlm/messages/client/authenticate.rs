use std::io;

use byteorder::{LittleEndian, WriteBytesExt};
use rand::rngs::{StdRng, SysRng};
use rand_core::{Rng as _, SeedableRng as _};

use crate::crypto::Rc4;
use crate::ntlm::messages::computations::*;
use crate::ntlm::messages::{
    CLIENT_SEAL_MAGIC, CLIENT_SIGN_MAGIC, MessageFields, MessageTypes, NTLM_SIGNATURE, NTLM_VERSION_SIZE,
    SERVER_SEAL_MAGIC, SERVER_SIGN_MAGIC,
};
use crate::ntlm::{
    AuthIdentityBuffers, AuthenticateMessage, ENCRYPTED_RANDOM_SESSION_KEY_SIZE, MESSAGE_INTEGRITY_CHECK_SIZE, Mic,
    NegotiateFlags, Ntlm, NtlmState, SESSION_KEY_SIZE,
};
use crate::{SecurityStatus, Utf16StringExt};

const MIC_SIZE: usize = 16;
const BASE_OFFSET: usize = 64;
const AUTH_MESSAGE_OFFSET: usize = BASE_OFFSET + NTLM_VERSION_SIZE + MIC_SIZE; // MIC is always used in NTLMv2

struct AuthenticateMessageFields {
    workstation: MessageFields,
    domain_name: MessageFields,
    encrypted_random_session_key: MessageFields,
    user_name: MessageFields,
    lm_challenge_response: MessageFields,
    nt_challenge_response: MessageFields,
}

impl AuthenticateMessageFields {
    pub(crate) fn new(
        identity: &AuthIdentityBuffers,
        lm_challenge_response: &[u8],
        nt_challenge_response: &[u8],
        negotiate_flags: NegotiateFlags,
        encrypted_random_session_key_buffer: &[u8],
        offset: u32,
    ) -> Self {
        let mut workstation = MessageFields::new();
        let mut domain_name = MessageFields::with_buffer(identity.domain.to_bytes_le());
        let mut encrypted_random_session_key = MessageFields::new();
        let mut user_name = MessageFields::with_buffer(identity.user.to_bytes_le());
        let mut lm_challenge_response = MessageFields::with_buffer(lm_challenge_response.to_vec());
        let mut nt_challenge_response = MessageFields::with_buffer(nt_challenge_response.to_vec());

        if negotiate_flags.contains(NegotiateFlags::NTLM_SSP_NEGOTIATE_KEY_EXCH) {
            encrypted_random_session_key.buffer = encrypted_random_session_key_buffer.to_vec();
        }

        // will not set workstation because it is not used anywhere

        domain_name.buffer_offset = offset;

        user_name.buffer_offset = domain_name.buffer_offset + domain_name.buffer.len() as u32;

        workstation.buffer_offset = user_name.buffer_offset + user_name.buffer.len() as u32;

        lm_challenge_response.buffer_offset = workstation.buffer_offset + workstation.buffer.len() as u32;

        nt_challenge_response.buffer_offset =
            lm_challenge_response.buffer_offset + lm_challenge_response.buffer.len() as u32;

        encrypted_random_session_key.buffer_offset =
            nt_challenge_response.buffer_offset + nt_challenge_response.buffer.len() as u32;

        Self {
            domain_name,
            user_name,
            workstation,
            lm_challenge_response,
            nt_challenge_response,
            encrypted_random_session_key,
        }
    }

    pub(crate) fn data_len(&self) -> usize {
        self.encrypted_random_session_key.buffer_offset as usize + self.encrypted_random_session_key.buffer.len()
    }
}

pub(crate) fn write_authenticate(
    context: &mut Ntlm,
    credentials: &AuthIdentityBuffers,
    mut transport: impl io::Write,
) -> crate::Result<SecurityStatus> {
    check_state(context.state)?;

    let negotiate_message = context
        .negotiate_message
        .as_ref()
        .expect("negotiate message must be set on negotiate phase");
    let challenge_message = context
        .challenge_message
        .as_ref()
        .expect("challenge message must be set on challenge phase");

    // calculate needed fields
    // NTLMv2
    let target_info = get_authenticate_target_info(
        challenge_message.target_info.as_ref(),
        context.channel_bindings.as_ref(),
        context.send_single_host_data,
    )?;

    let client_challenge = generate_challenge()?;
    let ntlm_v2_hash = compute_ntlm_v2_hash(credentials)?;
    let lm_challenge_response = compute_lm_v2_response(
        client_challenge.as_ref(),
        challenge_message.server_challenge.as_ref(),
        ntlm_v2_hash.as_ref(),
    )?;
    let (nt_challenge_response, key_exchange_key) = compute_ntlm_v2_response(
        client_challenge.as_ref(),
        challenge_message.server_challenge.as_ref(),
        target_info.as_ref(),
        ntlm_v2_hash.as_ref(),
        challenge_message.timestamp,
    )?;
    context.flags = get_flags(context, credentials);

    let session_key = if context.flags.contains(NegotiateFlags::NTLM_SSP_NEGOTIATE_KEY_EXCH) {
        let mut session_key = [0; SESSION_KEY_SIZE];
        let mut rand = StdRng::try_from_rng(&mut SysRng)?;
        rand.fill_bytes(session_key.as_mut());
        session_key
    } else {
        key_exchange_key
    };

    let encrypted_session_key_vec = Rc4::new(&key_exchange_key).process(session_key.as_ref());
    let mut encrypted_session_key = [0x00; ENCRYPTED_RANDOM_SESSION_KEY_SIZE];
    encrypted_session_key.clone_from_slice(encrypted_session_key_vec.as_ref());

    let message_fields = AuthenticateMessageFields::new(
        credentials,
        lm_challenge_response.as_ref(),
        nt_challenge_response.as_ref(),
        context.flags,
        encrypted_session_key.as_ref(),
        AUTH_MESSAGE_OFFSET as u32,
    );

    let mut buffer = Vec::with_capacity(message_fields.data_len());

    write_header(context.flags, context.version.as_ref(), &message_fields, &mut buffer)?;
    write_payload(&message_fields, &mut buffer)?;

    let message = buffer.clone();

    let mut buffer = io::Cursor::new(buffer);
    let mic = write_mic(
        negotiate_message.message.as_ref(),
        challenge_message.message.as_ref(),
        message.as_ref(),
        session_key.as_ref(),
        AUTH_MESSAGE_OFFSET as u8,
        &mut buffer,
    )?;

    transport.write_all(buffer.into_inner().as_slice())?;
    transport.flush()?;

    context.send_signing_key = generate_signing_key(session_key.as_ref(), CLIENT_SIGN_MAGIC);
    context.recv_signing_key = generate_signing_key(session_key.as_ref(), SERVER_SIGN_MAGIC);
    context.send_sealing_key = Some(Rc4::new(
        generate_signing_key(session_key.as_ref(), CLIENT_SEAL_MAGIC).as_ref(),
    ));
    context.recv_sealing_key = Some(Rc4::new(
        generate_signing_key(session_key.as_ref(), SERVER_SEAL_MAGIC).as_ref(),
    ));
    context.session_key = Some(session_key);

    context.authenticate_message = Some(AuthenticateMessage::new(
        message,
        Some(mic),
        target_info,
        client_challenge,
        Some(encrypted_session_key),
    ));
    context.state = NtlmState::Final;

    Ok(SecurityStatus::Ok)
}

fn check_state(state: NtlmState) -> crate::Result<()> {
    if state != NtlmState::Authenticate {
        Err(crate::Error::new(
            crate::ErrorKind::OutOfSequence,
            String::from("Write authenticate was fired but the state is not an Authenticate"),
        ))
    } else {
        Ok(())
    }
}

fn get_flags(context: &Ntlm, identity: &AuthIdentityBuffers) -> NegotiateFlags {
    // set KEY_EXCH flag if it was in the challenge message
    let mut flags = context.flags & NegotiateFlags::NTLM_SSP_NEGOTIATE_KEY_EXCH;

    if !identity.domain.is_empty() {
        flags |= NegotiateFlags::NTLM_SSP_NEGOTIATE_DOMAIN_SUPPLIED;
    }

    // will not set workstation because it is not used anywhere

    flags |= NegotiateFlags::NTLM_SSP_NEGOTIATE56
        | NegotiateFlags::NTLM_SSP_NEGOTIATE128
        | NegotiateFlags::NTLM_SSP_NEGOTIATE_ALWAYS_SIGN
        | NegotiateFlags::NTLM_SSP_NEGOTIATE_EXTENDED_SESSION_SECURITY
        | NegotiateFlags::NTLM_SSP_NEGOTIATE_NTLM
        | NegotiateFlags::NTLM_SSP_NEGOTIATE_REQUEST_TARGET
        | NegotiateFlags::NTLM_SSP_NEGOTIATE_UNICODE
        | NegotiateFlags::NTLM_SSP_NEGOTIATE_TARGET_INFO
        | NegotiateFlags::NTLM_SSP_NEGOTIATE_VERSION;

    if context.sealing {
        flags |= NegotiateFlags::NTLM_SSP_NEGOTIATE_SEAL;
    }

    if context.signing {
        flags |= NegotiateFlags::NTLM_SSP_NEGOTIATE_SIGN;
    }

    flags
}

fn write_header(
    negotiate_flags: NegotiateFlags,
    version: &[u8],
    message_fields: &AuthenticateMessageFields,
    mut buffer: impl io::Write,
) -> io::Result<()> {
    buffer.write_all(NTLM_SIGNATURE)?; // signature 8 bytes
    buffer.write_u32::<LittleEndian>(MessageTypes::Authenticate as u32)?; // message type 4 bytes
    message_fields.lm_challenge_response.write_to(&mut buffer)?; // LmChallengeResponseFields (8 bytes)
    message_fields.nt_challenge_response.write_to(&mut buffer)?; // NtChallengeResponseFields (8 bytes)
    message_fields.domain_name.write_to(&mut buffer)?; // DomainNameFields (8 bytes)
    message_fields.user_name.write_to(&mut buffer)?; // UserNameFields (8 bytes)
    message_fields.workstation.write_to(&mut buffer)?; // WorkstationFields (8 bytes)
    message_fields.encrypted_random_session_key.write_to(&mut buffer)?; // EncryptedRandomSessionKeyFields (8 bytes)
    buffer.write_u32::<LittleEndian>(negotiate_flags.bits())?; // NegotiateFlags (4 bytes)
    buffer.write_all(version)?;

    // use_mic always true, when ntlm_v2 is true
    // For now, just write zeros to the stream,
    // and write to this position an authenticate_message,
    // when will calc the authenticate_message
    buffer.write_all(&[0x00; MESSAGE_INTEGRITY_CHECK_SIZE])?;

    Ok(())
}

fn write_payload(message_fields: &AuthenticateMessageFields, mut buffer: impl io::Write) -> io::Result<()> {
    message_fields.domain_name.write_buffer_to(&mut buffer)?;
    message_fields.user_name.write_buffer_to(&mut buffer)?;
    message_fields.workstation.write_buffer_to(&mut buffer)?;
    message_fields.lm_challenge_response.write_buffer_to(&mut buffer)?;
    message_fields.nt_challenge_response.write_buffer_to(&mut buffer)?;
    message_fields
        .encrypted_random_session_key
        .write_buffer_to(&mut buffer)?;

    Ok(())
}

fn write_mic(
    negotiate_message: &[u8],
    challenge_message: &[u8],
    authenticate_message: &[u8],
    exported_session_key: &[u8],
    offset: u8,
    mut buffer: impl io::Write + io::Seek,
) -> crate::Result<Mic> {
    let mic = Mic {
        offset: offset - MIC_SIZE as u8,
        value: compute_message_integrity_check(
            negotiate_message,
            challenge_message,
            authenticate_message,
            exported_session_key,
        )?,
    };

    buffer.seek(io::SeekFrom::Start(u64::from(mic.offset)))?;
    buffer.write_all(&mic.value)?;
    buffer.seek(io::SeekFrom::End(0))?;

    Ok(mic)
}

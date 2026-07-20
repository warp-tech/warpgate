use std::io;

use byteorder::{LittleEndian, WriteBytesExt};

use crate::SecurityStatus;
use crate::ntlm::messages::computations::*;
use crate::ntlm::messages::{MessageFields, MessageTypes, NTLM_SIGNATURE, NTLM_VERSION_SIZE};
use crate::ntlm::{ChallengeMessage, NegotiateFlags, Ntlm, NtlmState};

const BASE_OFFSET: usize = 48;
const CHALLENGE_MESSAGE_OFFSET: usize = BASE_OFFSET + NTLM_VERSION_SIZE;

struct ChallengeMessageFields {
    target_name: MessageFields,
    target_info: MessageFields,
}

impl ChallengeMessageFields {
    fn new(target_info: &[u8], offset: u32) -> Self {
        let mut target_info = MessageFields::with_buffer(target_info.to_vec());
        let mut target_name = MessageFields::new();

        // will not set target name because it is not used anywhere

        target_name.buffer_offset = offset;
        target_info.buffer_offset = target_name.buffer_offset + target_name.buffer.len() as u32;

        ChallengeMessageFields {
            target_name,
            target_info,
        }
    }

    fn data_len(&self) -> usize {
        self.target_info.buffer_offset as usize + self.target_info.buffer.len()
    }
}

pub(crate) fn write_challenge(context: &mut Ntlm, mut transport: impl io::Write) -> crate::Result<SecurityStatus> {
    check_state(context.state)?;

    let server_challenge = generate_challenge()?;
    let timestamp = now_file_time_timestamp()?;
    let target_info = get_challenge_target_info(timestamp)?;

    context.flags = get_flags(context.flags);
    let message_fields = ChallengeMessageFields::new(target_info.as_ref(), CHALLENGE_MESSAGE_OFFSET as u32);

    let mut buffer = io::Cursor::new(Vec::with_capacity(message_fields.data_len()));

    write_header(
        context.flags,
        server_challenge.as_ref(),
        context.version.as_ref(),
        &message_fields,
        &mut buffer,
    )?;
    write_payload(&message_fields, &mut buffer)?;

    let message = buffer.into_inner();

    transport.write_all(message.as_slice())?;
    transport.flush()?;

    context.challenge_message = Some(ChallengeMessage::new(message, target_info, server_challenge, timestamp));
    context.state = NtlmState::Authenticate;

    Ok(SecurityStatus::ContinueNeeded)
}

fn check_state(state: NtlmState) -> crate::Result<()> {
    if state != NtlmState::Challenge {
        Err(crate::Error::new(
            crate::ErrorKind::OutOfSequence,
            String::from("Write challenge was fired but the state is not a Challenge"),
        ))
    } else {
        Ok(())
    }
}

fn get_flags(negotiate_flags: NegotiateFlags) -> NegotiateFlags {
    negotiate_flags | NegotiateFlags::NTLM_SSP_NEGOTIATE_TARGET_INFO
}

fn write_header(
    negotiate_flags: NegotiateFlags,
    server_challenge: &[u8],
    version: &[u8],
    message_fields: &ChallengeMessageFields,
    mut buffer: impl io::Write,
) -> io::Result<()> {
    buffer.write_all(NTLM_SIGNATURE)?; // signature 8 bytes
    buffer.write_u32::<LittleEndian>(MessageTypes::Challenge as u32)?; // message type 4 bytes
    message_fields.target_name.write_to(&mut buffer)?; // target name fields 8 bytes
    buffer.write_u32::<LittleEndian>(negotiate_flags.bits())?; // negotiate flags 4 bytes
    buffer.write_all(server_challenge)?; // server challenge 8 bytes
    buffer.write_u64::<LittleEndian>(0x00)?; // reserved 8 bytes
    message_fields.target_info.write_to(&mut buffer)?; // target info fields 8 bytes
    buffer.write_all(version)?; // version 8 bytes

    Ok(())
}

fn write_payload(message_fields: &ChallengeMessageFields, mut buffer: impl io::Write) -> io::Result<()> {
    message_fields.target_name.write_buffer_to(&mut buffer)?;
    message_fields.target_info.write_buffer_to(&mut buffer)?;

    Ok(())
}

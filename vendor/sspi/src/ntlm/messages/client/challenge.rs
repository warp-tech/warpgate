use std::io;

use byteorder::{LittleEndian, ReadBytesExt};

use crate::SecurityStatus;
use crate::ntlm::messages::computations::*;
use crate::ntlm::messages::{MessageFields, MessageTypes, read_ntlm_header, try_read_version};
use crate::ntlm::{CHALLENGE_SIZE, ChallengeMessage, NegotiateFlags, Ntlm, NtlmState};

const HEADER_SIZE: usize = 48;

struct ChallengeMessageFields {
    target_name: MessageFields,
    target_info: MessageFields,
}

pub(crate) fn read_challenge(context: &mut Ntlm, mut stream: impl io::Read) -> crate::Result<SecurityStatus> {
    check_state(context.state)?;

    let mut buffer = Vec::with_capacity(HEADER_SIZE);
    stream.read_to_end(&mut buffer)?;
    let mut buffer = io::Cursor::new(buffer);

    read_ntlm_header(&mut buffer, MessageTypes::Challenge)?;
    let (mut message_fields, flags, server_challenge) = read_header(&mut buffer)?;
    context.flags = flags;
    let _version = try_read_version(context.flags, &mut buffer)?;
    read_payload(&mut message_fields, &mut buffer)?;
    let timestamp = get_challenge_timestamp_from_response(message_fields.target_info.buffer.as_ref())?;

    let message = buffer.into_inner();
    context.challenge_message = Some(ChallengeMessage::new(
        message,
        message_fields.target_info.buffer,
        server_challenge,
        timestamp,
    ));

    context.state = NtlmState::Authenticate;

    Ok(SecurityStatus::ContinueNeeded)
}

fn check_state(state: NtlmState) -> crate::Result<()> {
    if state != NtlmState::Challenge {
        Err(crate::Error::new(
            crate::ErrorKind::OutOfSequence,
            String::from("Read challenge was fired but the state is not a Challenge"),
        ))
    } else {
        Ok(())
    }
}

fn read_header(
    mut buffer: impl io::Read,
) -> crate::Result<(ChallengeMessageFields, NegotiateFlags, [u8; CHALLENGE_SIZE])> {
    let mut target_name = MessageFields::new();
    let mut target_info = MessageFields::new();

    target_name.read_from(&mut buffer)?;
    let negotiate_flags =
        NegotiateFlags::from_bits(buffer.read_u32::<LittleEndian>()?).unwrap_or_else(NegotiateFlags::empty);
    let mut server_challenge = [0x00; CHALLENGE_SIZE];
    buffer.read_exact(&mut server_challenge)?;
    let _reserved = buffer.read_u64::<LittleEndian>()?;
    target_info.read_from(&mut buffer)?;

    let message_fields = ChallengeMessageFields {
        target_name,
        target_info,
    };

    Ok((message_fields, negotiate_flags, server_challenge))
}

fn read_payload(
    message_fields: &mut ChallengeMessageFields,
    mut buffer: impl io::Read + io::Seek,
) -> crate::Result<()> {
    message_fields.target_name.read_buffer_from(&mut buffer)?;
    message_fields.target_info.read_buffer_from(&mut buffer)?;

    Ok(())
}

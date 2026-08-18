use std::io;

use byteorder::{LittleEndian, WriteBytesExt};

use crate::SecurityStatus;
use crate::ntlm::messages::{MessageFields, MessageTypes, NTLM_SIGNATURE, NTLM_VERSION_SIZE};
use crate::ntlm::{NegotiateFlags, NegotiateMessage, Ntlm, NtlmState};

const HEADER_SIZE: usize = 32;
const NEGO_MESSAGE_OFFSET: usize = HEADER_SIZE + NTLM_VERSION_SIZE;

struct NegotiateMessageFields {
    domain_name: MessageFields,
    workstation: MessageFields,
}

impl NegotiateMessageFields {
    pub(crate) fn new(offset: u32, workstation: Option<Vec<u8>>) -> Self {
        let mut domain_name = MessageFields::new();
        let mut workstation = MessageFields::with_buffer(workstation.unwrap_or_default());

        domain_name.buffer_offset = offset;
        workstation.buffer_offset = domain_name.buffer_offset + domain_name.buffer.len() as u32;

        NegotiateMessageFields {
            domain_name,
            workstation,
        }
    }

    pub(crate) fn data_len(&self) -> usize {
        self.workstation.buffer_offset as usize + self.workstation.buffer.len()
    }
}

fn check_state(state: NtlmState) -> crate::Result<()> {
    if state != NtlmState::Negotiate {
        Err(crate::Error::new(
            crate::ErrorKind::OutOfSequence,
            String::from("Write negotiate was fired but the state is not a Negotiate"),
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn write_negotiate(context: &mut Ntlm, mut transport: impl io::Write) -> crate::Result<SecurityStatus> {
    check_state(context.state)?;

    let negotiate_flags = get_flags(context);
    let message_fields = NegotiateMessageFields::new(
        NEGO_MESSAGE_OFFSET as u32,
        context
            .config
            .client_computer_name
            .as_ref()
            .map(|workstation| workstation.as_bytes().to_vec()),
    );

    let mut buffer = Vec::with_capacity(message_fields.data_len());

    write_header(negotiate_flags, context.version.as_ref(), &message_fields, &mut buffer)?;
    write_payload(&message_fields, &mut buffer)?;
    context.flags = negotiate_flags;

    let message = buffer;

    transport.write_all(message.as_slice())?;
    transport.flush()?;

    context.negotiate_message = Some(NegotiateMessage::new(message));
    context.state = NtlmState::Challenge;

    Ok(SecurityStatus::ContinueNeeded)
}

fn get_flags(context: &Ntlm) -> NegotiateFlags {
    let mut flags = NegotiateFlags::NTLM_SSP_NEGOTIATE56
        | NegotiateFlags::NTLM_SSP_NEGOTIATE_OEM
        | NegotiateFlags::NTLM_SSP_NEGOTIATE128
        | NegotiateFlags::NTLM_SSP_NEGOTIATE_ALWAYS_SIGN
        | NegotiateFlags::NTLM_SSP_NEGOTIATE_EXTENDED_SESSION_SECURITY
        | NegotiateFlags::NTLM_SSP_NEGOTIATE_NTLM
        | NegotiateFlags::NTLM_SSP_NEGOTIATE_REQUEST_TARGET
        | NegotiateFlags::NTLM_SSP_NEGOTIATE_UNICODE
        | NegotiateFlags::NTLM_SSP_NEGOTIATE_VERSION;

    if context.sealing {
        flags |= NegotiateFlags::NTLM_SSP_NEGOTIATE_LM_KEY;
        flags |= NegotiateFlags::NTLM_SSP_NEGOTIATE_SEAL;
        flags |= NegotiateFlags::NTLM_SSP_NEGOTIATE_KEY_EXCH;
    }

    if context.signing {
        flags |= NegotiateFlags::NTLM_SSP_NEGOTIATE_SIGN;
    }

    if context.config().client_computer_name.is_some() {
        flags |= NegotiateFlags::NTLM_SSP_NEGOTIATE_WORKSTATION_SUPPLIED;
    }

    flags
}

fn write_header(
    negotiate_flags: NegotiateFlags,
    version: &[u8],
    message_fields: &NegotiateMessageFields,
    mut buffer: impl io::Write,
) -> io::Result<()> {
    buffer.write_all(NTLM_SIGNATURE)?; // signature 8 bytes
    buffer.write_u32::<LittleEndian>(MessageTypes::Negotiate as u32)?; // message type 4 bytes
    buffer.write_u32::<LittleEndian>(negotiate_flags.bits())?; // negotiate flags 4 bytes
    message_fields.domain_name.write_to(&mut buffer)?; // domain name 8 bytes
    message_fields.workstation.write_to(&mut buffer)?; // workstation 8 bytes
    buffer.write_all(version)?;

    Ok(())
}

fn write_payload(message_fields: &NegotiateMessageFields, mut buffer: impl io::Write) -> io::Result<()> {
    message_fields.domain_name.write_buffer_to(&mut buffer)?;
    message_fields.workstation.write_buffer_to(&mut buffer)?;

    Ok(())
}

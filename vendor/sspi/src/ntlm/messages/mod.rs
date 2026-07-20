pub(super) mod client;
pub(super) mod server;
#[cfg(test)]
pub(super) mod test;

mod av_pair;
pub(super) mod computations;

use std::io;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use crate::ntlm::{NTLM_VERSION_SIZE, NegotiateFlags};

const NTLM_SIGNATURE: &[u8; NTLM_SIGNATURE_SIZE] = b"NTLMSSP\0";
const NTLM_SIGNATURE_SIZE: usize = 8;

const MAGIC_SIZE: usize = 59;
pub(super) const CLIENT_SIGN_MAGIC: &[u8; MAGIC_SIZE] = b"session key to client-to-server signing key magic constant\0";
pub(super) const SERVER_SIGN_MAGIC: &[u8; MAGIC_SIZE] = b"session key to server-to-client signing key magic constant\0";
pub(super) const CLIENT_SEAL_MAGIC: &[u8; MAGIC_SIZE] = b"session key to client-to-server sealing key magic constant\0";
pub(super) const SERVER_SEAL_MAGIC: &[u8; MAGIC_SIZE] = b"session key to server-to-client sealing key magic constant\0";

#[derive(Clone, Copy)]
pub(super) enum MessageTypes {
    Negotiate = 1,
    Challenge = 2,
    Authenticate = 3,
}

pub(super) struct MessageFields {
    buffer: Vec<u8>,
    buffer_offset: u32,
}

impl MessageFields {
    fn new() -> Self {
        Self {
            buffer: Vec::new(),
            buffer_offset: 0,
        }
    }
    fn with_buffer(buffer: Vec<u8>) -> Self {
        Self {
            buffer,
            buffer_offset: 0,
        }
    }
    fn write_to(&self, mut buffer: impl io::Write) -> io::Result<()> {
        buffer.write_u16::<LittleEndian>(self.buffer.len() as u16)?; // Len
        buffer.write_u16::<LittleEndian>(self.buffer.len() as u16)?; // MaxLen
        buffer.write_u32::<LittleEndian>(self.buffer_offset)?; // BufferOffset

        Ok(())
    }
    fn write_buffer_to(&self, mut buffer: impl io::Write) -> io::Result<()> {
        buffer.write_all(&self.buffer)?;

        Ok(())
    }
    fn read_from(&mut self, mut buffer: impl io::Read) -> io::Result<()> {
        let len = buffer.read_u16::<LittleEndian>()?; // Len
        let _max_len = buffer.read_u16::<LittleEndian>()?; // MaxLen
        self.buffer_offset = buffer.read_u32::<LittleEndian>()?; // BufferOffset
        self.buffer.resize(len as usize, 0x00);
        Ok(())
    }
    fn read_buffer_from(&mut self, mut cursor: impl io::Read + io::Seek) -> io::Result<()> {
        cursor.seek(io::SeekFrom::Start(u64::from(self.buffer_offset)))?;
        cursor.read_exact(&mut self.buffer)?;

        Ok(())
    }

    fn read_buffer_from_cursor<T>(&mut self, cursor: &mut io::Cursor<T>) -> io::Result<()>
    where
        io::Cursor<T>: io::Read + io::Seek,
    {
        self.read_buffer_from(cursor)
    }
}

fn try_read_version(flags: NegotiateFlags, mut cursor: impl io::Read) -> io::Result<Option<[u8; NTLM_VERSION_SIZE]>> {
    if flags.contains(NegotiateFlags::NTLM_SSP_NEGOTIATE_VERSION) {
        // major version 1 byte
        // minor version 1 byte
        // product build 2 bytes
        // reserved 3 bytes
        // ntlm revision current 1 byte
        let mut version = [0x00; NTLM_VERSION_SIZE];
        cursor.read_exact(version.as_mut())?;

        Ok(Some(version))
    } else {
        Ok(None)
    }
}

pub(super) fn read_ntlm_header(mut stream: impl io::Read, expected_message_type: MessageTypes) -> crate::Result<()> {
    let mut signature = [0x00; NTLM_SIGNATURE_SIZE];
    stream.read_exact(signature.as_mut())?;
    let message_type = stream.read_u32::<LittleEndian>()?;

    if signature.as_ref() != NTLM_SIGNATURE {
        return Err(crate::Error::new(
            crate::ErrorKind::InvalidToken,
            format!("Read NTLM signature is invalid: {signature:?}"),
        ));
    }
    if message_type != expected_message_type as u32 {
        return Err(crate::Error::new(
            crate::ErrorKind::InvalidToken,
            format!(
                "Message type is invalid: {} != expected ({})",
                message_type, expected_message_type as u32
            ),
        ));
    }

    Ok(())
}

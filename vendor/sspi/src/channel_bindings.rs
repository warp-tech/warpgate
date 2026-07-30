use crate::{Error, ErrorKind, Result};

// size of SEC_CHANNEL_BINDINGS structure
const SEC_CHANNEL_BINDINGS_SIZE: usize = 32;

/// [SEC_CHANNEL_BINDINGS](https://docs.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-sec_channel_bindings)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelBindings {
    pub initiator_addr_type: u32,
    pub initiator: Vec<u8>,
    pub acceptor_addr_type: u32,
    pub acceptor: Vec<u8>,
    pub application_data: Vec<u8>,
}

impl ChannelBindings {
    pub fn from_bytes<T: AsRef<[u8]>>(data: T) -> Result<Self> {
        let data = data.as_ref();

        if data.len() < SEC_CHANNEL_BINDINGS_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidParameter,
                format!(
                    "Invalid SEC_CHANNEL_BINDINGS buffer: buffer is too short: {}. Minimum len: {}",
                    data.len(),
                    SEC_CHANNEL_BINDINGS_SIZE,
                ),
            ));
        }

        let initiator_addr_type = u32::from_le_bytes(data[0..4].try_into().unwrap());

        let initiator_len = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
        let initiator_offset = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
        if initiator_offset + initiator_len > data.len() {
            return Err(Error::new(
                ErrorKind::InvalidParameter,
                format!(
                    "Invalid SEC_CHANNEL_BINDINGS buffer: initiator offset + len ({}) goes outside the buffer ({})",
                    initiator_offset + initiator_len,
                    data.len()
                ),
            ));
        }

        let initiator = if initiator_len > 0 {
            data[initiator_offset..(initiator_offset + initiator_len)].to_vec()
        } else {
            Vec::new()
        };

        let acceptor_addr_type = u32::from_le_bytes(data[12..16].try_into().unwrap());

        let acceptor_len = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;
        let acceptor_offset = u32::from_le_bytes(data[20..24].try_into().unwrap()) as usize;
        if acceptor_offset + acceptor_len > data.len() {
            return Err(Error::new(
                ErrorKind::InvalidParameter,
                format!(
                    "Invalid SEC_CHANNEL_BINDINGS buffer: acceptor offset + len ({}) goes outside the buffer ({})",
                    acceptor_offset + acceptor_len,
                    data.len()
                ),
            ));
        }

        let acceptor = if acceptor_len > 0 {
            data[acceptor_offset..(acceptor_offset + acceptor_len)].to_vec()
        } else {
            Vec::new()
        };

        let application_len = u32::from_le_bytes(data[24..28].try_into().unwrap()) as usize;
        let application_offset = u32::from_le_bytes(data[28..32].try_into().unwrap()) as usize;
        if application_offset + application_len > data.len() {
            return Err(Error::new(
                ErrorKind::InvalidParameter,
                format!(
                    "Invalid SEC_CHANNEL_BINDINGS buffer: application offset + len ({}) goes outside the buffer ({})",
                    application_offset + application_len,
                    data.len()
                ),
            ));
        }

        let application_data = if application_len > 0 {
            data[application_offset..(application_offset + application_len)].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            initiator_addr_type,
            initiator,
            acceptor_addr_type,
            acceptor,
            application_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::ChannelBindings;

    #[test]
    fn from_bytes() {
        let expected = ChannelBindings {
            initiator_addr_type: 0,
            initiator: Vec::new(),
            acceptor_addr_type: 0,
            acceptor: Vec::new(),
            application_data: vec![1, 2, 3, 4],
        };

        let channel_bindings_token = [1, 2, 3, 4];
        let application_offset = 32_u32;
        let application_len = channel_bindings_token.len();

        let mut buffer = [0; 36];

        buffer[24..28].copy_from_slice(&(application_len as u32).to_le_bytes());
        buffer[28..32].copy_from_slice(&application_offset.to_le_bytes());
        buffer[32..].copy_from_slice(&channel_bindings_token);

        let channel_bindings = ChannelBindings::from_bytes(buffer).unwrap();

        assert_eq!(channel_bindings, expected);
    }

    #[test]
    fn too_small_buffer() {
        assert!(ChannelBindings::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]).is_err());

        assert!(ChannelBindings::from_bytes([]).is_err());
    }

    #[test]
    fn invalid_len() {
        let channel_bindings_token = [1, 2, 3, 4];
        let application_offset = 32_u32;
        // invalid len
        let application_len = channel_bindings_token.len() + 2;

        let mut buffer = [0; 36];

        buffer[24..28].copy_from_slice(&(application_len as u32).to_le_bytes());
        buffer[28..32].copy_from_slice(&application_offset.to_le_bytes());
        buffer[32..].copy_from_slice(&channel_bindings_token);

        let channel_bindings = ChannelBindings::from_bytes(buffer);

        assert!(channel_bindings.is_err());
    }

    #[test]
    fn invalid_offset() {
        let channel_bindings_token = [1, 2, 3, 4];
        // invalid offset
        let application_offset = 32_u32 + 3;
        let application_len = channel_bindings_token.len();

        let mut buffer = [0; 36];

        buffer[24..28].copy_from_slice(&(application_len as u32).to_le_bytes());
        buffer[28..32].copy_from_slice(&application_offset.to_le_bytes());
        buffer[32..].copy_from_slice(&channel_bindings_token);

        let channel_bindings = ChannelBindings::from_bytes(buffer);

        assert!(channel_bindings.is_err());
    }
}

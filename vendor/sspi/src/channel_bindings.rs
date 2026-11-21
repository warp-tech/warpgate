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

        let initiator_len: usize = u32::from_le_bytes(data[4..8].try_into().unwrap()).try_into()?;

        let initiator_offset: usize = u32::from_le_bytes(data[8..12].try_into().unwrap()).try_into()?;

        let initiator = if initiator_len > 0 {
            let Some(initiator_data) = data.get(initiator_offset..(initiator_offset + initiator_len)) else {
                return Err(Error::new(
                    ErrorKind::InvalidParameter,
                    format!(
                        "Invalid SEC_CHANNEL_BINDINGS buffer: initiator offset + len ({}) goes outside the buffer ({})",
                        initiator_offset + initiator_len,
                        data.len()
                    ),
                ));
            };

            initiator_data.to_vec()
        } else {
            Vec::new()
        };

        let acceptor_addr_type = u32::from_le_bytes(
            data[12..16]
                .try_into()
                .expect("data[12..16] is castable to [u8; 4] because of prior check"),
        );

        let acceptor_len: usize = u32::from_le_bytes(
            data[16..20]
                .try_into()
                .expect("data[16..20] is castable to [u8; 4] because of prior check"),
        )
        .try_into()?;

        let acceptor_offset: usize = u32::from_le_bytes(
            data[20..24]
                .try_into()
                .expect("data[20..24] is castable to [u8; 4] because of prior check"),
        )
        .try_into()?;

        let acceptor = if acceptor_len > 0 {
            let Some(acceptor) = data.get(acceptor_offset..(acceptor_offset + acceptor_len)) else {
                return Err(Error::new(
                    ErrorKind::InvalidParameter,
                    format!(
                        "Invalid SEC_CHANNEL_BINDINGS buffer: acceptor offset + len ({}) goes outside the buffer ({})",
                        acceptor_offset + acceptor_len,
                        data.len()
                    ),
                ));
            };

            acceptor.to_vec()
        } else {
            Vec::new()
        };

        let application_len: usize = u32::from_le_bytes(
            data[24..28]
                .try_into()
                .expect("data[24..28] is castable to [u8; 4] because of prior check"),
        )
        .try_into()?;

        let application_offset: usize = u32::from_le_bytes(
            data[28..32]
                .try_into()
                .expect("data[28..32] is castable to [u8; 4] because of prior check"),
        )
        .try_into()?;

        let application_data = if application_len > 0 {
            let Some(application_data) = data.get(application_offset..(application_offset + application_len)) else {
                return Err(Error::new(
                    ErrorKind::InvalidParameter,
                    format!(
                        "Invalid SEC_CHANNEL_BINDINGS buffer: application offset + len ({}) goes outside the buffer ({})",
                        application_offset + application_len,
                        data.len()
                    ),
                ));
            };

            application_data.to_vec()
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
        let application_len = u32::try_from(channel_bindings_token.len()).unwrap();

        let mut buffer = [0; 36];

        buffer[24..28].copy_from_slice(&application_len.to_le_bytes());
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
        let application_len = u32::try_from(channel_bindings_token.len() + 2).unwrap();

        let mut buffer = [0; 36];

        buffer[24..28].copy_from_slice(&application_len.to_le_bytes());
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
        let application_len = u32::try_from(channel_bindings_token.len()).unwrap();

        let mut buffer = [0; 36];

        buffer[24..28].copy_from_slice(&application_len.to_le_bytes());
        buffer[28..32].copy_from_slice(&application_offset.to_le_bytes());
        buffer[32..].copy_from_slice(&channel_bindings_token);

        let channel_bindings = ChannelBindings::from_bytes(buffer);

        assert!(channel_bindings.is_err());
    }
}

use std::io;

use bitflags::bitflags;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use crate::crypto::HASH_SIZE;
use crate::ntlm::messages::computations::SINGLE_HOST_DATA_SIZE;

pub(super) const AV_PAIR_ID_BYTES_SIZE: usize = 2;
pub(super) const AV_PAIR_LEN_BYTES_SIZE: usize = 2;

pub(super) const AV_PAIR_EOL: u16 = 0;
pub(super) const AV_PAIR_NB_COMPUTER_NAME: u16 = 1;
pub(super) const AV_PAIR_NB_DOMAIN_NAME: u16 = 2;
pub(super) const AV_PAIR_DNS_COMPUTER_NAME: u16 = 3;
pub(super) const AV_PAIR_DNS_DOMAIN_NAME: u16 = 4;
pub(super) const AV_PAIR_DNS_TREE_NAME: u16 = 5;
pub(super) const AV_PAIR_FLAGS: u16 = 6;
pub(super) const AV_PAIR_TIMESTAMP: u16 = 7;
pub(super) const AV_PAIR_SINGLE_HOST: u16 = 8;
pub(super) const AV_PAIR_TARGET_NAME: u16 = 9;
pub(super) const AV_PAIR_CHANNEL_BINDINGS: u16 = 10;

const AV_PAIR_EOL_SIZE: usize = 0;
const AV_PAIR_FLAGS_SIZE: usize = 4;
const AV_PAIR_TIMESTAMP_SIZE: usize = 8;

#[derive(Clone)]
#[allow(clippy::upper_case_acronyms)]
pub(super) enum AvPair {
    EOL,
    NbComputerName(Vec<u8>),
    NbDomainName(Vec<u8>),
    DnsComputerName(Vec<u8>),
    DnsDomainName(Vec<u8>),
    DnsTreeName(Vec<u8>),
    Flags(u32),
    Timestamp(u64),
    SingleHost([u8; SINGLE_HOST_DATA_SIZE]),
    TargetName(Vec<u8>),
    ChannelBindings([u8; HASH_SIZE]),
}

impl AvPair {
    pub(super) fn from_buffer(mut buffer: impl io::Read) -> io::Result<Self> {
        let av_type = buffer.read_u16::<LittleEndian>()?;
        let len = buffer.read_u16::<LittleEndian>()? as usize;

        match av_type {
            AV_PAIR_EOL => {
                if len != AV_PAIR_EOL_SIZE {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Got EOL AvPair with len {len} != {AV_PAIR_EOL_SIZE}"),
                    ))
                } else {
                    Ok(AvPair::EOL)
                }
            }
            AV_PAIR_NB_COMPUTER_NAME
            | AV_PAIR_NB_DOMAIN_NAME
            | AV_PAIR_DNS_COMPUTER_NAME
            | AV_PAIR_DNS_DOMAIN_NAME
            | AV_PAIR_DNS_TREE_NAME
            | AV_PAIR_TARGET_NAME => {
                let mut value = vec![0x00; len];
                buffer.read_exact(value.as_mut())?;

                match av_type {
                    AV_PAIR_NB_COMPUTER_NAME => Ok(AvPair::NbComputerName(value)),
                    AV_PAIR_NB_DOMAIN_NAME => Ok(AvPair::NbDomainName(value)),
                    AV_PAIR_DNS_COMPUTER_NAME => Ok(AvPair::DnsComputerName(value)),
                    AV_PAIR_DNS_DOMAIN_NAME => Ok(AvPair::DnsDomainName(value)),
                    AV_PAIR_DNS_TREE_NAME => Ok(AvPair::DnsTreeName(value)),
                    AV_PAIR_TARGET_NAME => Ok(AvPair::TargetName(value)),
                    _ => unreachable!(),
                }
            }
            AV_PAIR_FLAGS => {
                if len != AV_PAIR_FLAGS_SIZE {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Got Flags AvPair with len {len} != {AV_PAIR_FLAGS_SIZE}"),
                    ))
                } else {
                    Ok(AvPair::Flags(buffer.read_u32::<LittleEndian>()?))
                }
            }
            AV_PAIR_TIMESTAMP => {
                if len != AV_PAIR_TIMESTAMP_SIZE {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Got Timestamp AvPair with len {len} != {AV_PAIR_TIMESTAMP_SIZE}"),
                    ))
                } else {
                    Ok(AvPair::Timestamp(buffer.read_u64::<LittleEndian>()?))
                }
            }
            AV_PAIR_SINGLE_HOST => {
                // MS-NLMP: "Any fields after the MachineID field MUST be ignored on receipt."
                // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/f221c061-cc40-4471-95da-d2ff71c85c5b
                // Windows 11 Build 26200+ sends 80 bytes instead of the traditional 48.
                if len < SINGLE_HOST_DATA_SIZE {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Got SingleHost AvPair with len {len} < {SINGLE_HOST_DATA_SIZE}"),
                    ))
                } else {
                    let mut value = [0x00; SINGLE_HOST_DATA_SIZE];
                    buffer.read_exact(value.as_mut())?;

                    // Skip any trailing bytes beyond SINGLE_HOST_DATA_SIZE
                    let trailing = len - SINGLE_HOST_DATA_SIZE;
                    if trailing > 0 {
                        let mut discard = vec![0x00; trailing];
                        buffer.read_exact(discard.as_mut())?;
                    }

                    Ok(AvPair::SingleHost(value))
                }
            }
            AV_PAIR_CHANNEL_BINDINGS => {
                if len != HASH_SIZE {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Got ChannelBindings AvPair with len {len} != {HASH_SIZE}"),
                    ))
                } else {
                    let mut value = [0x00; HASH_SIZE];
                    buffer.read_exact(value.as_mut())?;

                    Ok(AvPair::ChannelBindings(value))
                }
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid AvType: '{av_type}'"),
            )),
        }
    }
    pub(super) fn buffer_to_av_pairs(mut buffer: &[u8]) -> io::Result<Vec<Self>> {
        let mut av_pairs = Vec::new();
        while !buffer.is_empty() {
            av_pairs.push(AvPair::from_buffer(&mut buffer)?);
        }

        Ok(av_pairs)
    }
    pub(super) fn list_to_buffer(av_pairs: &[AvPair]) -> io::Result<Vec<u8>> {
        let mut buffer = Vec::with_capacity(av_pairs.len() * (AV_PAIR_ID_BYTES_SIZE + AV_PAIR_LEN_BYTES_SIZE));
        for av_pair in av_pairs.iter() {
            av_pair.write_to(&mut buffer)?;
        }

        Ok(buffer)
    }
    pub(super) fn write_to(&self, mut buffer: impl io::Write) -> io::Result<()> {
        let av_type = self.as_u16();
        let (len, value) = match self {
            AvPair::EOL => (AV_PAIR_EOL_SIZE, Vec::new()),
            AvPair::NbComputerName(value)
            | AvPair::NbDomainName(value)
            | AvPair::DnsComputerName(value)
            | AvPair::DnsDomainName(value)
            | AvPair::DnsTreeName(value)
            | AvPair::TargetName(value) => (value.len(), value.clone()),
            AvPair::Flags(value) => (AV_PAIR_FLAGS_SIZE, value.to_le_bytes().to_vec()),
            AvPair::Timestamp(value) => (AV_PAIR_TIMESTAMP_SIZE, value.to_le_bytes().to_vec()),
            AvPair::SingleHost(value) => (SINGLE_HOST_DATA_SIZE, value.to_vec()),
            AvPair::ChannelBindings(value) => (HASH_SIZE, value.to_vec()),
        };
        buffer.write_u16::<LittleEndian>(av_type)?;
        buffer.write_u16::<LittleEndian>(len as u16)?;
        buffer.write_all(value.as_ref())?;

        Ok(())
    }
    pub(super) fn as_u16(&self) -> u16 {
        match self {
            AvPair::EOL => AV_PAIR_EOL,
            AvPair::NbComputerName(_) => AV_PAIR_NB_COMPUTER_NAME,
            AvPair::NbDomainName(_) => AV_PAIR_NB_DOMAIN_NAME,
            AvPair::DnsComputerName(_) => AV_PAIR_DNS_COMPUTER_NAME,
            AvPair::DnsDomainName(_) => AV_PAIR_DNS_DOMAIN_NAME,
            AvPair::DnsTreeName(_) => AV_PAIR_DNS_TREE_NAME,
            AvPair::TargetName(_) => AV_PAIR_TARGET_NAME,
            AvPair::Flags(_) => AV_PAIR_FLAGS,
            AvPair::Timestamp(_) => AV_PAIR_TIMESTAMP,
            AvPair::SingleHost(_) => AV_PAIR_SINGLE_HOST,
            AvPair::ChannelBindings(_) => AV_PAIR_CHANNEL_BINDINGS,
        }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct MsvAvFlags: u32 {
        const MESSAGE_INTEGRITY_CHECK = 0x0000_0002;
    }
}

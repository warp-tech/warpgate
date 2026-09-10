#[cfg(test)]
mod tests;

use std::io;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

#[repr(u8)]
#[allow(unused)]
pub(crate) enum Pc {
    Primitive = 0x00,
    Construct = 0x20,
}

#[repr(u8)]
#[allow(unused)]
enum Class {
    Universal = 0x00,
    Application = 0x40,
    ContextSpecific = 0x80,
    Private = 0xC0,
}

#[repr(u8)]
#[allow(unused)]
enum Tag {
    Mask = 0x1F,
    Boolean = 0x01,
    Integer = 0x02,
    BitString = 0x03,
    OctetString = 0x04,
    ObjectIdentifier = 0x06,
    Enumerated = 0x0A,
    Sequence = 0x10,
}

const TAG_MASK: u8 = 0x1F;

pub(crate) fn sizeof_sequence(length: u16) -> u16 {
    1 + sizeof_length(length) + length
}

pub(crate) fn sizeof_sequence_tag(length: u16) -> u16 {
    1 + sizeof_length(length)
}

pub(crate) fn sizeof_contextual_tag(length: u16) -> u16 {
    1 + sizeof_length(length)
}

pub(crate) fn sizeof_octet_string(length: u16) -> u16 {
    1 + sizeof_length(length) + length
}

pub(crate) fn sizeof_sequence_octet_string(length: u16) -> u16 {
    sizeof_contextual_tag(sizeof_octet_string(length)) + sizeof_octet_string(length)
}

pub(crate) fn sizeof_integer(value: u32) -> u16 {
    if value < 0x80 {
        3
    } else if value < 0x8000 {
        4
    } else if value < 0x0080_0000 {
        5
    } else {
        6
    }
}

pub(crate) fn write_sequence_tag(mut stream: impl io::Write, length: u16) -> io::Result<usize> {
    write_universal_tag(&mut stream, Tag::Sequence, Pc::Construct)?;
    write_length(stream, length).map(|length| length + 1)
}

pub(crate) fn read_sequence_tag(mut stream: impl io::Read) -> io::Result<u16> {
    let identifier = stream.read_u8()?;

    if identifier != Class::Universal as u8 | Pc::Construct as u8 | (TAG_MASK & Tag::Sequence as u8) {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid sequence tag identifier",
        ))
    } else {
        read_length(stream)
    }
}

pub(crate) fn write_contextual_tag(mut stream: impl io::Write, tagnum: u8, length: u16, pc: Pc) -> io::Result<usize> {
    let identifier = Class::ContextSpecific as u8 | pc as u8 | (TAG_MASK & tagnum);
    stream.write_u8(identifier)?;

    write_length(stream, length).map(|length| length + 1)
}

pub(crate) fn read_contextual_tag(mut stream: impl io::Read, tagnum: u8, pc: Pc) -> io::Result<u16> {
    let identifier = stream.read_u8()?;

    if identifier != Class::ContextSpecific as u8 | pc as u8 | (TAG_MASK & tagnum) {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid contextual tag identifier",
        ))
    } else {
        read_length(stream)
    }
}

pub(crate) fn read_contextual_tag_or_unwind(
    mut stream: impl io::Read + io::Seek,
    tagnum: u8,
    pc: Pc,
) -> io::Result<Option<u16>> {
    match read_contextual_tag(&mut stream, tagnum, pc) {
        Ok(contextual_tag_len) => Ok(Some(contextual_tag_len)),
        Err(_) => {
            stream.seek(io::SeekFrom::Current(-1))?;

            Ok(None)
        }
    }
}

pub(crate) fn write_integer(mut stream: impl io::Write, value: u32) -> io::Result<usize> {
    write_universal_tag(&mut stream, Tag::Integer, Pc::Primitive)?;

    if value < 0x80 {
        write_length(&mut stream, 1)?;
        stream.write_u8(value as u8)?;

        Ok(3)
    } else if value < 0x8000 {
        write_length(&mut stream, 2)?;
        stream.write_u16::<BigEndian>(value as u16)?;

        Ok(4)
    } else if value < 0x0080_0000 {
        write_length(&mut stream, 3)?;
        stream.write_u8((value >> 16) as u8)?;
        stream.write_u16::<BigEndian>((value & 0xFFFF) as u16)?;

        Ok(5)
    } else {
        write_length(&mut stream, 4)?;
        stream.write_u32::<BigEndian>(value)?;

        Ok(6)
    }
}

pub(crate) fn read_integer(mut stream: impl io::Read) -> io::Result<u64> {
    read_universal_tag(&mut stream, Tag::Integer, Pc::Primitive)?;
    let length = read_length(&mut stream)?;

    if length == 1 {
        stream.read_u8().map(u64::from)
    } else if length == 2 {
        stream.read_u16::<BigEndian>().map(u64::from)
    } else if length == 3 {
        let a = stream.read_u8()?;
        let b = stream.read_u16::<BigEndian>()?;

        Ok(u64::from(b) + (u64::from(a) << 16))
    } else if length == 4 {
        stream.read_u32::<BigEndian>().map(u64::from)
    } else if length == 8 {
        stream.read_u64::<BigEndian>()
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidData, "invalid integer len"))
    }
}

pub(crate) fn write_sequence_octet_string(mut stream: impl io::Write, tagnum: u8, value: &[u8]) -> io::Result<usize> {
    let tag_len = write_contextual_tag(
        &mut stream,
        tagnum,
        sizeof_octet_string(value.len() as u16),
        Pc::Construct,
    )?;
    let string_len = write_octet_string(&mut stream, value)?;

    Ok(tag_len + string_len)
}

pub(crate) fn write_octet_string(mut stream: impl io::Write, value: &[u8]) -> io::Result<usize> {
    let tag_size = write_octet_string_tag(&mut stream, value.len() as u16)?;
    stream.write_all(value)?;
    Ok(tag_size + value.len())
}

pub(crate) fn write_octet_string_tag(mut stream: impl io::Write, length: u16) -> io::Result<usize> {
    write_universal_tag(&mut stream, Tag::OctetString, Pc::Primitive)?;
    write_length(&mut stream, length).map(|length| length + 1)
}

pub(crate) fn read_octet_string_tag(mut stream: impl io::Read) -> io::Result<u16> {
    read_universal_tag(&mut stream, Tag::OctetString, Pc::Primitive)?;
    read_length(stream)
}

fn write_universal_tag(mut stream: impl io::Write, tag: Tag, pc: Pc) -> io::Result<usize> {
    let identifier = Class::Universal as u8 | pc as u8 | (TAG_MASK & tag as u8);
    stream.write_u8(identifier)?;

    Ok(1)
}

fn read_universal_tag(mut stream: impl io::Read, tag: Tag, pc: Pc) -> io::Result<()> {
    let identifier = stream.read_u8()?;

    if identifier != Class::Universal as u8 | pc as u8 | (TAG_MASK & tag as u8) {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid universal tag identifier",
        ))
    } else {
        Ok(())
    }
}

fn write_length(mut stream: impl io::Write, length: u16) -> io::Result<usize> {
    if length > 0xFF {
        stream.write_u8(0x80 ^ 0x2)?;
        stream.write_u16::<BigEndian>(length)?;

        Ok(3)
    } else if length > 0x7F {
        stream.write_u8(0x80 ^ 0x1)?;
        stream.write_u8(length as u8)?;

        Ok(2)
    } else {
        stream.write_u8(length as u8)?;

        Ok(1)
    }
}

fn read_length(mut stream: impl io::Read) -> io::Result<u16> {
    let byte = stream.read_u8()?;

    if byte & 0x80 != 0 {
        let len = byte & !0x80;

        if len == 1 {
            stream.read_u8().map(u16::from)
        } else if len == 2 {
            let length = stream.read_u16::<BigEndian>()?;

            // u16 should be capable to hold the ASN1 structure length
            // this condition checks that length is not too big for the u16 type
            if length > u16::MAX - 1 /* tag byte */ - sizeof_length(length) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "the length is too big"));
            }

            Ok(length)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid length of the length",
            ))
        }
    } else {
        Ok(u16::from(byte))
    }
}

fn sizeof_length(length: u16) -> u16 {
    if length > 0xff {
        3
    } else if length > 0x7f {
        2
    } else {
        1
    }
}

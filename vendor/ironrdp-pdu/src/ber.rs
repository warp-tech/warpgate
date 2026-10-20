use ironrdp_core::{ReadCursor, WriteCursor, cast_length, ensure_size, invalid_field_err};

use crate::{DecodeResult, EncodeResult};

#[repr(u8)]
#[derive(Copy, Clone)]
pub(crate) enum Pc {
    Primitive = 0x00,
    Construct = 0x20,
}

impl Pc {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    fn as_u8(self) -> u8 {
        self as u8
    }
}

#[repr(u8)]
#[expect(unused)]
#[derive(Copy, Clone)]
enum Class {
    Universal = 0x00,
    Application = 0x40,
    ContextSpecific = 0x80,
    Private = 0xC0,
}

impl Class {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    fn as_u8(self) -> u8 {
        self as u8
    }
}

#[repr(u8)]
#[expect(unused)]
#[derive(Copy, Clone)]
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

impl Tag {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    fn as_u8(self) -> u8 {
        self as u8
    }
}

pub(crate) const SIZEOF_ENUMERATED: usize = 3;
pub(crate) const SIZEOF_BOOL: usize = 3;

const TAG_MASK: u8 = 0x1F;

pub(crate) fn sizeof_application_tag(tagnum: u8, length: u16) -> usize {
    let tag_len = if tagnum > 0x1E { 2 } else { 1 };

    sizeof_length(length) + tag_len
}

pub(crate) fn sizeof_sequence_tag(length: u16) -> usize {
    1 + sizeof_length(length)
}

pub(crate) fn sizeof_octet_string(length: u16) -> usize {
    1 + sizeof_length(length) + usize::from(length)
}

pub(crate) fn sizeof_integer(value: u32) -> usize {
    if value < 0x0000_0080 {
        3
    } else if value < 0x0000_8000 {
        4
    } else if value < 0x0080_0000 {
        5
    } else {
        6
    }
}

pub(crate) fn write_sequence_tag(stream: &mut WriteCursor<'_>, length: u16) -> EncodeResult<usize> {
    write_universal_tag(stream, Tag::Sequence, Pc::Construct)?;

    write_length(stream, length).map(|length| length + 1)
}

pub(crate) fn read_sequence_tag(stream: &mut ReadCursor<'_>) -> DecodeResult<u16> {
    ensure_size!(in: stream, size: 1);
    let identifier = stream.read_u8();

    if identifier != Class::Universal.as_u8() | Pc::Construct.as_u8() | (TAG_MASK & Tag::Sequence.as_u8()) {
        Err(invalid_field_err!("identifier", "invalid sequence tag identifier"))
    } else {
        read_length(stream)
    }
}

pub(crate) fn write_application_tag(stream: &mut WriteCursor<'_>, tagnum: u8, length: u16) -> EncodeResult<usize> {
    ensure_size!(in: stream, size: sizeof_application_tag(tagnum, length));

    let taglen = if tagnum > 0x1E {
        stream.write_u8(Class::Application.as_u8() | Pc::Construct.as_u8() | TAG_MASK);
        stream.write_u8(tagnum);
        2
    } else {
        stream.write_u8(Class::Application.as_u8() | Pc::Construct.as_u8() | (TAG_MASK & tagnum));
        1
    };

    write_length(stream, length).map(|length| length + taglen)
}

pub(crate) fn read_application_tag(stream: &mut ReadCursor<'_>, tagnum: u8) -> DecodeResult<u16> {
    ensure_size!(in: stream, size: 1);
    let identifier = stream.read_u8();

    if tagnum > 0x1E {
        if identifier != Class::Application.as_u8() | Pc::Construct.as_u8() | TAG_MASK {
            return Err(invalid_field_err!("identifier", "invalid application tag identifier"));
        }
        ensure_size!(in: stream, size: 1);
        if stream.read_u8() != tagnum {
            return Err(invalid_field_err!("tagnum", "invalid application tag identifier"));
        }
    } else if identifier != Class::Application.as_u8() | Pc::Construct.as_u8() | (TAG_MASK & tagnum) {
        return Err(invalid_field_err!("identifier", "invalid application tag identifier"));
    }

    read_length(stream)
}

pub(crate) fn write_enumerated(stream: &mut WriteCursor<'_>, enumerated: u8) -> EncodeResult<usize> {
    let mut size = 0;
    size += write_universal_tag(stream, Tag::Enumerated, Pc::Primitive)?;
    size += write_length(stream, 1)?;
    ensure_size!(in: stream, size: 1);
    stream.write_u8(enumerated);
    size += 1;

    Ok(size)
}

pub(crate) fn read_enumerated(stream: &mut ReadCursor<'_>, count: u8) -> DecodeResult<u8> {
    read_universal_tag(stream, Tag::Enumerated, Pc::Primitive)?;

    let length = read_length(stream)?;
    if length != 1 {
        return Err(invalid_field_err!("len", "invalid enumerated len"));
    }

    ensure_size!(in: stream, size: 1);
    let enumerated = stream.read_u8();
    if enumerated == u8::MAX || enumerated + 1 > count {
        return Err(invalid_field_err!("enumerated", "invalid enumerated value"));
    }

    Ok(enumerated)
}

pub(crate) fn write_integer(stream: &mut WriteCursor<'_>, value: u32) -> EncodeResult<usize> {
    write_universal_tag(stream, Tag::Integer, Pc::Primitive)?;

    if value < 0x0000_0080 {
        write_length(stream, 1)?;
        ensure_size!(in: stream, size: 1);
        stream.write_u8(u8::try_from(value).expect("value is guaranteed to fit into u8 due to the prior check"));

        Ok(3)
    } else if value < 0x0000_8000 {
        write_length(stream, 2)?;
        ensure_size!(in: stream, size: 2);
        stream.write_u16_be(u16::try_from(value).expect("value is guaranteed to fit into u16 due to the prior check"));

        Ok(4)
    } else if value < 0x0080_0000 {
        write_length(stream, 3)?;
        ensure_size!(in: stream, size: 3);
        stream.write_u8(u8::try_from(value >> 16).expect("value is guaranteed to fit into u8 due to the prior check"));
        stream.write_u16_be(
            u16::try_from(value & 0xFFFF).expect("masking with 0xFFFF ensures that the value fits into u16"),
        );

        Ok(5)
    } else {
        write_length(stream, 4)?;
        ensure_size!(in: stream, size: 4);
        stream.write_u32_be(value);

        Ok(6)
    }
}

pub(crate) fn read_integer(stream: &mut ReadCursor<'_>) -> DecodeResult<u64> {
    read_universal_tag(stream, Tag::Integer, Pc::Primitive)?;
    let length = read_length(stream)?;

    if length == 1 {
        ensure_size!(in: stream, size: 1);
        Ok(u64::from(stream.read_u8()))
    } else if length == 2 {
        ensure_size!(in: stream, size: 2);
        Ok(u64::from(stream.read_u16_be()))
    } else if length == 3 {
        ensure_size!(in: stream, size: 3);
        let a = stream.read_u8();
        let b = stream.read_u16_be();

        Ok(u64::from(b) + (u64::from(a) << 16))
    } else if length == 4 {
        ensure_size!(in: stream, size: 4);
        Ok(u64::from(stream.read_u32_be()))
    } else if length == 8 {
        ensure_size!(in: stream, size: 8);
        Ok(stream.read_u64_be())
    } else {
        Err(invalid_field_err!("len", "invalid integer len"))
    }
}

pub(crate) fn write_bool(stream: &mut WriteCursor<'_>, value: bool) -> EncodeResult<usize> {
    let mut size = 0;
    size += write_universal_tag(stream, Tag::Boolean, Pc::Primitive)?;
    size += write_length(stream, 1)?;

    ensure_size!(in: stream, size: 1);
    stream.write_u8(if value { 0xFF } else { 0x00 });
    size += 1;

    Ok(size)
}

pub(crate) fn read_bool(stream: &mut ReadCursor<'_>) -> DecodeResult<bool> {
    read_universal_tag(stream, Tag::Boolean, Pc::Primitive)?;
    let length = read_length(stream)?;

    if length != 1 {
        return Err(invalid_field_err!("len", "invalid integer len"));
    }

    ensure_size!(in: stream, size: 1);
    Ok(stream.read_u8() != 0)
}

pub(crate) fn write_octet_string(stream: &mut WriteCursor<'_>, value: &[u8]) -> EncodeResult<usize> {
    let tag_size = write_octet_string_tag(stream, cast_length!("len", value.len())?)?;
    ensure_size!(in: stream, size: value.len());
    stream.write_slice(value);
    Ok(tag_size + value.len())
}

pub(crate) fn write_octet_string_tag(stream: &mut WriteCursor<'_>, length: u16) -> EncodeResult<usize> {
    write_universal_tag(stream, Tag::OctetString, Pc::Primitive)?;
    write_length(stream, length).map(|length| length + 1)
}

pub(crate) fn read_octet_string(stream: &mut ReadCursor<'_>) -> DecodeResult<Vec<u8>> {
    let length = cast_length!("len", read_octet_string_tag(stream)?)?;

    ensure_size!(in: stream, size: length);
    let buffer = stream.read_slice(length);

    Ok(buffer.into())
}

pub(crate) fn read_octet_string_tag(stream: &mut ReadCursor<'_>) -> DecodeResult<u16> {
    read_universal_tag(stream, Tag::OctetString, Pc::Primitive)?;
    read_length(stream)
}

fn write_universal_tag(stream: &mut WriteCursor<'_>, tag: Tag, pc: Pc) -> EncodeResult<usize> {
    ensure_size!(in: stream, size: 1);

    let identifier = Class::Universal.as_u8() | pc.as_u8() | (TAG_MASK & tag.as_u8());
    stream.write_u8(identifier);

    Ok(1)
}

fn read_universal_tag(stream: &mut ReadCursor<'_>, tag: Tag, pc: Pc) -> DecodeResult<()> {
    ensure_size!(in: stream, size: 1);

    let identifier = stream.read_u8();

    if identifier != Class::Universal.as_u8() | pc.as_u8() | (TAG_MASK & tag.as_u8()) {
        Err(invalid_field_err!("identifier", "invalid universal tag identifier"))
    } else {
        Ok(())
    }
}

fn write_length(stream: &mut WriteCursor<'_>, length: u16) -> EncodeResult<usize> {
    ensure_size!(in: stream, size: sizeof_length(length));

    if length > 0xFF {
        stream.write_u8(0x80 ^ 0x2);
        stream.write_u16_be(length);

        Ok(3)
    } else if length > 0x7F {
        stream.write_u8(0x80 ^ 0x1);
        stream.write_u8(u8::try_from(length).expect("length is guaranteed to fit into u8 due to the prior check"));

        Ok(2)
    } else {
        stream.write_u8(u8::try_from(length).expect("length is guaranteed to fit into u8 due to the prior check"));

        Ok(1)
    }
}

fn read_length(stream: &mut ReadCursor<'_>) -> DecodeResult<u16> {
    ensure_size!(in: stream, size: 1);
    let byte = stream.read_u8();

    if byte & 0x80 != 0 {
        let len = byte & !0x80;

        if len == 1 {
            ensure_size!(in: stream, size: 1);
            Ok(u16::from(stream.read_u8()))
        } else if len == 2 {
            ensure_size!(in: stream, size: 2);
            Ok(stream.read_u16_be())
        } else {
            Err(invalid_field_err!("len", "invalid length of the length"))
        }
    } else {
        Ok(u16::from(byte))
    }
}

fn sizeof_length(length: u16) -> usize {
    if length > 0xff {
        3
    } else if length > 0x7f {
        2
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use ironrdp_core::DecodeErrorKind;

    use super::*;

    #[test]
    fn write_sequence_tag_is_correct() {
        let mut buf = [0x0; 4];
        let mut cur = WriteCursor::new(&mut buf);
        assert_eq!(write_sequence_tag(&mut cur, 0x100).unwrap(), 4);
        assert_eq!(buf, [0x30, 0x82, 0x01, 0x00]);
    }

    #[test]
    fn read_sequence_tag_returns_correct_length() {
        let buf = [0x30, 0x82, 0x01, 0x00];
        let mut cur = ReadCursor::new(&buf);
        assert_eq!(read_sequence_tag(&mut cur).unwrap(), 0x100);
    }

    #[test]
    fn read_sequence_tag_returns_error_on_invalid_tag() {
        let buf = [0x3a, 0x82, 0x01, 0x00];
        let mut cur = ReadCursor::new(&buf);
        assert!(matches!(
            read_sequence_tag(&mut cur).unwrap_err().kind(),
            DecodeErrorKind::InvalidField { .. }
        ));
    }

    #[test]
    fn write_application_tag_is_correct_with_long_tag() {
        let mut buf = [0x0; 3];
        let mut cur = WriteCursor::new(&mut buf);
        assert_eq!(write_application_tag(&mut cur, 0x1F, 0x0F).unwrap(), 3);
        assert_eq!(buf, [0x7F, 0x1F, 0x0F]);
    }

    #[test]
    fn write_application_tag_is_correct_with_short_tag() {
        let mut buf = [0x0; 4];
        let mut cur = WriteCursor::new(&mut buf);
        assert_eq!(write_application_tag(&mut cur, 0x08, 0x100).unwrap(), 4);
        assert_eq!(buf, [0x68, 0x82, 0x01, 0x00]);
    }

    #[test]
    fn read_application_tag_is_correct_with_long_tag() {
        let buf = [0x7F, 0x1F, 0x0F];
        let mut cur = ReadCursor::new(&buf);
        assert_eq!(read_application_tag(&mut cur, 0x1F).unwrap(), 0x0F);
    }

    #[test]
    fn read_application_tag_is_correct_with_short_tag() {
        let buf = [0x68, 0x82, 0x01, 0x00];
        let mut cur = ReadCursor::new(&buf);
        assert_eq!(read_application_tag(&mut cur, 0x08).unwrap(), 0x100);
    }

    #[test]
    fn read_application_tag_returns_error_on_invalid_long_tag() {
        let buf = [0x68, 0x1B, 0x0F];
        let mut cur = ReadCursor::new(&buf);
        assert!(matches!(
            read_application_tag(&mut cur, 0x1F).unwrap_err().kind(),
            DecodeErrorKind::InvalidField { .. }
        ));
    }

    #[test]
    fn read_application_tag_returns_error_on_invalid_long_tag_value() {
        let buf = [0x7F, 0x1B, 0x0F];
        let mut cur = ReadCursor::new(&buf);
        assert!(matches!(
            read_application_tag(&mut cur, 0x1F).unwrap_err().kind(),
            DecodeErrorKind::InvalidField { .. }
        ));
    }

    #[test]
    fn read_application_tag_returns_error_on_invalid_short_tag() {
        let buf = [0x67, 0x0F];
        let mut cur = ReadCursor::new(&buf);
        assert!(matches!(
            read_application_tag(&mut cur, 0x08).unwrap_err().kind(),
            DecodeErrorKind::InvalidField { .. }
        ));
    }

    #[test]
    fn write_enumerated_is_correct() {
        let mut buf = [0x0; 3];
        let mut cur = WriteCursor::new(&mut buf);
        assert_eq!(write_enumerated(&mut cur, 0x0F).unwrap(), 3);
        assert_eq!(buf, [0x0A, 0x01, 0x0F]);
    }

    #[test]
    fn read_enumerated_is_correct() {
        let buf = [0x0A, 0x01, 0x0F];
        let mut cur = ReadCursor::new(&buf);
        assert_eq!(read_enumerated(&mut cur, 0x10).unwrap(), 0x0F);
    }

    #[test]
    fn read_enumerated_returns_error_on_wrong_tag() {
        let buf = [0x0B, 0x01, 0x0F];
        let mut cur = ReadCursor::new(&buf);
        assert!(matches!(
            read_enumerated(&mut cur, 0x10).unwrap_err().kind(),
            DecodeErrorKind::InvalidField { .. }
        ));
    }

    #[test]
    fn read_enumerated_returns_error_on_invalid_len() {
        let buf = [0x0A, 0x02, 0x0F];
        let mut cur = ReadCursor::new(&buf);
        assert!(matches!(
            read_enumerated(&mut cur, 0x10).unwrap_err().kind(),
            DecodeErrorKind::InvalidField { .. }
        ));
    }

    #[test]
    fn read_enumerated_returns_error_on_invalid_variant() {
        let buf = [0x0A, 0x01, 0x0F];
        let mut cur = ReadCursor::new(&buf);
        assert!(matches!(
            read_enumerated(&mut cur, 0x05).unwrap_err().kind(),
            DecodeErrorKind::InvalidField { .. }
        ));
    }

    #[test]
    fn write_bool_true_is_correct() {
        let mut buf = [0x0; 3];
        let mut cur = WriteCursor::new(&mut buf);
        assert_eq!(write_bool(&mut cur, true).unwrap(), 3);
        assert_eq!(buf, [0x01, 0x01, 0xFF]);
    }

    #[test]
    fn write_bool_false_is_correct() {
        let mut buf = [0x0; 3];
        let mut cur = WriteCursor::new(&mut buf);
        assert_eq!(write_bool(&mut cur, false).unwrap(), 3);
        assert_eq!(buf, [0x01, 0x01, 0x00]);
    }

    #[test]
    fn read_bool_true_is_correct() {
        let buf = vec![0x01, 0x01, 0xFF];
        let mut cur = ReadCursor::new(&buf);
        assert!(read_bool(&mut cur).unwrap());
    }

    #[test]
    fn read_bool_false_is_correct() {
        let buf = [0x01, 0x01, 0x00];
        let mut cur = ReadCursor::new(&buf);
        assert!(!read_bool(&mut cur).unwrap());
    }

    #[test]
    fn read_bool_returns_error_on_wrong_tag() {
        let buf = [0x0A, 0x01, 0xFF];
        let mut cur = ReadCursor::new(&buf);
        assert!(matches!(
            read_bool(&mut cur).unwrap_err().kind(),
            DecodeErrorKind::InvalidField { .. }
        ));
    }

    #[test]
    fn read_bool_returns_error_on_invalid_len() {
        let buf = [0x01, 0x02, 0x0F];
        let mut cur = ReadCursor::new(&buf);
        assert!(matches!(
            read_bool(&mut cur).unwrap_err().kind(),
            DecodeErrorKind::InvalidField { .. }
        ));
    }

    #[test]
    fn write_octet_string_tag_is_correct() {
        let mut buf = [0x0; 2];
        let mut cur = WriteCursor::new(&mut buf);
        assert_eq!(write_octet_string_tag(&mut cur, 0x0F).unwrap(), 2);
        assert_eq!(buf, [0x04, 0x0F]);
    }

    #[test]
    fn read_octet_string_tag_is_correct() {
        let buf = [0x04, 0x0F];
        let mut cur = ReadCursor::new(&buf);
        assert_eq!(read_octet_string_tag(&mut cur).unwrap(), 0x0F);
    }

    #[test]
    fn read_octet_string_tag_returns_error_on_wrong_tag() {
        let buf = [0x05, 0x0F];
        let mut cur = ReadCursor::new(&buf);
        assert!(matches!(
            read_octet_string_tag(&mut cur).unwrap_err().kind(),
            DecodeErrorKind::InvalidField { .. }
        ));
    }

    #[test]
    fn write_octet_string_is_correct() {
        let mut buf = [0x0; 7];
        let mut cur = WriteCursor::new(&mut buf);
        let string = [0x68, 0x65, 0x6c, 0x6c, 0x6f];
        let expected: Vec<_> = [0x04, 0x05].iter().chain(string.iter()).copied().collect();
        assert_eq!(write_octet_string(&mut cur, &string).unwrap(), 7);
        assert_eq!(buf, expected.as_slice());
    }

    #[test]
    fn read_octet_string_is_correct() {
        let buf = [0x04, 0x03, 0x00, 0x01, 0x02];
        let mut cur = ReadCursor::new(&buf);
        assert_eq!(read_octet_string(&mut cur).unwrap(), vec![0x00, 0x01, 0x02]);
    }

    #[test]
    fn write_length_is_correct_with_3_byte_length() {
        let mut buf = [0x0; 3];
        let mut cur = WriteCursor::new(&mut buf);
        assert_eq!(write_length(&mut cur, 0x100).unwrap(), 3);
        assert_eq!(buf, [0x82, 0x01, 0x00]);
    }

    #[test]
    fn write_length_is_correct_with_2_byte_length() {
        let mut buf = [0x0; 2];
        let mut cur = WriteCursor::new(&mut buf);
        assert_eq!(write_length(&mut cur, 0xFA).unwrap(), 2);
        assert_eq!(buf, [0x81, 0xFA]);
    }

    #[test]
    fn write_length_is_correct_with_1_byte_length() {
        let mut buf = [0x0];
        let mut cur = WriteCursor::new(&mut buf);
        assert_eq!(write_length(&mut cur, 0x70).unwrap(), 1);
        assert_eq!(buf, [0x70]);
    }

    #[test]
    fn read_length_is_correct_with_3_byte_length() {
        let buf = [0x82, 0x01, 0x00];
        let mut cur = ReadCursor::new(&buf);
        assert_eq!(read_length(&mut cur).unwrap(), 0x100);
    }

    #[test]
    fn read_length_is_correct_with_2_byte_length() {
        let buf = [0x81, 0xFA];
        let mut cur = ReadCursor::new(&buf);
        assert_eq!(read_length(&mut cur).unwrap(), 0xFA);
    }

    #[test]
    fn read_length_is_correct_with_1_byte_length() {
        let buf = [0x70];
        let mut cur = ReadCursor::new(&buf);
        assert_eq!(read_length(&mut cur).unwrap(), 0x70);
    }

    #[test]
    fn read_length_returns_error_on_invalid_length() {
        let buf = [0x8a, 0x1];
        let mut cur = ReadCursor::new(&buf);
        assert!(matches!(
            read_length(&mut cur).unwrap_err().kind(),
            DecodeErrorKind::InvalidField { .. }
        ));
    }

    #[test]
    fn write_integer_is_correct_with_4_byte_integer() {
        let mut buf = [0x0; 6];
        let mut cur = WriteCursor::new(&mut buf);
        assert_eq!(write_integer(&mut cur, 0x0080_0000).unwrap(), 6);
        assert_eq!(buf, [0x02, 0x04, 0x00, 0x80, 0x00, 0x00]);
    }

    #[test]
    fn write_integer_is_correct_with_3_byte_integer() {
        let mut buf = [0x0; 5];
        let mut cur = WriteCursor::new(&mut buf);
        assert_eq!(write_integer(&mut cur, 0x80000).unwrap(), 5);
        assert_eq!(buf, [0x02, 0x03, 0x08, 0x00, 0x00]);
    }

    #[test]
    fn write_integer_is_correct_with_2_byte_integer() {
        let mut buf = [0x0; 4];
        let mut cur = WriteCursor::new(&mut buf);
        assert_eq!(write_integer(&mut cur, 0x800).unwrap(), 4);
        assert_eq!(buf, [0x02, 0x02, 0x08, 0x00]);
    }

    #[test]
    fn write_integer_is_correct_with_1_byte_integer() {
        let mut buf = [0x0; 3];
        let mut cur = WriteCursor::new(&mut buf);
        assert_eq!(write_integer(&mut cur, 0x79).unwrap(), 3);
        assert_eq!(buf, [0x02, 0x01, 0x79]);
    }

    #[test]
    fn read_integer_is_correct_with_8_byte_integer() {
        let buf = [0x02, 0x08, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut cur = ReadCursor::new(&buf);
        assert_eq!(read_integer(&mut cur).unwrap(), 0x0080_0000_0000_0000);
    }

    #[test]
    fn read_integer_is_correct_with_4_byte_integer() {
        let buf = [0x02, 0x04, 0x00, 0x80, 0x00, 0x00];
        let mut cur = ReadCursor::new(&buf);
        assert_eq!(read_integer(&mut cur).unwrap(), 0x0080_0000);
    }

    #[test]
    fn read_integer_is_correct_with_3_byte_integer() {
        let buf = [0x02, 0x03, 0x08, 0x00, 0x00];
        let mut cur = ReadCursor::new(&buf);
        assert_eq!(read_integer(&mut cur).unwrap(), 0x80000);
    }

    #[test]
    fn read_integer_is_correct_with_2_byte_integer() {
        let buf = [0x02, 0x02, 0x08, 0x00];
        let mut cur = ReadCursor::new(&buf);
        assert_eq!(read_integer(&mut cur).unwrap(), 0x800);
    }

    #[test]
    fn read_integer_is_correct_with_1_byte_integer() {
        let buf = [0x02, 0x01, 0x79];
        let mut cur = ReadCursor::new(&buf);
        assert_eq!(read_integer(&mut cur).unwrap(), 0x79);
    }

    #[test]
    fn read_integer_returns_error_on_incorrect_len() {
        let buf = [0x02, 0x06, 0x79];
        let mut cur = ReadCursor::new(&buf);
        assert!(matches!(
            read_integer(&mut cur).unwrap_err().kind(),
            DecodeErrorKind::InvalidField { .. }
        ));
    }

    #[test]
    fn write_universal_tag_primitive_integer_is_correct() {
        let mut buf = [0x0];
        let mut cur = WriteCursor::new(&mut buf);
        assert_eq!(write_universal_tag(&mut cur, Tag::Integer, Pc::Primitive).unwrap(), 1);
        assert_eq!(buf, [0x02]);
    }

    #[test]
    fn write_universal_tag_construct_enumerated_is_correct() {
        let mut buf = [0x0];
        let mut cur = WriteCursor::new(&mut buf);
        assert_eq!(
            write_universal_tag(&mut cur, Tag::Enumerated, Pc::Construct).unwrap(),
            1
        );
        assert_eq!(buf, [0x2A]);
    }

    #[test]
    fn sizeof_length_with_long_len() {
        let len = 625;
        let expected = 3;
        assert_eq!(sizeof_length(len), expected);
    }
}

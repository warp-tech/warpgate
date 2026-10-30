use core::fmt::Debug;
use core::ops::Add;

use byteorder::{LittleEndian, ReadBytesExt as _};
use ironrdp_core::{ReadCursor, WriteCursor, ensure_size, invalid_field_err, other_err};
use num_derive::FromPrimitive;

use crate::{DecodeResult, EncodeResult};

pub fn split_u64(value: u64) -> (u32, u32) {
    #[expect(clippy::missing_panics_doc, reason = "unreachable panic (checked integer downcast)")]
    let low =
        u32::try_from(value & 0xFFFF_FFFF).expect("masking with 0xFFFF_FFFF ensures that the value fits into u32");

    #[expect(clippy::missing_panics_doc, reason = "unreachable panic (checked integer downcast)")]
    let high = u32::try_from(value >> 32).expect("(u64 >> 32) fits into u32");

    (low, high)
}

pub fn combine_u64(lo: u32, hi: u32) -> u64 {
    let mut position_bytes = [0u8; size_of::<u64>()];
    position_bytes[..size_of::<u32>()].copy_from_slice(&lo.to_le_bytes());
    position_bytes[size_of::<u32>()..].copy_from_slice(&hi.to_le_bytes());
    u64::from_le_bytes(position_bytes)
}

pub fn to_utf16_bytes(value: &str) -> Vec<u8> {
    value
        .encode_utf16()
        .flat_map(|i| i.to_le_bytes().to_vec())
        .collect::<Vec<u8>>()
}

pub fn from_utf16_bytes(mut value: &[u8]) -> String {
    let mut value_u16 = vec![0x00; value.len() / 2];

    #[expect(clippy::missing_panics_doc, reason = "unreachable panic (prior constrain)")]
    value
        .read_u16_into::<LittleEndian>(value_u16.as_mut())
        .expect("read_u16_into cannot fail at this point");

    String::from_utf16_lossy(value_u16.as_ref())
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive)]
pub enum CharacterSet {
    Ansi = 1,
    Unicode = 2,
}

impl CharacterSet {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

// Read a string from the cursor, using the specified character set.
//
// If read_null_terminator is true, the string will be read until a null terminator is found.
// Otherwise, the string will be read until the end of the cursor. If the next character is a null
// terminator, an empty string will be returned (without consuming the null terminator).
pub fn read_string_from_cursor(
    cursor: &mut ReadCursor<'_>,
    character_set: CharacterSet,
    read_null_terminator: bool,
) -> DecodeResult<String> {
    let size = if character_set == CharacterSet::Unicode {
        let code_units = if read_null_terminator {
            // Find null or read all if null is not found
            cursor
                .remaining()
                .chunks_exact(2)
                .position(|chunk| chunk == [0, 0])
                .map(|null_terminator_pos| null_terminator_pos + 1) // Read null code point
                .unwrap_or(cursor.len() / 2)
        } else {
            // UTF16 uses 2 bytes per code unit, so we need to read an even number of bytes
            cursor.len() / 2
        };

        code_units * 2
    } else if read_null_terminator {
        // Find null or read all if null is not found
        cursor
            .remaining()
            .iter()
            .position(|&i| i == 0)
            .map(|null_terminator_pos| null_terminator_pos + 1) // Read null code point
            .unwrap_or(cursor.len())
    } else {
        // Read all
        cursor.len()
    };

    // Empty string, nothing to do
    if size == 0 {
        return Ok(String::new());
    }

    let result = match character_set {
        CharacterSet::Unicode => {
            ensure_size!(ctx: "Decode string (UTF-16)", in: cursor, size: size);
            let mut slice = cursor.read_slice(size);

            let str_buffer = &mut slice;
            let mut u16_buffer = vec![0u16; str_buffer.len() / 2];

            #[expect(clippy::missing_panics_doc, reason = "unreachable panic (prior constrain)")]
            str_buffer
                .read_u16_into::<LittleEndian>(u16_buffer.as_mut())
                .expect("BUG: str_buffer is always even for UTF16");

            String::from_utf16(&u16_buffer)
                .map_err(|_| invalid_field_err!("UTF16 decode", "buffer", "Failed to decode UTF16 string"))?
        }
        CharacterSet::Ansi => {
            ensure_size!(ctx: "Decode string (UTF-8)", in: cursor, size: size);
            let slice = cursor.read_slice(size);
            String::from_utf8(slice.to_vec())
                .map_err(|_| invalid_field_err!("UTF8 decode", "buffer", "Failed to decode UTF8 string"))?
        }
    };

    Ok(result.trim_end_matches('\0').into())
}

pub fn decode_string(src: &[u8], character_set: CharacterSet, read_null_terminator: bool) -> DecodeResult<String> {
    read_string_from_cursor(&mut ReadCursor::new(src), character_set, read_null_terminator)
}

pub fn read_multistring_from_cursor(
    cursor: &mut ReadCursor<'_>,
    character_set: CharacterSet,
) -> DecodeResult<Vec<String>> {
    let mut strings = Vec::new();

    loop {
        let string = read_string_from_cursor(cursor, character_set, true)?;
        if string.is_empty() {
            // empty string indicates the end of the multi-string array
            // (we hit two null terminators in a row)
            break;
        }

        strings.push(string);
    }

    Ok(strings)
}

pub fn encode_string(
    dst: &mut [u8],
    value: &str,
    character_set: CharacterSet,
    write_null_terminator: bool,
) -> EncodeResult<usize> {
    let (buffer, ctx) = match character_set {
        CharacterSet::Unicode => {
            let mut buffer = to_utf16_bytes(value);
            if write_null_terminator {
                buffer.extend_from_slice(&[0, 0]);
            }
            (buffer, "Encode string (UTF-16)")
        }
        CharacterSet::Ansi => {
            let mut buffer = value.as_bytes().to_vec();
            if write_null_terminator {
                buffer.push(0);
            }
            (buffer, "Encode string (UTF-8)")
        }
    };

    let len = buffer.len();

    ensure_size!(ctx: ctx, in: dst, size: len);
    dst[..len].copy_from_slice(&buffer);

    Ok(len)
}

pub fn write_string_to_cursor(
    cursor: &mut WriteCursor<'_>,
    value: &str,
    character_set: CharacterSet,
    write_null_terminator: bool,
) -> EncodeResult<()> {
    let len = encode_string(cursor.remaining_mut(), value, character_set, write_null_terminator)?;
    cursor.advance(len);
    Ok(())
}

pub fn write_multistring_to_cursor(
    cursor: &mut WriteCursor<'_>,
    strings: &[String],
    character_set: CharacterSet,
) -> EncodeResult<()> {
    // Write each string to cursor, separated by a null terminator
    for string in strings {
        write_string_to_cursor(cursor, string, character_set, true)?;
    }

    // Write final null terminator signifying the end of the multi-string
    match character_set {
        CharacterSet::Unicode => {
            ensure_size!(ctx: "Encode multistring (UTF-16)", in: cursor, size: 2);
            cursor.write_u16(0)
        }
        CharacterSet::Ansi => {
            ensure_size!(ctx: "Encode multistring (UTF-8)", in: cursor, size: 1);
            cursor.write_u8(0)
        }
    }

    Ok(())
}

/// Returns the length in bytes of the encoded value
/// based on the passed CharacterSet and with_null_terminator flag.
pub fn encoded_str_len(value: &str, character_set: CharacterSet, with_null_terminator: bool) -> usize {
    match character_set {
        CharacterSet::Ansi => value.len() + if with_null_terminator { 1 } else { 0 },
        CharacterSet::Unicode => value.encode_utf16().count() * 2 + if with_null_terminator { 2 } else { 0 },
    }
}

/// Returns the length in bytes of the encoded multi-string
/// based on the passed CharacterSet.
pub fn encoded_multistring_len(strings: &[String], character_set: CharacterSet) -> usize {
    strings
        .iter()
        .map(|s| encoded_str_len(s, character_set, true))
        .sum::<usize>()
        + if character_set == CharacterSet::Unicode { 2 } else { 1 }
}

// FIXME: legacy trait
pub trait SplitTo {
    #[must_use]
    fn split_to(&mut self, n: usize) -> Self;
}

impl<T> SplitTo for &[T] {
    fn split_to(&mut self, n: usize) -> Self {
        assert!(n <= self.len());

        let (a, b) = self.split_at(n);
        *self = b;

        a
    }
}

impl<T> SplitTo for &mut [T] {
    fn split_to(&mut self, n: usize) -> Self {
        assert!(n <= self.len());

        let (a, b) = core::mem::take(self).split_at_mut(n);
        *self = b;

        a
    }
}

pub trait CheckedAdd: Sized + Add<Output = Self> {
    fn checked_add(self, rhs: Self) -> Option<Self>;
}

// Implement the trait for usize and u32
impl CheckedAdd for usize {
    fn checked_add(self, rhs: Self) -> Option<Self> {
        usize::checked_add(self, rhs)
    }
}

impl CheckedAdd for u32 {
    fn checked_add(self, rhs: Self) -> Option<Self> {
        u32::checked_add(self, rhs)
    }
}

// Utility function for checked addition that returns a PduResult
pub fn checked_sum<T>(values: &[T]) -> DecodeResult<T>
where
    T: CheckedAdd + Copy + Debug,
{
    values.split_first().map_or_else(
        || Err(other_err!("empty array provided to checked_sum")),
        |(&first, rest)| {
            rest.iter().try_fold(first, |acc, &val| {
                acc.checked_add(val)
                    .ok_or_else(|| other_err!("overflow detected during addition"))
            })
        },
    )
}

/// Utility function that panics on overflow
///
/// # Panics
///
/// Panics if sum of values overflows.
// FIXME: Is it really something we want to expose from ironrdp-pdu?
pub fn strict_sum<T>(values: &[T]) -> T
where
    T: CheckedAdd + Copy + Debug,
{
    checked_sum::<T>(values).expect("overflow detected during addition")
}

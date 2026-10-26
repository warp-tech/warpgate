#[cfg(test)]
mod tests;

use bitflags::bitflags;
use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, ensure_fixed_part_size, read_padding,
    write_padding,
};

use crate::gcc::{IME_FILE_NAME_SIZE, KeyboardType};
use crate::utils;

const INPUT_LENGTH: usize = 84;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct InputFlags: u16 {
        const SCANCODES = 0x0001;
        const MOUSEX = 0x0004;
        const FASTPATH_INPUT = 0x0008;
        const UNICODE = 0x0010;
        const FASTPATH_INPUT_2 = 0x0020;
        const UNUSED_1 = 0x0040;
        const MOUSE_RELATIVE = 0x0080;
        const TS_MOUSE_HWHEEL = 0x0100;
        const TS_QOE_TIMESTAMPS = 0x0200;

        const _ = !0;
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Input {
    pub input_flags: InputFlags,
    pub keyboard_layout: u32,
    pub keyboard_type: Option<KeyboardType>,
    pub keyboard_subtype: u32,
    pub keyboard_function_key: u32,
    pub keyboard_ime_filename: String,
}

impl Input {
    const NAME: &'static str = "Input";

    const FIXED_PART_SIZE: usize = INPUT_LENGTH;
}

impl Encode for Input {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u16(self.input_flags.bits());
        write_padding!(dst, 2);
        dst.write_u32(self.keyboard_layout);

        let type_buffer = match self.keyboard_type {
            Some(value) => value.0,
            None => 0,
        };
        dst.write_u32(type_buffer);

        dst.write_u32(self.keyboard_subtype);
        dst.write_u32(self.keyboard_function_key);

        utils::encode_string(
            dst.remaining_mut(),
            &self.keyboard_ime_filename,
            utils::CharacterSet::Unicode,
            true,
        )?;
        dst.advance(IME_FILE_NAME_SIZE);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for Input {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let input_flags = InputFlags::from_bits_retain(src.read_u16());
        read_padding!(src, 2);
        let keyboard_layout = src.read_u32();

        // keyboardType is only meaningful when non-zero: the server-to-client direction of this
        // same capability set SHOULD send zero (MS-RDPBCGR 2.2.7.1.6), so zero maps to `None`
        // rather than being treated as an (invalid) discriminant.
        let keyboard_type = match src.read_u32() {
            0 => None,
            value => Some(KeyboardType(value)),
        };

        let keyboard_subtype = src.read_u32();
        let keyboard_function_key = src.read_u32();

        let keyboard_ime_filename =
            utils::decode_string(src.read_slice(IME_FILE_NAME_SIZE), utils::CharacterSet::Unicode, false)?;

        Ok(Input {
            input_flags,
            keyboard_layout,
            keyboard_type,
            keyboard_subtype,
            keyboard_function_key,
            keyboard_ime_filename,
        })
    }
}

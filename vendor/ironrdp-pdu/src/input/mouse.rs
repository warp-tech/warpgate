use bitflags::bitflags;
use ironrdp_core::{Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, ensure_fixed_part_size};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct MousePdu {
    pub flags: PointerFlags,
    pub number_of_wheel_rotation_units: i16,
    pub x_position: u16,
    pub y_position: u16,
}

impl MousePdu {
    const NAME: &'static str = "MousePdu";

    const FIXED_PART_SIZE: usize = 2 /* flags */ + 2 /* x */ + 2 /* y */;
}

impl Encode for MousePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        let wheel_negative_bit = if self.number_of_wheel_rotation_units < 0 {
            PointerFlags::WHEEL_NEGATIVE.bits()
        } else {
            PointerFlags::empty().bits()
        };

        // The wire field is 9-bit two's complement: representable range is
        // [-256, 255], narrower than i16.
        debug_assert!(
            (-256..=255).contains(&self.number_of_wheel_rotation_units),
            "number_of_wheel_rotation_units out of the 9-bit two's-complement range [-256, 255]: {}",
            self.number_of_wheel_rotation_units
        );

        #[expect(
            clippy::as_conversions,
            clippy::cast_sign_loss,
            clippy::cast_possible_truncation,
            reason = "truncation intended"
        )]
        let truncated_wheel_rotation_units = self.number_of_wheel_rotation_units as u8;
        let wheel_rotations_bits = u16::from(truncated_wheel_rotation_units);

        let flags = self.flags.bits() | wheel_negative_bit | wheel_rotations_bits;

        dst.write_u16(flags);
        dst.write_u16(self.x_position);
        dst.write_u16(self.y_position);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for MousePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let flags_raw = src.read_u16();

        let flags = PointerFlags::from_bits_retain(flags_raw);

        #[expect(
            clippy::as_conversions,
            clippy::cast_possible_truncation,
            reason = "truncation intended"
        )]
        let wheel_rotations_bits = flags_raw as u8;

        // Per MS-RDPBCGR 2.2.8.1.1.3.1.1.3, WheelRotationMask (0x01FF) is a 9-bit
        // TWO'S-COMPLEMENT field: WHEEL_NEGATIVE (0x0100) is the sign bit of that
        // 9-bit value, not an independent "negate this magnitude" flag. So a byte
        // of 0xFF with WHEEL_NEGATIVE set means -1, not -255. This must mirror
        // `encode` above, which already produces a proper two's-complement byte
        // via a truncating cast (`self.number_of_wheel_rotation_units as u8`) —
        // without this, `decode(encode(x))` does not round-trip for x < 0.
        let number_of_wheel_rotation_units = if flags.contains(PointerFlags::WHEEL_NEGATIVE) {
            i16::from(wheel_rotations_bits) - 0x100
        } else {
            i16::from(wheel_rotations_bits)
        };

        let x_position = src.read_u16();
        let y_position = src.read_u16();

        Ok(Self {
            flags,
            number_of_wheel_rotation_units,
            x_position,
            y_position,
        })
    }
}
bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct PointerFlags: u16 {
        const WHEEL_NEGATIVE = 0x0100;
        const VERTICAL_WHEEL = 0x0200;
        const HORIZONTAL_WHEEL = 0x0400;
        const MOVE = 0x0800;
        const LEFT_BUTTON = 0x1000;
        const RIGHT_BUTTON = 0x2000;
        const MIDDLE_BUTTON_OR_WHEEL = 0x4000;
        const DOWN = 0x8000;

        const _ = !0;
    }
}

#[cfg(test)]
mod tests {
    use ironrdp_core::{decode, encode_vec};

    use super::*;

    fn mouse_pdu(number_of_wheel_rotation_units: i16) -> MousePdu {
        MousePdu {
            flags: PointerFlags::VERTICAL_WHEEL,
            number_of_wheel_rotation_units,
            x_position: 0,
            y_position: 0,
        }
    }

    #[test]
    fn wheel_rotation_units_round_trip_through_encode_decode() {
        // Every representable value must survive an encode/decode round trip.
        // This previously failed for small negative values: encode(-1) produced
        // byte 0xFF + WHEEL_NEGATIVE, which decode incorrectly read back as -255
        // (sign-magnitude) instead of -1 (two's complement, matching encode).
        //
        // The wire field is 9-bit two's complement, so its representable domain
        // is [-256, 255] (wider than i8, narrower than i16) — iterate that exact
        // range rather than i8::MIN..=i8::MAX so this test documents (and checks)
        // the real contract, not an arbitrary subset of it.
        for value in -256i16..=255i16 {
            let pdu = mouse_pdu(value);
            let buffer = encode_vec(&pdu).unwrap();
            let decoded: MousePdu = decode(buffer.as_slice()).unwrap();
            assert_eq!(
                decoded.number_of_wheel_rotation_units, value,
                "round trip failed for {value}"
            );
        }
    }

    #[test]
    fn small_negative_wheel_rotation_decodes_correctly() {
        // WHEEL_NEGATIVE set, byte = 0xFF -> true value is -1 (two's complement:
        // byte - 0x100), NOT -255 (sign-magnitude: -byte).
        let flags = (PointerFlags::VERTICAL_WHEEL | PointerFlags::WHEEL_NEGATIVE).bits() | 0x00FF;
        let mut buffer = [0u8; 6];
        buffer[0..2].copy_from_slice(&flags.to_le_bytes());
        let pdu: MousePdu = decode(buffer.as_slice()).unwrap();
        assert_eq!(pdu.number_of_wheel_rotation_units, -1);
    }
}

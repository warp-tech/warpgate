use ironrdp_core::{Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, ensure_fixed_part_size};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct FrameAcknowledge {
    pub max_unacknowledged_frame_count: u32,
}

impl FrameAcknowledge {
    const NAME: &'static str = "FrameAcknowledge";

    const FIXED_PART_SIZE: usize = 4 /* maxUnackFrameCount */;
}

impl Encode for FrameAcknowledge {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u32(self.max_unacknowledged_frame_count);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for FrameAcknowledge {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let max_unacknowledged_frame_count = src.read_u32();

        Ok(Self {
            max_unacknowledged_frame_count,
        })
    }
}

#[cfg(test)]
mod test {
    use ironrdp_core::{decode, encode_vec};

    use super::*;

    const FRAME_ACKNOWLEDGE_PDU_BUFFER: [u8; 4] = [0xf4, 0xf3, 0xf2, 0xf1];
    const FRAME_ACKNOWLEDGE_PDU: FrameAcknowledge = FrameAcknowledge {
        max_unacknowledged_frame_count: 0xf1f2_f3f4,
    };

    #[test]
    fn from_buffer_correctly_parses_frame_acknowledge() {
        assert_eq!(
            FRAME_ACKNOWLEDGE_PDU,
            decode(FRAME_ACKNOWLEDGE_PDU_BUFFER.as_ref()).unwrap()
        );
    }

    #[test]
    fn to_buffer_correctly_serializes_frame_acknowledge() {
        let expected = FRAME_ACKNOWLEDGE_PDU_BUFFER.as_ref();

        let buffer = encode_vec(&FRAME_ACKNOWLEDGE_PDU).unwrap();
        assert_eq!(expected, buffer.as_slice());
    }

    #[test]
    fn buffer_length_is_correct_for_frame_acknowledge() {
        assert_eq!(FRAME_ACKNOWLEDGE_PDU_BUFFER.len(), FRAME_ACKNOWLEDGE_PDU.size());
    }
}

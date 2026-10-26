use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, ensure_fixed_part_size, ensure_size,
    invalid_field_err,
};

const NON_RLE_PADDING_SIZE: usize = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum ColorPlaneDefinition {
    Argb,
    AYCoCg {
        color_loss_level: u8,
        use_chroma_subsampling: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct BitmapStreamHeader {
    pub enable_rle_compression: bool,
    pub use_alpha: bool,
    pub color_plane_definition: ColorPlaneDefinition,
}

impl BitmapStreamHeader {
    pub const NAME: &'static str = "Rdp6BitmapStreamHeader";
    const FIXED_PART_SIZE: usize = 1;
}

impl Decode<'_> for BitmapStreamHeader {
    fn decode(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);
        let header = src.read_u8();

        let color_loss_level = header & 0x07;
        let use_chroma_subsampling = (header & 0x08) != 0;
        let enable_rle_compression = (header & 0x10) != 0;
        let use_alpha = (header & 0x20) == 0;

        let color_plane_definition = match color_loss_level {
            0 => ColorPlaneDefinition::Argb,
            color_loss_level => ColorPlaneDefinition::AYCoCg {
                color_loss_level,
                use_chroma_subsampling,
            },
        };

        Ok(Self {
            enable_rle_compression,
            use_alpha,
            color_plane_definition,
        })
    }
}

impl Encode for BitmapStreamHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        let mut header = (u8::from(self.enable_rle_compression) << 4) | (u8::from(!self.use_alpha) << 5);

        match self.color_plane_definition {
            ColorPlaneDefinition::Argb => {
                // ARGB color planes keep cll and cs flags set to 0
            }
            ColorPlaneDefinition::AYCoCg {
                color_loss_level,
                use_chroma_subsampling,
                ..
            } => {
                // Add cll and cs flags to header
                header |= (color_loss_level & 0x07) | (u8::from(use_chroma_subsampling) << 3);
            }
        }

        dst.write_u8(header);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
            + if self.enable_rle_compression {
                0
            } else {
                NON_RLE_PADDING_SIZE
            }
    }
}

/// Represents `RDP6_BITMAP_STREAM` structure described in [MS-RDPEGDI] 2.2.2.5.1
#[derive(Debug, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct BitmapStream<'a> {
    pub header: BitmapStreamHeader,
    pub color_planes: &'a [u8],
}

impl<'a> BitmapStream<'a> {
    pub const NAME: &'static str = "Rdp6BitmapStream";
    const FIXED_PART_SIZE: usize = 1;

    pub fn color_panes_data(&self) -> &'a [u8] {
        self.color_planes
    }

    pub fn has_subsampled_chroma(&self) -> bool {
        match self.header.color_plane_definition {
            ColorPlaneDefinition::Argb => false,
            ColorPlaneDefinition::AYCoCg {
                use_chroma_subsampling, ..
            } => use_chroma_subsampling,
        }
    }
}

impl<'a> Decode<'a> for BitmapStream<'a> {
    fn decode(src: &mut ReadCursor<'a>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);
        let header = ironrdp_core::decode_cursor::<BitmapStreamHeader>(src)?;

        let color_planes_size = if !header.enable_rle_compression {
            // Cut padding field if RLE flags is set to 0
            if src.is_empty() {
                return Err(invalid_field_err!(
                    "padding",
                    "missing padding byte from zero-sized non-RLE bitmap data",
                ));
            }
            src.len() - NON_RLE_PADDING_SIZE
        } else {
            src.len()
        };

        let color_planes = src.read_slice(color_planes_size);

        Ok(Self { header, color_planes })
    }
}

impl Encode for BitmapStream<'_> {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        ironrdp_core::encode_cursor(&self.header, dst)?;
        dst.write_slice(self.color_panes_data());

        // Write padding
        if !self.header.enable_rle_compression {
            dst.write_u8(0);
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        self.header.size() + self.color_panes_data().len()
    }
}

#[cfg(test)]
#[cfg(feature = "alloc")]
#[expect(
    clippy::needless_raw_strings,
    reason = "the lint is disable to not interfere with expect! macro"
)]
mod tests {
    use expect_test::{Expect, expect};

    use super::*;

    fn assert_roundtrip(buffer: &[u8], expected: Expect) {
        let pdu = ironrdp_core::decode::<BitmapStream<'_>>(buffer).unwrap();
        expected.assert_debug_eq(&pdu);
        assert_eq!(pdu.size(), buffer.len());
        let reencoded = ironrdp_core::encode_vec(&pdu).unwrap();
        assert_eq!(reencoded.as_slice(), buffer);
    }

    fn assert_parsing_failure(buffer: &[u8], expected: Expect) {
        let error = ironrdp_core::decode::<BitmapStream<'_>>(buffer).err().unwrap();
        expected.assert_debug_eq(&error);
    }

    #[test]
    fn parsing_valid_data_succeeds() {
        // AYCoCg color planes, with RLE
        assert_roundtrip(
            &[0x3F, 0x01, 0x02, 0x03, 0x04],
            expect![[r#"
                BitmapStream {
                    header: BitmapStreamHeader {
                        enable_rle_compression: true,
                        use_alpha: false,
                        color_plane_definition: AYCoCg {
                            color_loss_level: 7,
                            use_chroma_subsampling: true,
                        },
                    },
                    color_planes: [
                        1,
                        2,
                        3,
                        4,
                    ],
                }
            "#]],
        );

        // RGB color planes, with RLE, with alpha
        assert_roundtrip(
            &[0x10, 0x01, 0x02, 0x03, 0x04],
            expect![[r#"
                BitmapStream {
                    header: BitmapStreamHeader {
                        enable_rle_compression: true,
                        use_alpha: true,
                        color_plane_definition: Argb,
                    },
                    color_planes: [
                        1,
                        2,
                        3,
                        4,
                    ],
                }
            "#]],
        );

        // Without RLE, validate that padding is handled correctly
        assert_roundtrip(
            &[0x20, 0x01, 0x02, 0x03, 0x00],
            expect![[r#"
                BitmapStream {
                    header: BitmapStreamHeader {
                        enable_rle_compression: false,
                        use_alpha: false,
                        color_plane_definition: Argb,
                    },
                    color_planes: [
                        1,
                        2,
                        3,
                    ],
                }
            "#]],
        );

        // Empty color planes, with RLE
        assert_roundtrip(
            &[0x10],
            expect![[r#"
                BitmapStream {
                    header: BitmapStreamHeader {
                        enable_rle_compression: true,
                        use_alpha: true,
                        color_plane_definition: Argb,
                    },
                    color_planes: [],
                }
            "#]],
        );

        // Empty color planes, without RLE
        assert_roundtrip(
            &[0x00, 0x00],
            expect![[r#"
                BitmapStream {
                    header: BitmapStreamHeader {
                        enable_rle_compression: false,
                        use_alpha: true,
                        color_plane_definition: Argb,
                    },
                    color_planes: [],
                }
            "#]],
        );
    }

    #[test]
    fn failures_handled_gracefully() {
        // Empty buffer
        assert_parsing_failure(
            &[],
            expect![[r#"
                Error {
                    context: "<ironrdp_pdu::basic_output::bitmap::rdp6::BitmapStream as ironrdp_core::decode::Decode>::decode",
                    kind: NotEnoughBytes {
                        received: 0,
                        expected: 1,
                    },
                    source: None,
                }
            "#]],
        );

        // Without RLE, Check that missing padding byte is handled correctly
        assert_parsing_failure(
            &[0x20],
            expect![[r#"
                Error {
                    context: "<ironrdp_pdu::basic_output::bitmap::rdp6::BitmapStream as ironrdp_core::decode::Decode>::decode",
                    kind: InvalidField {
                        field: "padding",
                        reason: "missing padding byte from zero-sized non-RLE bitmap data",
                    },
                    source: None,
                }
            "#]],
        );
    }
}

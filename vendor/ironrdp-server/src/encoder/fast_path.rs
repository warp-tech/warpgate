use core::{cmp, fmt};

use ironrdp_pdu::fast_path::{EncryptionFlags, FastPathHeader, FastPathUpdatePdu, Fragmentation, UpdateCode};
use ironrdp_pdu::{Encode as _, WriteCursor};

// this is the maximum amount of data (not including headers) we can send in a single TS_FP_UPDATE_PDU
const MAX_FASTPATH_UPDATE_SIZE: usize = 16_374;

const FASTPATH_HEADER_SIZE: usize = 6;

#[expect(
    clippy::allow_attributes,
    reason = "Unfortunately, expect attribute doesn't work when above or after visibility::make attribute"
)]
#[allow(unreachable_pub)]
#[expect(
    clippy::partial_pub_fields,
    reason = "public field is not a part of the public API and is used by benchmarks"
)]
#[cfg_attr(feature = "__bench", visibility::make(pub))]
pub(crate) struct UpdateFragmenter {
    code: UpdateCode,
    index: usize,
    #[doc(hidden)] // not part of the public API, used by benchmarks
    pub data: Vec<u8>,
    position: usize,
}

impl fmt::Debug for UpdateFragmenter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpdateFragmenter")
            .field("len", &self.data.len())
            .finish()
    }
}

impl UpdateFragmenter {
    pub(crate) fn new(code: UpdateCode, data: Vec<u8>) -> Self {
        Self {
            code,
            index: 0,
            data,
            position: 0,
        }
    }

    pub(crate) fn size_hint(&self) -> usize {
        FASTPATH_HEADER_SIZE + cmp::min(self.data.len(), MAX_FASTPATH_UPDATE_SIZE)
    }

    pub(crate) fn next(&mut self, dst: &mut [u8]) -> Option<usize> {
        let (consumed, written) = self.encode_next(dst)?;
        self.position += consumed;
        self.index = self.index.checked_add(1)?;
        Some(written)
    }

    fn encode_next(&mut self, dst: &mut [u8]) -> Option<(usize, usize)> {
        match self.data.len() - self.position {
            0 => None,

            1..=MAX_FASTPATH_UPDATE_SIZE => {
                let frag = if self.index > 0 {
                    Fragmentation::Last
                } else {
                    Fragmentation::Single
                };

                self.encode_fastpath(frag, &self.data[self.position..], dst)
                    .map(|written| (self.data.len() - self.position, written))
            }

            _ => {
                let frag = if self.index > 0 {
                    Fragmentation::Next
                } else {
                    Fragmentation::First
                };

                self.encode_fastpath(
                    frag,
                    &self.data[self.position..MAX_FASTPATH_UPDATE_SIZE + self.position],
                    dst,
                )
                .map(|written| (MAX_FASTPATH_UPDATE_SIZE, written))
            }
        }
    }

    fn encode_fastpath(&self, frag: Fragmentation, data: &[u8], dst: &mut [u8]) -> Option<usize> {
        let mut cursor = WriteCursor::new(dst);

        let update = FastPathUpdatePdu {
            fragmentation: frag,
            update_code: self.code,
            compression_flags: None,
            compression_type: None,
            data,
        };

        let header = FastPathHeader::new(EncryptionFlags::empty(), update.size());

        header.encode(&mut cursor).ok()?;
        update.encode(&mut cursor).ok()?;

        Some(cursor.pos())
    }
}

#[cfg(test)]
mod tests {
    use ironrdp_core::{ReadCursor, decode_cursor};

    use super::*;

    #[test]
    fn test_single_fragment() {
        let data = vec![1, 2, 3, 4];
        let mut fragmenter = UpdateFragmenter::new(UpdateCode::Bitmap, data);
        let mut buffer = vec![0; 100];
        let written = fragmenter.next(&mut buffer).unwrap();
        assert!(written > 0);
        assert_eq!(fragmenter.index, 1);

        let mut cursor = ReadCursor::new(&buffer);
        let header: FastPathHeader = decode_cursor(&mut cursor).unwrap();
        let update: FastPathUpdatePdu<'_> = decode_cursor(&mut cursor).unwrap();
        assert!(matches!(header, FastPathHeader { data_length: 7, .. }));
        assert!(matches!(
            update,
            FastPathUpdatePdu {
                fragmentation: Fragmentation::Single,
                ..
            }
        ));

        assert!(fragmenter.next(&mut buffer).is_none());
    }

    #[test]
    fn test_multi_fragment() {
        let data = vec![0u8; MAX_FASTPATH_UPDATE_SIZE * 2 + 10];
        let mut fragmenter = UpdateFragmenter::new(UpdateCode::Bitmap, data);
        let mut buffer = vec![0u8; fragmenter.size_hint()];
        let written = fragmenter.next(&mut buffer).unwrap();
        assert!(written > 0);
        assert_eq!(fragmenter.index, 1);

        let mut cursor = ReadCursor::new(&buffer);
        let _header: FastPathHeader = decode_cursor(&mut cursor).unwrap();
        let update: FastPathUpdatePdu<'_> = decode_cursor(&mut cursor).unwrap();
        assert!(matches!(
            update,
            FastPathUpdatePdu {
                fragmentation: Fragmentation::First,
                ..
            }
        ));
        assert_eq!(update.data.len(), MAX_FASTPATH_UPDATE_SIZE);

        let written = fragmenter.next(&mut buffer).unwrap();
        assert!(written > 0);
        assert_eq!(fragmenter.index, 2);
        let mut cursor = ReadCursor::new(&buffer);
        let _header: FastPathHeader = decode_cursor(&mut cursor).unwrap();
        let update: FastPathUpdatePdu<'_> = decode_cursor(&mut cursor).unwrap();
        assert!(matches!(
            update,
            FastPathUpdatePdu {
                fragmentation: Fragmentation::Next,
                ..
            }
        ));
        assert_eq!(update.data.len(), MAX_FASTPATH_UPDATE_SIZE);

        let written = fragmenter.next(&mut buffer).unwrap();
        assert!(written > 0);
        assert_eq!(fragmenter.index, 3);
        let mut cursor = ReadCursor::new(&buffer);
        let _header: FastPathHeader = decode_cursor(&mut cursor).unwrap();
        let update: FastPathUpdatePdu<'_> = decode_cursor(&mut cursor).unwrap();
        assert!(matches!(
            update,
            FastPathUpdatePdu {
                fragmentation: Fragmentation::Last,
                ..
            }
        ));
        assert_eq!(update.data.len(), 10);

        assert!(fragmenter.next(&mut buffer).is_none());
    }
}

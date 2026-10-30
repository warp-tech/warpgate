use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, cast_length, ensure_fixed_part_size,
    ensure_size, read_padding, write_padding,
};

use crate::geometry::InclusiveRectangle;

/// [2.2.11.2.1] Refresh Rect PDU Data (TS_REFRESH_RECT_PDU)
///
/// The Refresh Rect PDU allows the client to request that the server redraw one
/// or more rectangles of the session screen area. The client can use it to
/// repaint sections of the client window that were obscured by local
/// applications. Server support for this PDU is indicated in the General
/// Capability Set (section [2.2.7.1.1].
///
/// [2.2.11.2.1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/fe04a39d-dc10-489f-bea7-08dad5538547
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct RefreshRectanglePdu {
    pub areas_to_refresh: Vec<InclusiveRectangle>,
}

impl RefreshRectanglePdu {
    const NAME: &'static str = "RefreshRectanglePdu";

    const FIXED_PART_SIZE: usize = 1 /* numberOfAreas */ + 3 /* pad3Octets */;
}

impl Encode for RefreshRectanglePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        let n_areas = cast_length!("nAreas", self.areas_to_refresh.len())?;

        dst.write_u8(n_areas);
        write_padding!(dst, 3);
        for rectangle in self.areas_to_refresh.iter() {
            rectangle.encode(dst)?;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.areas_to_refresh.iter().map(|r| r.size()).sum::<usize>()
        // areasToRefresh
    }
}

impl<'de> Decode<'de> for RefreshRectanglePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let number_of_areas = usize::from(src.read_u8());
        read_padding!(src, 3);
        let areas_to_refresh = core::iter::repeat_with(|| InclusiveRectangle::decode(src))
            .take(number_of_areas)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { areas_to_refresh })
    }
}

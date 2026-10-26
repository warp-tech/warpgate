#[cfg(test)]
mod tests;

use bitflags::bitflags;
use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, ensure_fixed_part_size, read_padding,
    write_padding,
};

pub const BITMAP_CACHE_ENTRIES_NUM: usize = 3;

const BITMAP_CACHE_LENGTH: usize = 36;
const BITMAP_CACHE_REV2_LENGTH: usize = 36;
const CELL_INFO_LENGTH: usize = 4;
const BITMAP_CACHE_REV2_CELL_INFO_NUM: usize = 5;
const CACHE_ENTRY_LENGTH: usize = 4;

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct BitmapCache {
    pub caches: [CacheEntry; BITMAP_CACHE_ENTRIES_NUM],
}

impl BitmapCache {
    const NAME: &'static str = "BitmapCache";

    const FIXED_PART_SIZE: usize = BITMAP_CACHE_LENGTH;
}

impl Encode for BitmapCache {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        write_padding!(dst, 24);

        for cache in self.caches.iter() {
            cache.encode(dst)?;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for BitmapCache {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        read_padding!(src, 24);

        let mut caches = [CacheEntry::default(); BITMAP_CACHE_ENTRIES_NUM];

        for cache in caches.iter_mut() {
            *cache = CacheEntry::decode(src)?;
        }

        Ok(BitmapCache { caches })
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, Default)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct CacheEntry {
    pub entries: u16,
    pub max_cell_size: u16,
}

impl CacheEntry {
    const NAME: &'static str = "CacheEntry";

    const FIXED_PART_SIZE: usize = CACHE_ENTRY_LENGTH;
}

impl Encode for CacheEntry {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u16(self.entries);
        dst.write_u16(self.max_cell_size);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for CacheEntry {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let entries = src.read_u16();
        let max_cell_size = src.read_u16();

        Ok(CacheEntry { entries, max_cell_size })
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct CacheFlags: u16 {
        const PERSISTENT_KEYS_EXPECTED_FLAG = 1;
        const ALLOW_CACHE_WAITING_LIST_FLAG = 2;

        const _ = !0;
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct BitmapCacheRev2 {
    pub cache_flags: CacheFlags,
    pub num_cell_caches: u8,
    pub cache_cell_info: [CellInfo; BITMAP_CACHE_REV2_CELL_INFO_NUM],
}

impl BitmapCacheRev2 {
    const NAME: &'static str = "BitmapCacheRev2";

    const FIXED_PART_SIZE: usize = BITMAP_CACHE_REV2_LENGTH;
}

impl Encode for BitmapCacheRev2 {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u16(self.cache_flags.bits());
        write_padding!(dst, 1);
        dst.write_u8(self.num_cell_caches);

        for cell_info in self.cache_cell_info.iter() {
            cell_info.encode(dst)?;
        }

        write_padding!(dst, 12);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for BitmapCacheRev2 {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let cache_flags = CacheFlags::from_bits_retain(src.read_u16());
        let _padding = src.read_u8();
        let num_cell_caches = src.read_u8();

        let mut cache_cell_info = [CellInfo::default(); BITMAP_CACHE_REV2_CELL_INFO_NUM];

        for cell in cache_cell_info.iter_mut() {
            *cell = CellInfo::decode(src)?;
        }

        read_padding!(src, 12);

        Ok(BitmapCacheRev2 {
            cache_flags,
            num_cell_caches,
            cache_cell_info,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, Default)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct CellInfo {
    pub num_entries: u32,
    pub is_cache_persistent: bool,
}

impl CellInfo {
    const NAME: &'static str = "CellInfo";

    const FIXED_PART_SIZE: usize = CELL_INFO_LENGTH;
}

impl Encode for CellInfo {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        let mut data = self.num_entries;

        if self.is_cache_persistent {
            data |= 1 << 31;
        }

        dst.write_u32(data);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for CellInfo {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let cell_info = src.read_u32();

        let num_entries = cell_info & !(1 << 31);
        let is_cache_persistent = cell_info >> 31 != 0;

        Ok(CellInfo {
            num_entries,
            is_cache_persistent,
        })
    }
}

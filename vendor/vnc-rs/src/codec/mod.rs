mod cursor;
mod raw;
mod tight;
mod trle;
mod zlib;
mod zrle;
pub(crate) use cursor::Decoder as CursorDecoder;
pub(crate) use raw::Decoder as RawDecoder;
pub(crate) use tight::Decoder as TightDecoder;
pub(crate) use trle::Decoder as TrleDecoder;
pub(crate) use zrle::Decoder as ZrleDecoder;

fn uninit_vec(len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    #[allow(clippy::uninit_vec)]
    unsafe {
        v.set_len(len)
    };
    v
}

/// Warpgate fork: per-rectangle cap for target-driven zlib blob allocations (ZRLE/TRLE).
/// A single RFB rectangle's compressed data never legitimately approaches this; the wire
/// U32 length field would otherwise let a hostile target demand a multi-gigabyte buffer.
const MAX_RECT_DATA_LEN: usize = 64 * 1024 * 1024;

/// Warpgate fork: bounded [`uninit_vec`] — rejects lengths above [`MAX_RECT_DATA_LEN`]
/// before allocating. The returned buffer is only ever filled by an immediately following
/// `read_exact` of the same length, so the uninitialised bytes are never observed. See
/// PATCHES.md.
pub(crate) fn uninit_vec_capped(len: usize) -> Result<Vec<u8>, crate::VncError> {
    if len > MAX_RECT_DATA_LEN {
        return Err(crate::VncError::InvalidImageData);
    }
    Ok(uninit_vec(len))
}

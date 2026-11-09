use core::fmt;
use core::num::NonZeroU16;

use ironrdp_acceptor::DesktopSize;
use ironrdp_graphics::diff::{Rect, find_different_rects_sub};
use ironrdp_pdu::codecs::rfx::Quant;
use ironrdp_pdu::encode_vec;
use ironrdp_pdu::fast_path::UpdateCode;
use ironrdp_pdu::geometry::ExclusiveRectangle;
use ironrdp_pdu::pointer::{
    CachedPointerAttribute, ColorPointerAttribute, LargePointerAttribute, Point16, PointerAttribute,
    PointerPositionAttribute,
};
use ironrdp_pdu::rdp::capability_sets::{CmdFlags, EntropyBits, LargePointerSupportFlags};
use ironrdp_pdu::surface_commands::{ExtendedBitmapDataPdu, SurfaceBitsPdu, SurfaceCommand};
use tracing::{debug, warn};

use self::bitmap::BitmapEncoder;
use self::rfx::RfxEncoder;
use super::BitmapUpdate;
use crate::error::{ServerError, ServerErrorExt as _, ServerResult, ServerResultExt as _};
use crate::macros::time_warn;
use crate::{ColorPointer, DisplayUpdate, Framebuffer, LargePointer, RGBAPointer};

mod bitmap;
mod fast_path;
mod pointer_mask;
#[cfg(feature = "qoiz")]
pub(crate) mod qoiz;
pub(crate) mod rfx;

pub(crate) use fast_path::*;
use ironrdp_graphics::rdp6::BitmapEncodeError;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
enum CodecId {
    None = 0x0,
}

impl CodecId {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    fn as_u8(self) -> u8 {
        self as u8
    }
}

#[cfg_attr(any(feature = "__test", feature = "__bench"), visibility::make(pub))]
#[derive(Debug)]
pub(crate) struct UpdateEncoderCodecs {
    remotefx: Option<(EntropyBits, u8, RemoteFxCodec)>,
    /// Quantization values for the RemoteFX encoder. Independent of
    /// `remotefx` (entropy coder + codec id, negotiated from the client's
    /// capabilities) because this is server-chosen, not client-negotiated:
    /// [MS-RDPRFX] 2.2.2.1.5 leaves quantization entirely up to the sender.
    remotefx_quant: Quant,
    #[cfg(feature = "qoi")]
    qoi: Option<u8>,
    #[cfg(feature = "qoiz")]
    qoiz: Option<u8>,
    /// `(codec_id, color_loss_level)` from the negotiated NsCodec capability.
    #[cfg(feature = "nscodec")]
    nscodec: Option<(u8, u8)>,
}

impl UpdateEncoderCodecs {
    #[cfg_attr(any(feature = "__test", feature = "__bench"), visibility::make(pub))]
    pub(crate) fn new() -> Self {
        Self {
            remotefx: None,
            remotefx_quant: Quant::default(),
            #[cfg(feature = "qoi")]
            qoi: None,
            #[cfg(feature = "qoiz")]
            qoiz: None,
            #[cfg(feature = "nscodec")]
            nscodec: None,
        }
    }

    /// Selects the RemoteFX codec the client listed, with its entropy coder and codec id.
    #[cfg_attr(any(feature = "__test", feature = "__bench"), visibility::make(pub))]
    pub(crate) fn set_remotefx_codec(&mut self, remotefx: Option<(EntropyBits, u8, RemoteFxCodec)>) {
        self.remotefx = remotefx
    }

    /// Set the quantization values the RemoteFX encoder uses once selected.
    /// Has no effect unless `set_remotefx_codec` also selects RemoteFX; kept
    /// separate because quantization is server policy, not part of codec
    /// selection.
    #[cfg_attr(feature = "__bench", visibility::make(pub))]
    pub(crate) fn set_remotefx_quant(&mut self, quant: Quant) {
        self.remotefx_quant = quant
    }

    #[cfg(feature = "qoi")]
    #[cfg_attr(feature = "__bench", visibility::make(pub))]
    pub(crate) fn set_qoi(&mut self, qoi: Option<u8>) {
        self.qoi = qoi
    }

    #[cfg(feature = "qoiz")]
    #[cfg_attr(feature = "__bench", visibility::make(pub))]
    pub(crate) fn set_qoiz(&mut self, qoiz: Option<u8>) {
        self.qoiz = qoiz
    }

    /// Record the negotiated NsCodec codec id and color-loss level so the
    /// encoder selection path can build an `NsCodecHandler` for this session.
    #[cfg(feature = "nscodec")]
    #[cfg_attr(feature = "__bench", visibility::make(pub))]
    pub(crate) fn set_nscodec(&mut self, nscodec: Option<(u8, u8)>) {
        self.nscodec = nscodec
    }
}

impl Default for UpdateEncoderCodecs {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg_attr(any(feature = "__test", feature = "__bench"), visibility::make(pub))]
pub(crate) struct UpdateEncoder {
    desktop_size: DesktopSize,
    framebuffer: Option<Framebuffer>,
    bitmap_updater: Option<BitmapUpdater>,
    /// Negotiated MultifragmentUpdate reassembly buffer size. Used to split
    /// oversized bitmaps into strips that fit within the limit when sent as
    /// uncompressed surface commands.
    max_request_size: usize,
    /// Client's advertised New Pointer Update cache size (MS-RDPBCGR 2.2.7.1.5
    /// `pointerCacheSize`). Zero means the client did not advertise support for the
    /// New Pointer Update; `RGBAPointer`/`CachedPointer` emission is skipped in that
    /// case rather than sending a PDU the client did not agree to accept.
    pointer_cache_size: u16,
    /// Client's advertised Large Pointer Capability Set flags (MS-RDPBCGR 2.2.7.2.7).
    /// Empty when the client didn't send this capability set at all. Governs both the
    /// pointer size ceiling for `RGBAPointer` (32x32 with no flags, 96x96 with
    /// `UP_TO_96X96_PIXELS`) and whether the dedicated `LargePointer` update, up to
    /// 384x384, is usable at all (`UP_TO_384X384_PIXELS`).
    large_pointer_flags: LargePointerSupportFlags,
}

impl fmt::Debug for UpdateEncoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpdateEncoder")
            .field("bitmap_update", &self.bitmap_updater)
            .finish()
    }
}

impl UpdateEncoder {
    #[cfg_attr(any(feature = "__test", feature = "__bench"), visibility::make(pub))]
    pub(crate) fn new(
        desktop_size: DesktopSize,
        surface_flags: CmdFlags,
        codecs: UpdateEncoderCodecs,
        max_request_size: u32,
        pointer_cache_size: u16,
        large_pointer_flags: LargePointerSupportFlags,
    ) -> ServerResult<Self> {
        let bitmap_updater = if surface_flags.contains(CmdFlags::SET_SURFACE_BITS) {
            match codecs {
                #[cfg(feature = "qoiz")]
                UpdateEncoderCodecs { qoiz: Some(id), .. } => BitmapUpdater::Qoiz(QoizHandler::new(id)?),
                #[cfg(feature = "qoi")]
                UpdateEncoderCodecs { qoi: Some(id), .. } => BitmapUpdater::Qoi(QoiHandler::new(id)),
                UpdateEncoderCodecs {
                    remotefx: Some((algo, id, codec)),
                    remotefx_quant,
                    ..
                } => {
                    let command = codec.surface_bits_command(surface_flags);
                    BitmapUpdater::RemoteFx(RemoteFxHandler::new(algo, remotefx_quant, id, desktop_size, command))
                }
                // NSCodec is the lowest-priority codec because it predates
                // RemoteFX and produces larger output. It's relevant mainly
                // for clients (notably macOS Microsoft Remote Desktop /
                // Windows App) whose legacy bitmap-codec list advertises
                // only NSCodec — those clients would otherwise fall through
                // to raw/RLE BitmapUpdate at much higher bandwidth.
                #[cfg(feature = "nscodec")]
                UpdateEncoderCodecs {
                    nscodec: Some((id, cll)),
                    ..
                } => BitmapUpdater::NsCodec(NsCodecHandler::new(id, cll)),
                _ => BitmapUpdater::None(NoneHandler),
            }
        } else {
            BitmapUpdater::Bitmap(BitmapHandler::new())
        };

        Ok(Self {
            desktop_size,
            framebuffer: None,
            bitmap_updater: Some(bitmap_updater),
            max_request_size: usize::try_from(max_request_size)
                .map_err(|e| ServerError::custom("max_request_size", e))?,
            pointer_cache_size,
            large_pointer_flags,
        })
    }

    /// Whether a `width`x`height` pointer shape fits the Color/New Pointer Update
    /// ceiling: 96x96 if the client's Large Pointer Capability Set includes
    /// `UP_TO_96X96_PIXELS` (MS-RDPBCGR 2.2.9.1.1.4.4's width/height field docs; New
    /// Pointer Update carries the same `ColorPointerAttribute` internally, so the same
    /// ceiling applies to both), 32x32 otherwise. Shapes above this ceiling need the
    /// dedicated Large Pointer Update instead (see `large_pointer_update_supported`).
    fn color_or_new_pointer_size_ok(&self, width: u16, height: u16) -> bool {
        let max = if self
            .large_pointer_flags
            .contains(LargePointerSupportFlags::UP_TO_96X96_PIXELS)
        {
            96
        } else {
            32
        };
        width <= max && height <= max
    }

    /// Whether the client negotiated the dedicated Fast-Path Large Pointer Update
    /// itself. Per MS-RDPBCGR 2.2.7.2.7, only `UP_TO_384X384_PIXELS` unlocks this PDU;
    /// `UP_TO_96X96_PIXELS` alone only raises the Color/New Pointer Update ceiling and
    /// does not enable it.
    fn large_pointer_update_supported(&self) -> bool {
        self.large_pointer_flags
            .contains(LargePointerSupportFlags::UP_TO_384X384_PIXELS)
    }

    #[cfg_attr(any(feature = "__test", feature = "__bench"), visibility::make(pub))]
    pub(crate) fn update(&mut self, update: DisplayUpdate) -> EncoderIter<'_> {
        EncoderIter {
            encoder: self,
            state: State::Start(update),
        }
    }

    pub(crate) fn set_desktop_size(&mut self, size: DesktopSize) {
        self.desktop_size = size;
        self.bitmap_updater
            .as_mut()
            .expect("bitmap updater always Some")
            .set_desktop_size(size);
    }

    fn rgba_pointer(ptr: RGBAPointer) -> ServerResult<UpdateFragmenter> {
        let xor_mask = ptr.data;
        let and_mask = pointer_mask::and_mask_from_alpha(&xor_mask, ptr.width, ptr.height);

        let hot_spot = Point16 {
            x: ptr.hot_x,
            y: ptr.hot_y,
        };
        let color_pointer = ColorPointerAttribute {
            cache_index: ptr.cache_index,
            hot_spot,
            width: ptr.width,
            height: ptr.height,
            xor_mask: &xor_mask,
            and_mask: &and_mask,
        };
        let ptr = PointerAttribute {
            xor_bpp: 32,
            color_pointer,
        };
        Ok(UpdateFragmenter::new(
            UpdateCode::NewPointer,
            encode_vec(&ptr).map_err(ServerError::encode)?,
        ))
    }

    fn large_pointer(ptr: LargePointer) -> ServerResult<UpdateFragmenter> {
        let xor_mask = ptr.data;
        let and_mask = pointer_mask::and_mask_from_alpha(&xor_mask, ptr.width, ptr.height);

        let hot_spot = Point16 {
            x: ptr.hot_x,
            y: ptr.hot_y,
        };
        let large_pointer = LargePointerAttribute {
            xor_bpp: 32,
            cache_index: ptr.cache_index,
            hot_spot,
            width: ptr.width,
            height: ptr.height,
            xor_mask: &xor_mask,
            and_mask: &and_mask,
        };
        Ok(UpdateFragmenter::new(
            UpdateCode::LargePointer,
            encode_vec(&large_pointer).map_err(ServerError::encode)?,
        ))
    }

    fn color_pointer(ptr: ColorPointer) -> ServerResult<UpdateFragmenter> {
        let hot_spot = Point16 {
            x: ptr.hot_x,
            y: ptr.hot_y,
        };
        let ptr = ColorPointerAttribute {
            cache_index: ptr.cache_index,
            hot_spot,
            width: ptr.width,
            height: ptr.height,
            xor_mask: &ptr.xor_mask,
            and_mask: &ptr.and_mask,
        };
        Ok(UpdateFragmenter::new(
            UpdateCode::ColorPointer,
            encode_vec(&ptr).map_err(ServerError::encode)?,
        ))
    }

    fn cached_pointer(cache_index: u16) -> ServerResult<UpdateFragmenter> {
        let ptr = CachedPointerAttribute { cache_index };
        Ok(UpdateFragmenter::new(
            UpdateCode::CachedPointer,
            encode_vec(&ptr).map_err(ServerError::encode)?,
        ))
    }

    fn default_pointer() -> ServerResult<UpdateFragmenter> {
        Ok(UpdateFragmenter::new(UpdateCode::DefaultPointer, vec![]))
    }

    fn hide_pointer() -> ServerResult<UpdateFragmenter> {
        Ok(UpdateFragmenter::new(UpdateCode::HiddenPointer, vec![]))
    }

    fn pointer_position(pos: PointerPositionAttribute) -> ServerResult<UpdateFragmenter> {
        Ok(UpdateFragmenter::new(
            UpdateCode::PositionPointer,
            encode_vec(&pos).map_err(ServerError::encode)?,
        ))
    }

    fn bitmap_diffs(&mut self, bitmap: &BitmapUpdate) -> Vec<Rect> {
        // TODO: we may want to make it optional for servers that already provide damaged regions
        const USE_DIFFS: bool = true;

        let diffs = if let Some(Framebuffer {
            data,
            stride,
            width,
            height,
            ..
        }) = USE_DIFFS.then_some(self.framebuffer.as_ref()).flatten()
        {
            find_different_rects_sub::<4>(
                data,
                *stride,
                width.get().into(),
                height.get().into(),
                &bitmap.data,
                bitmap.stride.get(),
                bitmap.width.get().into(),
                bitmap.height.get().into(),
                bitmap.x.into(),
                bitmap.y.into(),
            )
        } else {
            vec![Rect {
                x: 0,
                y: 0,
                width: bitmap.width.get().into(),
                height: bitmap.height.get().into(),
            }]
        };

        // Subdivide diff rects whose uncompressed size would exceed the
        // MultifragmentUpdate reassembly buffer.
        let mut tiled = Vec::with_capacity(diffs.len());
        for rect in diffs {
            if rect.width * rect.height * 4 <= self.max_request_size {
                tiled.push(rect);
            } else {
                let rects = self.split_diff(rect);
                tiled.extend(rects);
            }
        }
        tiled
    }

    /// Split a rect into tiles that fit within `max_request_size`.
    /// Splits by height first, then by width within each horizontal strip.
    fn split_diff(&self, rect: Rect) -> Vec<Rect> {
        let mut rects = Vec::new();

        let max_height = (self.max_request_size / (rect.width * 4)).max(1);
        let mut y = rect.y;
        let y_end = rect.y + rect.height;
        while y < y_end {
            let h = (y_end - y).min(max_height);
            // Width splitting is unlikely in practice (would require
            // max_request_size < ~256 KB), but ensures correctness.
            let max_width = (self.max_request_size / (h * 4)).max(1);
            let mut x = rect.x;
            let x_end = rect.x + rect.width;
            while x < x_end {
                let w = (x_end - x).min(max_width);
                rects.push(Rect {
                    x,
                    y,
                    width: w,
                    height: h,
                });
                x += max_width;
            }
            y += max_height;
        }

        rects
    }

    fn bitmap_update_framebuffer(&mut self, bitmap: BitmapUpdate, diffs: &[Rect]) {
        if bitmap.x == 0
            && bitmap.y == 0
            && bitmap.width.get() == self.desktop_size.width
            && bitmap.height.get() == self.desktop_size.height
        {
            match bitmap.try_into() {
                Ok(framebuffer) => self.framebuffer = Some(framebuffer),
                Err(err) => warn!("Failed to convert bitmap to framebuffer: {}", err),
            }
        } else if let Some(fb) = self.framebuffer.as_mut() {
            fb.update_diffs(&bitmap, diffs);
        }
    }

    async fn bitmap(&mut self, bitmap: BitmapUpdate) -> ServerResult<UpdateFragmenter> {
        // Move the bitmap updater to satisfy spawn_blocking 'static requirement.
        // It is restored after the blocking operation completes.
        let mut updater = self.bitmap_updater.take().expect("bitmap updater always Some");

        let (result, updater) = tokio::task::spawn_blocking(move || {
            let result = time_warn!("Encoding bitmap", 10, updater.handle(&bitmap));
            (result, updater)
        })
        .await
        .map_err(|e| ServerError::custom("bitmap encoder task", e))?;

        self.bitmap_updater = Some(updater);

        result
    }
}

#[derive(Debug, Default)]
enum State {
    Start(DisplayUpdate),
    BitmapDiffs {
        diffs: Vec<Rect>,
        bitmap: BitmapUpdate,
        pos: usize,
    },
    #[default]
    Ended,
}

#[cfg_attr(any(feature = "__test", feature = "__bench"), visibility::make(pub))]
pub(crate) struct EncoderIter<'a> {
    encoder: &'a mut UpdateEncoder,
    state: State,
}

impl EncoderIter<'_> {
    #[cfg_attr(any(feature = "__test", feature = "__bench"), visibility::make(pub))]
    pub(crate) async fn next(&mut self) -> Option<ServerResult<UpdateFragmenter>> {
        loop {
            let state = core::mem::take(&mut self.state);
            let encoder = &mut self.encoder;

            let res = match state {
                State::Start(update) => match update {
                    DisplayUpdate::Bitmap(bitmap) => {
                        let ds = encoder.desktop_size;
                        if bitmap.x + bitmap.width.get() > ds.width || bitmap.y + bitmap.height.get() > ds.height {
                            debug!(
                                "Dropping bitmap update that exceeds desktop size: \
                                 bitmap ({}, {}) {}x{} vs desktop {}x{}",
                                bitmap.x, bitmap.y, bitmap.width, bitmap.height, ds.width, ds.height,
                            );
                            continue;
                        }
                        let diffs = encoder.bitmap_diffs(&bitmap);
                        self.state = State::BitmapDiffs { diffs, bitmap, pos: 0 };
                        continue;
                    }
                    DisplayUpdate::PointerPosition(pos) => UpdateEncoder::pointer_position(pos),
                    DisplayUpdate::RGBAPointer(ptr) => {
                        if encoder.pointer_cache_size == 0 {
                            debug!("Dropping RGBAPointer update: client did not advertise New Pointer Update support");
                            continue;
                        }
                        if !encoder.color_or_new_pointer_size_ok(ptr.width, ptr.height) {
                            debug!(
                                "Dropping RGBAPointer update: {}x{} exceeds the client's negotiated pointer size \
                                 ceiling",
                                ptr.width, ptr.height,
                            );
                            continue;
                        }
                        UpdateEncoder::rgba_pointer(ptr)
                    }
                    DisplayUpdate::LargePointer(ptr) => {
                        if encoder.pointer_cache_size == 0 {
                            debug!("Dropping LargePointer update: client did not advertise New Pointer Update support");
                            continue;
                        }
                        if !encoder.large_pointer_update_supported() {
                            debug!(
                                "Dropping LargePointer update: client did not advertise \
                                 LARGE_POINTER_FLAG_384x384 support"
                            );
                            continue;
                        }
                        if 384 < ptr.width || 384 < ptr.height {
                            debug!(
                                "Dropping LargePointer update: {}x{} exceeds the 384x384 protocol maximum",
                                ptr.width, ptr.height,
                            );
                            continue;
                        }
                        UpdateEncoder::large_pointer(ptr)
                    }
                    DisplayUpdate::ColorPointer(ptr) => UpdateEncoder::color_pointer(ptr),
                    DisplayUpdate::HidePointer => UpdateEncoder::hide_pointer(),
                    DisplayUpdate::DefaultPointer => UpdateEncoder::default_pointer(),
                    DisplayUpdate::CachedPointer(idx) => {
                        if encoder.pointer_cache_size == 0 {
                            debug!(
                                "Dropping CachedPointer update: client did not advertise New Pointer Update support"
                            );
                            continue;
                        }
                        UpdateEncoder::cached_pointer(idx)
                    }
                    DisplayUpdate::Resize(_) => return None,
                },
                State::BitmapDiffs { diffs, bitmap, pos } => {
                    let Some(rect) = diffs.get(pos) else {
                        encoder.bitmap_update_framebuffer(bitmap, &diffs);
                        self.state = State::Ended;
                        return None;
                    };
                    let Rect { x, y, width, height } = *rect;

                    let x = match u16::try_from(x) {
                        Ok(x) => x,
                        Err(_) => {
                            return Some(Err(ServerError::reason(
                                "bitmap diff",
                                "invalid `x`: out of range integral conversion",
                            )));
                        }
                    };
                    let y = match u16::try_from(y) {
                        Ok(y) => y,
                        Err(_) => {
                            return Some(Err(ServerError::reason(
                                "bitmap diff",
                                "invalid `y`: out of range integral conversion",
                            )));
                        }
                    };
                    let width = match u16::try_from(width) {
                        Ok(width) => match NonZeroU16::new(width) {
                            Some(width) => width,
                            None => {
                                return Some(Err(ServerError::reason(
                                    "bitmap diff",
                                    "rectangle width cannot be zero",
                                )));
                            }
                        },
                        Err(_) => {
                            return Some(Err(ServerError::reason(
                                "bitmap diff",
                                "invalid `width`: out of range integral conversion",
                            )));
                        }
                    };
                    let height = match u16::try_from(height) {
                        Ok(height) => match NonZeroU16::new(height) {
                            Some(height) => height,
                            None => {
                                return Some(Err(ServerError::reason(
                                    "bitmap diff",
                                    "rectangle height cannot be zero",
                                )));
                            }
                        },
                        Err(_) => {
                            return Some(Err(ServerError::reason(
                                "bitmap diff",
                                "invalid `height`: out of range integral conversion",
                            )));
                        }
                    };

                    let Some(sub) = bitmap.sub(x, y, width, height) else {
                        warn!("Failed to extract bitmap subregion");
                        return None;
                    };
                    self.state = State::BitmapDiffs {
                        diffs,
                        bitmap,
                        pos: pos + 1,
                    };
                    encoder.bitmap(sub).await
                }
                State::Ended => return None,
            };

            return Some(res);
        }
    }
}

#[derive(Debug)]
enum BitmapUpdater {
    None(NoneHandler),
    Bitmap(BitmapHandler),
    RemoteFx(RemoteFxHandler),
    #[cfg(feature = "qoi")]
    Qoi(QoiHandler),
    #[cfg(feature = "qoiz")]
    Qoiz(QoizHandler),
    #[cfg(feature = "nscodec")]
    NsCodec(NsCodecHandler),
}

impl BitmapUpdater {
    fn handle(&mut self, bitmap: &BitmapUpdate) -> ServerResult<UpdateFragmenter> {
        match self {
            Self::None(up) => up.handle(bitmap),
            Self::Bitmap(up) => up.handle(bitmap),
            Self::RemoteFx(up) => up.handle(bitmap),
            #[cfg(feature = "qoi")]
            Self::Qoi(up) => up.handle(bitmap),
            #[cfg(feature = "qoiz")]
            Self::Qoiz(up) => up.handle(bitmap),
            #[cfg(feature = "nscodec")]
            Self::NsCodec(up) => up.handle(bitmap),
        }
    }

    fn set_desktop_size(&mut self, size: DesktopSize) {
        if let Self::RemoteFx(up) = self {
            up.set_desktop_size(size)
        }
    }
}

trait BitmapUpdateHandler {
    fn handle(&mut self, bitmap: &BitmapUpdate) -> ServerResult<UpdateFragmenter>;
}

#[derive(Clone, Debug)]
struct NoneHandler;

impl BitmapUpdateHandler for NoneHandler {
    fn handle(&mut self, bitmap: &BitmapUpdate) -> ServerResult<UpdateFragmenter> {
        let stride = usize::from(bitmap.format.bytes_per_pixel()) * usize::from(bitmap.width.get());
        let mut data = Vec::with_capacity(stride * usize::from(bitmap.height.get()));
        for row in bitmap.data.chunks(bitmap.stride.get()).rev() {
            data.extend_from_slice(&row[..stride]);
        }
        set_surface(bitmap, CodecId::None.as_u8(), &data)
    }
}

#[derive(Clone)]
struct BitmapHandler {
    bitmap: BitmapEncoder,
}

impl fmt::Debug for BitmapHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitmapHandler").finish()
    }
}

impl BitmapHandler {
    fn new() -> Self {
        Self {
            bitmap: BitmapEncoder::new(),
        }
    }
}

impl BitmapUpdateHandler for BitmapHandler {
    fn handle(&mut self, bitmap: &BitmapUpdate) -> ServerResult<UpdateFragmenter> {
        let mut buffer = vec![0; bitmap.data.len() * 2]; // TODO: estimate bitmap encoded size
        let len = loop {
            match self.bitmap.encode(bitmap, buffer.as_mut_slice()) {
                Err(err) => match err {
                    BitmapEncodeError::Encode(e) => match e.kind() {
                        ironrdp_core::EncodeErrorKind::NotEnoughBytes { .. } => {
                            buffer.resize(buffer.len() * 2, 0);
                            debug!("encoder buffer resized to: {}", buffer.len() * 2);
                        }
                        _ => return Err(ServerError::encode(e)).with_context("bitmap encode error"),
                    },
                    BitmapEncodeError::Rle(e) => return Err(ServerError::custom("bitmap RLE encode error", e)),
                },
                Ok(len) => break len,
            }
        };

        buffer.truncate(len);
        Ok(UpdateFragmenter::new(UpdateCode::Bitmap, buffer))
    }
}

/// A RemoteFX codec GUID from the client's [2.2.7.2.10.1.1] Bitmap Codec (TS_BITMAPCODEC) list.
///
/// [2.2.7.2.10.1.1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/86507fed-a0ee-4242-b802-237534a8f65e
#[cfg_attr(any(feature = "__test", feature = "__bench"), visibility::make(pub))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteFxCodec {
    /// `CODEC_GUID_REMOTEFX`
    RemoteFx,
    /// `CODEC_GUID_IMAGE_REMOTEFX`
    ImageRemoteFx,
}

impl RemoteFxCodec {
    /// The surface command that carries this codec's data.
    ///
    /// [3.1.8.3.1] Encode Message Sequencing puts a RemoteFX stream in a Stream Surface Bits
    /// command; it is sent when the client sets `STREAM_SURFACE_BITS` in its [2.2.7.2.9]
    /// Surface Commands Capability Set (TS_SURFCMDS_CAPABILITYSET). Windows 10 mstsc shows a
    /// black session when RemoteFX data comes in a Set Surface Bits command, and reports an
    /// internal error when ImageRemoteFX data comes in a Stream Surface Bits command, so
    /// ImageRemoteFX keeps Set Surface Bits. A client that does not set `STREAM_SURFACE_BITS`
    /// also keeps getting RemoteFX data in Set Surface Bits, as before this command choice.
    ///
    /// [3.1.8.3.1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdprfx/028ed301-385c-4b17-84ec-0a158a22c1b2
    /// [2.2.7.2.9]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/aa953018-c0a8-4761-bb12-86586c2cd56a
    fn surface_bits_command(self, surface_flags: CmdFlags) -> SurfaceBitsCommand {
        match self {
            Self::RemoteFx if surface_flags.contains(CmdFlags::STREAM_SURFACE_BITS) => SurfaceBitsCommand::Stream,
            Self::RemoteFx | Self::ImageRemoteFx => SurfaceBitsCommand::Set,
        }
    }
}

/// The command that carries bitmap data, one of the [2.2.9.2] Surface Commands.
///
/// [2.2.9.2]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/397d6c54-a897-498d-933b-300fed41ec8c
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SurfaceBitsCommand {
    /// [2.2.9.2.1] Set Surface Bits Command (TS_SURFCMD_SET_SURF_BITS)
    ///
    /// [2.2.9.2.1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/776dbdaf-7619-45fd-9a90-ebfd07802b24
    Set,
    /// [2.2.9.2.2] Stream Surface Bits Command (TS_SURFCMD_STREAM_SURF_BITS)
    ///
    /// [2.2.9.2.2]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b2218638-3cf9-4f2f-be61-b096ec3c8dc5
    Stream,
}

#[derive(Debug, Clone)]
struct RemoteFxHandler {
    remotefx: RfxEncoder,
    codec_id: u8,
    desktop_size: Option<DesktopSize>,
    command: SurfaceBitsCommand,
}

impl RemoteFxHandler {
    fn new(
        algo: EntropyBits,
        quant: Quant,
        codec_id: u8,
        desktop_size: DesktopSize,
        command: SurfaceBitsCommand,
    ) -> Self {
        Self {
            remotefx: RfxEncoder::new(algo, quant),
            desktop_size: Some(desktop_size),
            codec_id,
            command,
        }
    }

    fn set_desktop_size(&mut self, size: DesktopSize) {
        self.desktop_size = Some(size);
    }
}

impl BitmapUpdateHandler for RemoteFxHandler {
    fn handle(&mut self, bitmap: &BitmapUpdate) -> ServerResult<UpdateFragmenter> {
        let mut buffer = vec![0; bitmap.data.len()];
        let len = loop {
            match self
                .remotefx
                .encode(bitmap, buffer.as_mut_slice(), self.desktop_size)
            {
                Err(e) => match e.kind() {
                    ironrdp_core::EncodeErrorKind::NotEnoughBytes { .. } => {
                        buffer.resize(buffer.len() * 2, 0);
                        debug!("encoder buffer resized to: {}", buffer.len() * 2);
                    }
                    _ => return Err(ServerError::encode(e)).with_context("RemoteFX encode error"),
                },
                Ok(len) => break len,
            }
        };

        surface_bits(bitmap, self.codec_id, &buffer[..len], self.command)
    }
}

#[cfg(feature = "qoi")]
#[derive(Clone, Debug)]
struct QoiHandler {
    codec_id: u8,
}

#[cfg(feature = "qoi")]
impl QoiHandler {
    fn new(codec_id: u8) -> Self {
        Self { codec_id }
    }
}

#[cfg(feature = "qoi")]
impl BitmapUpdateHandler for QoiHandler {
    fn handle(&mut self, bitmap: &BitmapUpdate) -> ServerResult<UpdateFragmenter> {
        let data = qoi_encode(bitmap)?;
        set_surface(bitmap, self.codec_id, &data)
    }
}

#[cfg(feature = "qoiz")]
struct QoizHandler {
    codec_id: u8,
    compressor: qoiz::Compressor,
}

#[cfg(feature = "qoiz")]
impl fmt::Debug for QoizHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QoizHandler").field("codec_id", &self.codec_id).finish()
    }
}

#[cfg(feature = "qoiz")]
impl QoizHandler {
    fn new(codec_id: u8) -> ServerResult<Self> {
        Ok(Self {
            codec_id,
            compressor: qoiz::Compressor::new()?,
        })
    }
}

#[cfg(feature = "qoiz")]
impl BitmapUpdateHandler for QoizHandler {
    fn handle(&mut self, bitmap: &BitmapUpdate) -> ServerResult<UpdateFragmenter> {
        let qoi = qoi_encode(bitmap)?;
        let data = self.compressor.compress(&qoi)?;

        set_surface(bitmap, self.codec_id, &data)
    }
}

#[cfg(feature = "nscodec")]
#[derive(Clone, Debug)]
struct NsCodecHandler {
    codec_id: u8,
    color_loss_level: u8,
}

#[cfg(feature = "nscodec")]
impl NsCodecHandler {
    fn new(codec_id: u8, color_loss_level: u8) -> Self {
        Self {
            codec_id,
            color_loss_level,
        }
    }
}

#[cfg(feature = "nscodec")]
impl BitmapUpdateHandler for NsCodecHandler {
    fn handle(&mut self, bitmap: &BitmapUpdate) -> ServerResult<UpdateFragmenter> {
        let data = ironrdp_nscodec::encoder::encode(
            &bitmap.data,
            bitmap.width.get(),
            bitmap.height.get(),
            bitmap.stride.get(),
            bitmap.format,
            self.color_loss_level,
        );
        set_surface(bitmap, self.codec_id, &data)
    }
}

#[cfg(feature = "qoi")]
fn qoi_encode(bitmap: &BitmapUpdate) -> ServerResult<Vec<u8>> {
    use ironrdp_graphics::image_processing::PixelFormat::*;
    // Map every 4-byte input — whether it nominally has an alpha byte or
    // an "X" filler — to the 3-channel-output `*x` variant of
    // `RawChannels`. The qoi crate selects `Channels::Rgb` vs
    // `Channels::Rgba` for the QOI header from this enum: `*x` and `*r/g/b`
    // produce `Rgb`; `*a` produces `Rgba`. The `ironrdp-session` NSCodec-
    // free decode path in `fast_path.rs::qoi_apply` only supports
    // `Channels::Rgb` and explicitly drops `Channels::Rgba` frames with
    // `WARN: Unsupported RGBA QOI data`, so the previous "honest" mapping
    // (`BgrA32 -> Bgra`, etc.) produced output that no IronRDP client
    // could decode — every QOI session rendered a blank screen.
    //
    // Server-side bitmap captures are functionally opaque (the alpha byte
    // is either always 0xFF or treated as filler), so discarding it is
    // safe and matches what every successful legacy bitmap path
    // already does.
    let raw_channels = match bitmap.format {
        ARgb32 | XRgb32 => qoi::RawChannels::Xrgb,
        ABgr32 | XBgr32 => qoi::RawChannels::Xbgr,
        BgrA32 | BgrX32 => qoi::RawChannels::Bgrx,
        RgbA32 | RgbX32 => qoi::RawChannels::Rgbx,
    };
    let enc = qoi::EncoderBuilder::new(&bitmap.data, bitmap.width.get().into(), bitmap.height.get().into())
        .stride(bitmap.stride.get())
        .raw_channels(raw_channels)
        .build()
        .map_err(|e| ServerError::custom("qoi encoder build", e))?;
    enc.encode_to_vec().map_err(|e| ServerError::custom("qoi encode", e))
}

fn set_surface(bitmap: &BitmapUpdate, codec_id: u8, data: &[u8]) -> ServerResult<UpdateFragmenter> {
    surface_bits(bitmap, codec_id, data, SurfaceBitsCommand::Set)
}

fn surface_bits(
    bitmap: &BitmapUpdate,
    codec_id: u8,
    data: &[u8],
    command: SurfaceBitsCommand,
) -> ServerResult<UpdateFragmenter> {
    let destination = ExclusiveRectangle {
        left: bitmap.x,
        top: bitmap.y,
        right: bitmap.x + bitmap.width.get(),
        bottom: bitmap.y + bitmap.height.get(),
    };
    let extended_bitmap_data = ExtendedBitmapDataPdu {
        bpp: bitmap.format.bytes_per_pixel() * 8,
        width: bitmap.width.get(),
        height: bitmap.height.get(),
        codec_id,
        header: None,
        data,
    };
    let pdu = SurfaceBitsPdu {
        destination,
        extended_bitmap_data,
    };
    let cmd = match command {
        SurfaceBitsCommand::Set => SurfaceCommand::SetSurfaceBits(pdu),
        SurfaceBitsCommand::Stream => SurfaceCommand::StreamSurfaceBits(pdu),
    };
    Ok(UpdateFragmenter::new(
        UpdateCode::SurfaceCommands,
        encode_vec(&cmd).map_err(ServerError::encode)?,
    ))
}

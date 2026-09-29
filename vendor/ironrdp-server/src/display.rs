use core::num::{NonZeroU16, NonZeroUsize};

use anyhow::Result;
use bytes::{Bytes, BytesMut};
use ironrdp_displaycontrol::pdu::DisplayControlMonitorLayout;
use ironrdp_graphics::diff;
use ironrdp_pdu::pointer::PointerPositionAttribute;
use tracing::{debug, warn};

#[rustfmt::skip]
pub use ironrdp_acceptor::DesktopSize;
pub use ironrdp_graphics::image_processing::PixelFormat;

/// Display Update
///
/// Contains all types of display updates currently supported by the server implementation
/// and the RDP spec
///
#[derive(Debug, Clone)]
pub enum DisplayUpdate {
    Resize(DesktopSize),
    Bitmap(BitmapUpdate),
    PointerPosition(PointerPositionAttribute),
    ColorPointer(ColorPointer),
    RGBAPointer(RGBAPointer),
    HidePointer,
    DefaultPointer,
    CachedPointer(u16),
}

#[derive(Clone)]
pub struct RGBAPointer {
    pub cache_index: u16,
    pub width: u16,
    pub height: u16,
    pub hot_x: u16,
    pub hot_y: u16,
    pub data: Vec<u8>,
}

impl core::fmt::Debug for RGBAPointer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RGBAPointer")
            .field("with", &self.width)
            .field("height", &self.height)
            .field("hot_x", &self.hot_x)
            .field("hot_y", &self.hot_y)
            .field("data_len", &self.data.len())
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct ColorPointer {
    pub cache_index: u16,
    pub width: u16,
    pub height: u16,
    pub hot_x: u16,
    pub hot_y: u16,
    pub and_mask: Vec<u8>,
    pub xor_mask: Vec<u8>,
}

pub struct Framebuffer {
    pub width: NonZeroU16,
    pub height: NonZeroU16,
    pub format: PixelFormat,
    pub data: BytesMut,
    pub stride: usize,
}

impl TryInto<Framebuffer> for BitmapUpdate {
    type Error = &'static str;

    fn try_into(self) -> Result<Framebuffer, Self::Error> {
        assert_eq!(self.x, 0);
        assert_eq!(self.y, 0);
        Ok(Framebuffer {
            width: self.width,
            height: self.height,
            format: self.format,
            data: self.data.into(),
            stride: self.stride.get(),
        })
    }
}

impl Framebuffer {
    pub fn new(width: NonZeroU16, height: NonZeroU16, format: PixelFormat) -> Self {
        let mut data = BytesMut::new();
        let w = NonZeroUsize::from(width).get();
        let h = NonZeroUsize::from(height).get();
        let bpp = usize::from(format.bytes_per_pixel());
        data.resize(bpp * w * h, 0);

        Self {
            width,
            height,
            format,
            data,
            stride: bpp * w,
        }
    }

    pub fn update(&mut self, bitmap: &BitmapUpdate) {
        if self.format != bitmap.format {
            warn!("Bitmap format mismatch, unsupported");
            return;
        }
        let bpp = usize::from(self.format.bytes_per_pixel());
        let x = usize::from(bitmap.x);
        let y = usize::from(bitmap.y);
        let width = NonZeroUsize::from(bitmap.width).get();
        let height = NonZeroUsize::from(bitmap.height).get();

        let data = &mut self.data;
        let start = y * self.stride + x * bpp;
        let end = start + (height - 1) * self.stride + width * bpp;
        let dst = &mut data[start..end];

        for y in 0..height {
            let start = y * bitmap.stride.get();
            let end = start + width * bpp;

            let src = bitmap.data.slice(start..end);

            let start = y * self.stride;
            let end = start + width * bpp;
            let dst = &mut dst[start..end];

            dst.copy_from_slice(&src);
        }
    }

    pub(crate) fn update_diffs(&mut self, bitmap: &BitmapUpdate, diffs: &[diff::Rect]) {
        diffs
            .iter()
            .filter_map(|diff| {
                let x = u16::try_from(diff.x).ok()?;
                let y = u16::try_from(diff.y).ok()?;
                let width = u16::try_from(diff.width).ok().and_then(NonZeroU16::new)?;
                let height = u16::try_from(diff.height).ok().and_then(NonZeroU16::new)?;

                bitmap.sub(x, y, width, height)
            })
            .for_each(|sub| self.update(&sub));
    }
}

/// Bitmap Display Update
///
/// Bitmap updates are encoded using RDP 6.0 compression, fragmented and sent using
/// Fastpath Server Updates
///
#[derive(Clone)]
pub struct BitmapUpdate {
    pub x: u16,
    pub y: u16,
    pub width: NonZeroU16,
    pub height: NonZeroU16,
    pub format: PixelFormat,
    pub data: Bytes,
    pub stride: NonZeroUsize,
}

impl BitmapUpdate {
    /// Extracts a sub-region of the bitmap update.
    ///
    /// # Parameters
    ///
    /// - `x`: The x-coordinate of the top-left corner of the sub-region.
    /// - `y`: The y-coordinate of the top-left corner of the sub-region.
    /// - `width`: The width of the sub-region.
    /// - `height`: The height of the sub-region.
    ///
    /// # Returns
    ///
    /// An `Option` containing a new `BitmapUpdate` representing the sub-region if the specified
    /// dimensions are within the bounds of the original bitmap update, otherwise `None`.
    ///
    /// # Example
    ///
    /// ```
    /// # use core::num::NonZeroU16;
    /// # use std::num::NonZeroUsize;
    /// # use bytes::Bytes;
    /// # use ironrdp_graphics::image_processing::PixelFormat;
    /// # use ironrdp_server::BitmapUpdate;
    /// let original = BitmapUpdate {
    ///     x: 0,
    ///     y: 0,
    ///     width: NonZeroU16::new(100).unwrap(),
    ///     height: NonZeroU16::new(100).unwrap(),
    ///     format: PixelFormat::ARgb32,
    ///     data: Bytes::from(vec![0; 40000]),
    ///     stride: NonZeroUsize::new(400).unwrap(),
    /// };
    ///
    /// let sub_region = original.sub(10, 10, NonZeroU16::new(50).unwrap(), NonZeroU16::new(50).unwrap());
    /// assert!(sub_region.is_some());
    /// ```
    #[must_use]
    pub fn sub(&self, x: u16, y: u16, width: NonZeroU16, height: NonZeroU16) -> Option<Self> {
        if x + width.get() > self.width.get() || y + height.get() > self.height.get() {
            None
        } else {
            let bpp = usize::from(self.format.bytes_per_pixel());
            let start = usize::from(y) * self.stride.get() + usize::from(x) * bpp;
            let end = start + usize::from(height.get() - 1) * self.stride.get() + usize::from(width.get()) * bpp;
            Some(Self {
                x: self.x + x,
                y: self.y + y,
                width,
                height,
                format: self.format,
                data: self.data.slice(start..end),
                stride: self.stride,
            })
        }
    }
}

impl core::fmt::Debug for BitmapUpdate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BitmapUpdate")
            .field("x", &self.x)
            .field("y", &self.y)
            .field("width", &self.width)
            .field("height", &self.height)
            .field("format", &self.format)
            .field("stride", &self.stride)
            .finish()
    }
}

/// Display Updates receiver for an RDP server
///
/// The RDP server will repeatedly call the `next_update` method to receive
/// display updates which will then be encoded and sent to the client
///
/// See [`RdpServerDisplay`] example.
#[async_trait::async_trait]
pub trait RdpServerDisplayUpdates {
    /// # Cancel safety
    ///
    /// This method MUST be cancellation safe because it is used in a
    /// `tokio::select!` statement. If some other branch completes first, it
    /// MUST be guaranteed that no data is lost.
    async fn next_update(&mut self) -> Result<Option<DisplayUpdate>>;
}

/// Display for an RDP server
///
/// # Example
///
/// ```
///# use anyhow::Result;
/// use ironrdp_server::{DesktopSize, DisplayUpdate, RdpServerDisplay, RdpServerDisplayUpdates};
///
/// pub struct DisplayUpdates {
///     receiver: tokio::sync::mpsc::Receiver<DisplayUpdate>,
/// }
///
/// #[async_trait::async_trait]
/// impl RdpServerDisplayUpdates for DisplayUpdates {
///     async fn next_update(&mut self) -> anyhow::Result<Option<DisplayUpdate>> {
///         Ok(self.receiver.recv().await)
///     }
/// }
///
/// pub struct DisplayHandler {
///     width: u16,
///     height: u16,
/// }
///
/// #[async_trait::async_trait]
/// impl RdpServerDisplay for DisplayHandler {
///     async fn size(&mut self) -> DesktopSize {
///         DesktopSize { width: self.width, height: self.height }
///     }
///
///     async fn updates(&mut self) -> Result<Box<dyn RdpServerDisplayUpdates>> {
///         Ok(Box::new(DisplayUpdates { receiver: todo!() }))
///     }
/// }
/// ```
#[async_trait::async_trait]
pub trait RdpServerDisplay: Send {
    /// This method should return the current size of the display.
    async fn size(&mut self) -> DesktopSize;

    /// Request an initial size for the display.
    ///
    /// This method should return the negotiated display size.
    async fn request_initial_size(&mut self, client_size: DesktopSize) -> DesktopSize {
        debug!(?client_size, "Requesting initial size");
        self.size().await
    }

    /// Return a display updates receiver
    async fn updates(&mut self) -> Result<Box<dyn RdpServerDisplayUpdates>>;

    /// Request a new size for the display
    fn request_layout(&mut self, layout: DisplayControlMonitorLayout) {
        debug!(?layout, "Requesting layout")
    }
}

#[cfg(test)]
mod tests {
    use core::num::{NonZeroU16, NonZeroUsize};

    use ironrdp_graphics::diff::Rect;
    use ironrdp_graphics::image_processing::PixelFormat;

    use super::{BitmapUpdate, Framebuffer};

    #[test]
    fn framebuffer_update() {
        let width = NonZeroU16::new(800).unwrap();
        let height = NonZeroU16::new(600).unwrap();
        let fmt = PixelFormat::ABgr32;
        let bpp = usize::from(fmt.bytes_per_pixel());
        let mut fb = Framebuffer::new(width, height, fmt);

        let width = 15;
        let stride = NonZeroUsize::new(width * bpp).unwrap();
        let height = 20;
        let data = vec![1u8; height * stride.get()];
        let update = BitmapUpdate {
            x: 1,
            y: 2,
            width: NonZeroU16::new(15).unwrap(),
            height: NonZeroU16::new(20).unwrap(),
            format: fmt,
            data: data.into(),
            stride,
        };
        let diffs = vec![Rect::new(2, 3, 4, 5)];
        fb.update_diffs(&update, &diffs);
        let data = fb.data;
        for y in 5..10 {
            for x in 3..7 {
                for b in 0..bpp {
                    assert_eq!(data[y * fb.stride + x * bpp + b], 1);
                }
            }
        }
    }
}

use crate::{PixelFormat, Rect, VncError, VncEvent};
use std::future::Future;
use tokio::io::{AsyncRead, AsyncReadExt};

use super::uninit_vec;

pub struct Decoder {}

impl Decoder {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn decode<S, F, Fut>(
        &mut self,
        format: &PixelFormat,
        rect: &Rect,
        input: &mut S,
        output_func: &F,
    ) -> Result<(), VncError>
    where
        S: AsyncRead + Unpin,
        F: Fn(VncEvent) -> Fut,
        Fut: Future<Output = Result<(), VncError>>,
    {
        // +----------------------------+--------------+-------------+
        // | No. of bytes               | Type [Value] | Description |
        // +----------------------------+--------------+-------------+
        // | width*height*bytesPerPixel | PIXEL array  | pixels      |
        // +----------------------------+--------------+-------------+
        let bpp = format.bits_per_pixel / 8;
        let buffer_size = bpp as usize * rect.height as usize * rect.width as usize;
        let mut pixels = uninit_vec(buffer_size);
        input.read_exact(&mut pixels).await?;
        output_func(VncEvent::RawImage(*rect, pixels)).await?;
        Ok(())
    }
}

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
        let _hotx = rect.x;
        let _hoty = rect.y;
        let w = rect.width;
        let h = rect.height;

        let pixels_length = w as usize * h as usize * format.bits_per_pixel as usize / 8;
        let mask_length = (w as usize).div_ceil(8) * h as usize;

        let _bytes = pixels_length + mask_length;

        let mut pixels = uninit_vec(pixels_length);
        input.read_exact(&mut pixels).await?;
        let mut mask = uninit_vec(mask_length);
        input.read_exact(&mut mask).await?;
        let mut image = uninit_vec(pixels_length);
        let mut pix_idx = 0;

        let pixel_mask = ((format.red_max as u32) << format.red_shift)
            | ((format.green_max as u32) << format.green_shift)
            | ((format.blue_max as u32) << format.blue_shift);

        let mut alpha_idx = match pixel_mask {
            0xff_ff_ff_00 => 3,
            0xff_ff_00_ff => 2,
            0xff_00_ff_ff => 1,
            0x00_ff_ff_ff => 0,
            _ => unreachable!(),
        };
        if format.big_endian_flag == 0 {
            alpha_idx = 3 - alpha_idx;
        }
        for y in 0..h as usize {
            for x in 0..w as usize {
                let mask_idx = y * (w as usize).div_ceil(8) + (x / 8);
                let alpha = if (mask[mask_idx] << (x % 8)) & 0x80 > 0 {
                    255
                } else {
                    0
                };
                image[pix_idx] = pixels[pix_idx];
                image[pix_idx + 1] = pixels[pix_idx + 1];
                image[pix_idx + 2] = pixels[pix_idx + 2];
                image[pix_idx + 3] = pixels[pix_idx + 3];

                // use alpha from the bitmask to cover it.
                image[pix_idx + alpha_idx] = alpha;
                pix_idx += 4;
            }
        }

        output_func(VncEvent::SetCursor(*rect, image)).await?;

        Ok(())
    }
}

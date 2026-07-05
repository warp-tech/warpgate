use crate::{PixelFormat, Rect, VncError, VncEvent};
use std::future::Future;
use std::io::Read;
use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::error;

use super::{uninit_vec, zlib::ZlibReader};

const MAX_PALETTE: usize = 256;

#[derive(Default)]
pub struct Decoder {
    zlibs: [Option<flate2::Decompress>; 4],
    ctrl: u8,
    filter: u8,
    palette: Vec<u8>,
    alpha_shift: u32,
}

impl Decoder {
    pub fn new() -> Self {
        let mut new = Self {
            palette: Vec::with_capacity(MAX_PALETTE * 4),
            ..Default::default()
        };
        for i in 0..4 {
            let decompressor = flate2::Decompress::new(true);
            new.zlibs[i] = Some(decompressor);
        }
        new
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
        let pixel_mask = ((format.red_max as u32) << format.red_shift)
            | ((format.green_max as u32) << format.green_shift)
            | ((format.blue_max as u32) << format.blue_shift);

        self.alpha_shift = match pixel_mask {
            0xff_ff_ff_00 => 0,
            0xff_ff_00_ff => 8,
            0xff_00_ff_ff => 16,
            0x00_ff_ff_ff => 24,
            _ => unreachable!(),
        };

        let ctrl = input.read_u8().await?;
        for i in 0..4 {
            if (ctrl >> i) & 1 == 1 {
                self.zlibs[i].as_mut().unwrap().reset(true);
            }
        }

        // Figure out filter
        self.ctrl = ctrl >> 4;

        match self.ctrl {
            8 => {
                // fill Rect
                self.fill_rect(format, rect, input, output_func).await
            }
            9 => {
                // jpeg Rect
                self.jpeg_rect(format, rect, input, output_func).await
            }
            10 => {
                // png Rect
                error!("PNG received in standard Tight rect");
                Err(VncError::InvalidImageData)
            }
            x if x & 0x8 == 0 => {
                // basic Rect
                self.basic_rect(format, rect, input, output_func).await
            }
            _ => {
                error!("Illegal tight compression received ({})", self.ctrl);
                Err(VncError::InvalidImageData)
            }
        }
    }

    async fn read_data<S>(&mut self, input: &mut S) -> Result<Vec<u8>, VncError>
    where
        S: AsyncRead + Unpin,
    {
        let len = {
            let mut len;
            let mut byte = input.read_u8().await? as usize;
            len = byte & 0x7f;
            if byte & 0x80 == 0x80 {
                byte = input.read_u8().await? as usize;
                len |= (byte & 0x7f) << 7;

                if byte & 0x80 == 0x80 {
                    byte = input.read_u8().await? as usize;
                    len |= byte << 14;
                }
            }
            len
        };
        let mut data = uninit_vec(len);
        input.read_exact(&mut data).await?;
        Ok(data)
    }

    async fn fill_rect<S, F, Fut>(
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
        let mut color = [0; 3];
        input.read_exact(&mut color).await?;
        let bpp = format.bits_per_pixel as usize / 8;
        let mut image = Vec::with_capacity(rect.width as usize * rect.height as usize * bpp);

        let true_color = self.to_true_color(format, &color);

        for _ in 0..rect.width {
            for _ in 0..rect.height {
                image.extend_from_slice(&true_color);
            }
        }
        output_func(VncEvent::RawImage(*rect, image)).await?;
        Ok(())
    }

    async fn jpeg_rect<S, F, Fut>(
        &mut self,
        _format: &PixelFormat,
        rect: &Rect,
        input: &mut S,
        output_func: &F,
    ) -> Result<(), VncError>
    where
        S: AsyncRead + Unpin,
        F: Fn(VncEvent) -> Fut,
        Fut: Future<Output = Result<(), VncError>>,
    {
        let data = self.read_data(input).await?;
        output_func(VncEvent::JpegImage(*rect, data)).await?;
        Ok(())
    }

    async fn basic_rect<S, F, Fut>(
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
        self.filter = {
            if self.ctrl & 0x4 == 4 {
                input.read_u8().await?
            } else {
                0
            }
        };

        let stream_id = self.ctrl & 0x3;
        match self.filter {
            0 => {
                // copy filter
                self.copy_filter(stream_id, format, rect, input, output_func)
                    .await
            }
            1 => {
                // palette
                self.palette_filter(stream_id, format, rect, input, output_func)
                    .await
            }
            2 => {
                // gradient
                self.gradient_filter(stream_id, format, rect, input, output_func)
                    .await
            }
            _ => {
                error!("Illegal tight filter received (filter: {})", self.filter);
                Err(VncError::InvalidImageData)
            }
        }
    }

    async fn copy_filter<S, F, Fut>(
        &mut self,
        stream: u8,
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
        let uncompressed_size = rect.width as usize * rect.height as usize * 3;
        if uncompressed_size == 0 {
            return Ok(());
        };

        let data = self
            .read_tight_data(stream, input, uncompressed_size)
            .await?;
        let mut image = Vec::with_capacity(uncompressed_size / 3 * 4);
        let mut j = 0;
        while j < uncompressed_size {
            image.extend_from_slice(&self.to_true_color(format, &data[j..j + 3]));
            j += 3;
        }

        output_func(VncEvent::RawImage(*rect, image)).await?;

        Ok(())
    }

    async fn palette_filter<S, F, Fut>(
        &mut self,
        stream: u8,
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
        let num_colors = input.read_u8().await? as usize + 1;
        let palette_size = num_colors * 3;

        self.palette = uninit_vec(palette_size);
        input.read_exact(&mut self.palette).await?;

        let bpp = if num_colors <= 2 { 1 } else { 8 };
        let row_size = (rect.width as usize * bpp).div_ceil(8);
        let uncompressed_size = rect.height as usize * row_size;

        if uncompressed_size == 0 {
            return Ok(());
        }

        let data = self
            .read_tight_data(stream, input, uncompressed_size)
            .await?;

        if num_colors == 2 {
            self.mono_rect(data, rect, format, output_func).await?
        } else {
            self.palette_rect(data, rect, format, output_func).await?
        }

        Ok(())
    }

    async fn mono_rect<F, Fut>(
        &mut self,
        data: Vec<u8>,
        rect: &Rect,
        format: &PixelFormat,
        output_func: &F,
    ) -> Result<(), VncError>
    where
        F: Fn(VncEvent) -> Fut,
        Fut: Future<Output = Result<(), VncError>>,
    {
        // Convert indexed (palette based) image data to RGB
        let total = rect.width as usize * rect.height as usize;
        let mut image = uninit_vec(total * 4);
        let mut offset = 8_usize;
        let mut index = -1_isize;
        let mut dp = 0;
        for i in 0..total {
            if offset == 0 || i % rect.width as usize == 0 {
                offset = 8;
                index += 1;
            }
            offset -= 1;
            let sp = ((data[index as usize] >> offset) & 0x01) as usize * 3;
            let true_color = self.to_true_color(format, &self.palette[sp..sp + 3]);
            unsafe {
                std::ptr::copy_nonoverlapping(true_color.as_ptr(), image.as_mut_ptr().add(dp), 4)
            }
            dp += 4;
        }
        output_func(VncEvent::RawImage(*rect, image)).await?;
        Ok(())
    }

    async fn palette_rect<F, Fut>(
        &mut self,
        data: Vec<u8>,
        rect: &Rect,
        format: &PixelFormat,
        output_func: &F,
    ) -> Result<(), VncError>
    where
        F: Fn(VncEvent) -> Fut,
        Fut: Future<Output = Result<(), VncError>>,
    {
        // Convert indexed (palette based) image data to RGB
        let total = rect.width as usize * rect.height as usize;
        let mut image = uninit_vec(total * 4);
        let mut i = 0;
        let mut dp = 0;
        while i < total {
            let sp = data[i] as usize * 3;
            let true_color = self.to_true_color(format, &self.palette[sp..sp + 3]);
            unsafe {
                std::ptr::copy_nonoverlapping(true_color.as_ptr(), image.as_mut_ptr().add(dp), 4)
            }
            dp += 4;
            i += 1;
        }
        output_func(VncEvent::RawImage(*rect, image)).await?;
        Ok(())
    }

    async fn gradient_filter<S, F, Fut>(
        &mut self,
        stream: u8,
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
        let uncompressed_size = rect.width as usize * rect.height as usize * 3;
        if uncompressed_size == 0 {
            return Ok(());
        };
        let data = self
            .read_tight_data(stream, input, uncompressed_size)
            .await?;
        let mut image = uninit_vec(rect.width as usize * rect.height as usize * 4);

        let row_len = rect.width as usize * 3 + 3;
        let mut row_0 = vec![0_u16; row_len];
        let mut row_1 = vec![0_u16; row_len];
        let max = [format.red_max, format.green_max, format.blue_max];
        let shift = [format.red_shift, format.green_shift, format.blue_shift];
        let mut sp = 0;
        let mut dp = 0;

        for y in 0..rect.height as usize {
            let (this_row, prev_row) = match y & 1 {
                0 => (&mut row_0, &mut row_1),
                1 => (&mut row_1, &mut row_0),
                _ => unreachable!(),
            };
            let mut x = 3;
            while x < row_len {
                let rgb = &data[sp..sp + 3];
                let mut color = 0;
                for index in 0..3 {
                    let d = prev_row[index + x] as i32 + this_row[index + x - 3] as i32
                        - prev_row[index + x - 3] as i32;
                    let converted = if d < 0 {
                        0
                    } else if d > max[index] as i32 {
                        max[index]
                    } else {
                        d as u16
                    };
                    this_row[index + x] = (converted + rgb[index] as u16) & max[index];
                    color |= (this_row[x + index] as u32 & max[index] as u32) << shift[index];
                }
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        color.to_le_bytes().as_ptr(),
                        image.as_mut_ptr().add(dp),
                        4,
                    )
                }
                dp += 4;
                sp += 3;
                x += 3;
            }
        }

        output_func(VncEvent::RawImage(*rect, image)).await?;
        Ok(())
    }

    async fn read_tight_data<S>(
        &mut self,
        stream: u8,
        input: &mut S,
        uncompressed_size: usize,
    ) -> Result<Vec<u8>, VncError>
    where
        S: AsyncRead + Unpin,
    {
        let mut data;
        if uncompressed_size < 12 {
            data = uninit_vec(uncompressed_size);
            input.read_exact(&mut data).await?;
        } else {
            let d = self.read_data(input).await?;
            let mut reader = ZlibReader::new(self.zlibs[stream as usize].take().unwrap(), &d);
            data = uninit_vec(uncompressed_size);
            reader.read_exact(&mut data)?;
            self.zlibs[stream as usize] = Some(reader.into_inner()?);
        };
        Ok(data)
    }

    fn to_true_color(&self, format: &PixelFormat, color: &[u8]) -> [u8; 4] {
        let alpha = 255;
        // always rgb
        (((color[0] as u32 & format.red_max as u32) << format.red_shift)
            | ((color[1] as u32 & format.green_max as u32) << format.green_shift)
            | ((color[2] as u32 & format.blue_max as u32) << format.blue_shift)
            | ((alpha as u32) << self.alpha_shift))
            .to_le_bytes()
    }
}

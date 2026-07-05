use core::convert::Infallible;

use embedded_graphics::pixelcolor::Rgb888;
use embedded_graphics::prelude::*;

/// A minimal RGB888 framebuffer that `embedded-graphics` can draw into.
pub struct Framebuffer {
    width: u32,
    height: u32,
    pixels: Vec<u8>,
}

impl Framebuffer {
    pub fn new(width: u32, height: u32, fill: Rgb888) -> Self {
        let pattern = [fill.r(), fill.g(), fill.b()];
        let mut pixels = vec![0u8; (width * height * 3) as usize];
        for px in pixels.chunks_exact_mut(3) {
            px.copy_from_slice(&pattern);
        }
        Self {
            width,
            height,
            pixels,
        }
    }

    pub fn take_pixels(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pixels)
    }
}

impl OriginDimensions for Framebuffer {
    fn size(&self) -> Size {
        Size::new(self.width, self.height)
    }
}

impl DrawTarget for Framebuffer {
    type Color = Rgb888;
    type Error = Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Self::Color>>,
    {
        for Pixel(point, color) in pixels {
            if point.x < 0 || point.y < 0 {
                continue;
            }
            let (x, y) = (point.x as u32, point.y as u32);
            if x >= self.width || y >= self.height {
                continue;
            }
            let idx = ((y * self.width + x) * 3) as usize;
            if let Some([r, g, b]) = self.pixels.get_mut(idx..idx + 3) {
                *r = color.r();
                *g = color.g();
                *b = color.b();
            }
        }
        Ok(())
    }
}

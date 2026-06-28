//! Renders the "connecting" / auth screen shown to a VNC client
#![allow(clippy::cast_precision_loss, clippy::suboptimal_flops)]

mod bouncy_ball;
mod framebuffer;
mod logo;

use std::convert::Infallible;

use embedded_graphics::image::Image;
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::mono_font::ascii::FONT_10X20;
use embedded_graphics::pixelcolor::Rgb888;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::{CornerRadii, PrimitiveStyle, Rectangle, RoundedRectangle};
use embedded_graphics::text::{Alignment, Text};
use framebuffer::Framebuffer;
use warpgate_common::helpers::otp::OTP_DIGITS;

use crate::char_boxes::draw_char_boxes;
use crate::logo::logo;

pub const SCREEN_W: u16 = 1024;
pub const SCREEN_H: u16 = 768;

const BG: Rgb888 = Rgb888::new(0x14, 0x14, 0x1a);
const FG: Rgb888 = Rgb888::new(0xc1, 0xc9, 0xe4);

pub fn render_connecting(tick: u64) -> Result<Vec<u8>, Infallible> {
    render(tick, "Connecting", None)
}

pub enum AuthPrompt {
    WebApproval {
        url: Option<String>,
        security_key: String,
    },
    Otp {
        entered: String,
    },
}

pub fn render_authentication(tick: u64, prompt: &AuthPrompt) -> Result<Vec<u8>, Infallible> {
    match prompt {
        AuthPrompt::WebApproval { url, security_key } => {
            let mut text = String::new();
            match url {
                Some(url) => {
                    text.push_str(&format!(
                        "Approve this session at:\n{url}\n(has been copied to your clipboard)"
                    ));
                }
                None => text.push_str("Please approve this session in Warpgate first"),
            }
            let boxes = CharBoxes {
                text: &security_key,
                slots: security_key.chars().count(),
            };
            text.push_str("\n\nSecurity key:");
            render(tick, &text, Some(boxes))
        }
        AuthPrompt::Otp { entered } => render(
            tick,
            "One-time password:",
            Some(CharBoxes {
                text: &entered,
                slots: OTP_DIGITS,
            }),
        ),
    }
}

struct CharBoxes<'a> {
    text: &'a str,
    slots: usize,
}

fn render(tick: u64, text: &str, boxes: Option<CharBoxes>) -> Result<Vec<u8>, Infallible> {
    let mut fb = Framebuffer::new(u32::from(SCREEN_W), u32::from(SCREEN_H), BG);

    let cx = i32::from(SCREEN_W) / 2;
    let cy = i32::from(SCREEN_H) / 2 - 24;

    let image = logo();
    let x0 = (i32::from(SCREEN_W) - image.size().width as i32) / 2;
    Image::new(image, Point::new(x0, 60)).draw(&mut fb)?;

    bouncy_ball::bouncy_ball(tick, cx, cy)
        .into_styled(PrimitiveStyle::with_fill(FG))
        .draw(&mut fb)?;

    let style = MonoTextStyle::new(&FONT_10X20, FG);
    let mut y = cy + 88;
    for line in text.split('\n') {
        Text::with_alignment(line, Point::new(cx, y), style, Alignment::Center).draw(&mut fb)?;
        y += 26;
    }

    let style = MonoTextStyle::new(&FONT_10X20, BG);
    if let Some(boxes) = boxes {
        draw_char_boxes(&mut fb, cx, y + 8, boxes.text, boxes.slots, style);
    }

    Ok(fb.take_pixels())
}

mod char_boxes {
    use super::*;

    const OTP_BOX_W: i32 = 30;
    const OTP_BOX_H: i32 = 40;
    const OTP_BOX_GAP: i32 = 8;

    /// Draw a centred row of `slots` rounded boxes, filling each with the matching character of
    /// `text` (left to right); boxes past the end of `text` are left empty.
    pub fn draw_char_boxes(
        fb: &mut Framebuffer,
        cx: i32,
        y: i32,
        text: &str,
        slots: usize,
        style: MonoTextStyle<'_, Rgb888>,
    ) {
        let slots = slots as i32;
        let total_w = slots * OTP_BOX_W + (slots - 1) * OTP_BOX_GAP;
        let mut x = cx - total_w / 2;
        for i in 0..slots {
            let _ = RoundedRectangle::new(
                Rectangle::new(
                    Point::new(x, y),
                    Size::new(OTP_BOX_W as u32, OTP_BOX_H as u32),
                ),
                CornerRadii::new(Size::new_equal(3)),
            )
            .into_styled(PrimitiveStyle::with_fill(FG))
            .draw(fb);
            if let Some(ch) = text.chars().nth(i as usize) {
                let _ = Text::with_alignment(
                    &ch.to_string(),
                    Point::new(x + OTP_BOX_W / 2 - 1, y + OTP_BOX_H / 2 + 6),
                    style,
                    Alignment::Center,
                )
                .draw(fb);
            }
            x += OTP_BOX_W + OTP_BOX_GAP;
        }
    }
}

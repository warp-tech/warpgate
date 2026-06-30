use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

use super::MAX_STRING_LEN;

const ENCODING_RAW: i32 = 0;
const ENCODING_DESKTOP_SIZE: i32 = -223;
const MAX_ENCODINGS: usize = 4096;

/// RFB `PIXEL_FORMAT` + the raw bytes so it can be replayed
#[derive(Clone, Copy, Debug)]
pub struct PixelFormat {
    pub raw: [u8; 16],
    pub bits_per_pixel: u8,
    pub big_endian: bool,
    pub red_max: u16,
    pub green_max: u16,
    pub blue_max: u16,
    pub red_shift: u8,
    pub green_shift: u8,
    pub blue_shift: u8,
}

pub const DEFAULT_PIXEL_FORMAT: PixelFormat = PixelFormat {
    raw: [32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0],
    bits_per_pixel: 32,
    big_endian: false,
    red_max: 255,
    green_max: 255,
    blue_max: 255,
    red_shift: 16,
    green_shift: 8,
    blue_shift: 0,
};

impl PixelFormat {
    const fn parse(raw: [u8; 16]) -> Self {
        let [
            bpp,
            _depth,
            be,
            _tc,
            rmh,
            rml,
            gmh,
            gml,
            bmh,
            bml,
            rs,
            gs,
            bs,
            _,
            _,
            _,
        ] = raw;
        Self {
            raw,
            bits_per_pixel: bpp,
            big_endian: be != 0,
            red_max: u16::from_be_bytes([rmh, rml]),
            green_max: u16::from_be_bytes([gmh, gml]),
            blue_max: u16::from_be_bytes([bmh, bml]),
            red_shift: rs,
            green_shift: gs,
            blue_shift: bs,
        }
    }

    /// RFB requires `bits_per_pixel` of 8/16/32
    pub const fn is_supported(&self) -> bool {
        matches!(self.bits_per_pixel, 8 | 16 | 32)
    }

    /// Pack 8-bit RGB color into this pixel format
    pub fn pack(&self, r: u8, g: u8, b: u8, out: &mut Vec<u8>) {
        // `shift` is viewer-controlled (0..=255); a value >= 32 would overflow the `u32`
        // left-shift (panic in debug, wrong value in release), so drop those channel bits.
        let comp = |v: u8, max: u16, shift: u8| {
            (u32::from(v) * u32::from(max) / 255)
                .checked_shl(u32::from(shift))
                .unwrap_or(0)
        };
        let value = comp(r, self.red_max, self.red_shift)
            | comp(g, self.green_max, self.green_shift)
            | comp(b, self.blue_max, self.blue_shift);
        let n = (self.bits_per_pixel as usize) / 8;
        if self.big_endian {
            for i in (0..n).rev() {
                out.push((value >> (8 * i)) as u8);
            }
        } else {
            for i in 0..n {
                out.push((value >> (8 * i)) as u8);
            }
        }
    }
}

/// Pack an RGB888 image (3 bytes per pixel) into the viewer's pixel format
pub fn pack_rgb(pixel_format: &PixelFormat, rgb: &[u8]) -> Vec<u8> {
    let bytes_per_pixel = usize::from(pixel_format.bits_per_pixel) / 8;
    let mut out = Vec::with_capacity(rgb.len() / 3 * bytes_per_pixel);
    for px in rgb.chunks_exact(3) {
        if let [r, g, b] = *px {
            pixel_format.pack(r, g, b, &mut out);
        }
    }
    out
}

/// Pack a BGRA image (4 bytes per pixel, `[b, g, r, a]` as produced by the backend
/// decoder's `PixelFormat::bgra()`) into the viewer's pixel format. When the viewer
/// kept our advertised [`DEFAULT_PIXEL_FORMAT`] — the common case — the bytes are
/// already in exactly that 32-bit little-endian BGRX layout, so they're copied
/// directly; otherwise each pixel is re-packed into the requested format.
pub fn pack_bgra(pixel_format: &PixelFormat, bgra: &[u8]) -> Vec<u8> {
    if pixel_format.raw == DEFAULT_PIXEL_FORMAT.raw {
        return bgra.to_vec();
    }
    let bytes_per_pixel = usize::from(pixel_format.bits_per_pixel) / 8;
    let mut out = Vec::with_capacity(bgra.len() / 4 * bytes_per_pixel);
    for px in bgra.chunks_exact(4) {
        if let [b, g, r, _a] = *px {
            pixel_format.pack(r, g, b, &mut out);
        }
    }
    out
}

pub enum ClientEvent {
    PixelFormat(PixelFormat),
    Encodings { raw: Vec<u8>, desktop_size: bool },
    WantsFrame,
    Key { down: bool, keysym: u32 },
    Pointer { x: u16, y: u16, buttons: u8 },
    Clipboard(String),
}

pub async fn write_server_init<S>(
    stream: &mut S,
    width: u16,
    height: u16,
    pixel_format: &PixelFormat,
    name: &str,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut msg = Vec::with_capacity(24 + name.len());
    msg.extend_from_slice(&width.to_be_bytes());
    msg.extend_from_slice(&height.to_be_bytes());
    msg.extend_from_slice(&pixel_format.raw);
    msg.extend_from_slice(&(name.len() as u32).to_be_bytes());
    msg.extend_from_slice(name.as_bytes());
    stream.write_all(&msg).await?;
    stream.flush().await?;
    Ok(())
}

fn push_single_rect_fb_update_header(
    msg: &mut Vec<u8>,
    x: u16,
    y: u16,
    w: u16,
    h: u16,
    encoding: i32,
) {
    msg.push(0); // FramebufferUpdate
    msg.push(0); // padding
    msg.extend_from_slice(&1u16.to_be_bytes()); // one rectangle
    msg.extend_from_slice(&x.to_be_bytes());
    msg.extend_from_slice(&y.to_be_bytes());
    msg.extend_from_slice(&w.to_be_bytes());
    msg.extend_from_slice(&h.to_be_bytes());
    msg.extend_from_slice(&encoding.to_be_bytes());
}

/// Send a single-rectangle FramebufferUpdate using Raw encoding. `pixels` must already
/// be encoded in the viewer's pixel format and be `w * h * bytes_per_pixel` long.
pub async fn write_raw_rect<S>(
    stream: &mut S,
    x: u16,
    y: u16,
    w: u16,
    h: u16,
    pixels: &[u8],
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut msg = Vec::with_capacity(16 + pixels.len());
    push_single_rect_fb_update_header(&mut msg, x, y, w, h, ENCODING_RAW);
    msg.extend_from_slice(pixels);
    stream.write_all(&msg).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn write_server_cut_text<S>(stream: &mut S, text: &str) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let bytes = text.as_bytes();
    let mut msg = Vec::with_capacity(8 + bytes.len());
    msg.push(3); // ServerCutText
    msg.extend_from_slice(&[0, 0, 0]); // padding
    msg.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    msg.extend_from_slice(bytes);
    stream.write_all(&msg).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn write_desktop_size<S>(stream: &mut S, width: u16, height: u16) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut msg = Vec::with_capacity(16);
    push_single_rect_fb_update_header(&mut msg, 0, 0, width, height, ENCODING_DESKTOP_SIZE);
    stream.write_all(&msg).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn write_framebuffer_update_request<S>(
    stream: &mut S,
    incremental: bool,
    x: u16,
    y: u16,
    w: u16,
    h: u16,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut msg = Vec::with_capacity(10);
    msg.push(3); // FramebufferUpdateRequest
    msg.push(u8::from(incremental));
    msg.extend_from_slice(&x.to_be_bytes());
    msg.extend_from_slice(&y.to_be_bytes());
    msg.extend_from_slice(&w.to_be_bytes());
    msg.extend_from_slice(&h.to_be_bytes());
    stream.write_all(&msg).await?;
    stream.flush().await?;
    Ok(())
}

/// Protocol parse loop
pub async fn read_client_messages<R>(
    mut reader: R,
    events: tokio::sync::mpsc::UnboundedSender<ClientEvent>,
    mut stop: tokio::sync::oneshot::Receiver<()>,
) -> Result<R>
where
    R: AsyncRead + Unpin,
{
    loop {
        let msg_type = tokio::select! {
            biased;
            _ = &mut stop => break,
            r = reader.read_u8() => match r {
                Ok(t) => t,
                Err(_) => break, // EOF / viewer gone
            },
        };
        match msg_type {
            0 => {
                // SetPixelFormat: 3 padding + 16-byte pixel format.
                let mut padding = [0u8; 3];
                reader.read_exact(&mut padding).await?;
                let mut pf = [0u8; 16];
                reader.read_exact(&mut pf).await?;
                let parsed = PixelFormat::parse(pf);
                debug!(
                    bits_per_pixel = parsed.bits_per_pixel,
                    big_endian = parsed.big_endian,
                    "viewer SetPixelFormat"
                );
                if !parsed.is_supported() {
                    bail!(
                        "viewer requested unsupported bits_per_pixel: {}",
                        parsed.bits_per_pixel
                    );
                }
                let _ = events.send(ClientEvent::PixelFormat(parsed));
            }
            2 => {
                // SetEncodings: 1 padding + 2 count + count * 4-byte encodings.
                let mut head = [0u8; 3];
                reader.read_exact(&mut head).await?;
                let [_, count_hi, count_lo] = head;
                let count = usize::from(u16::from_be_bytes([count_hi, count_lo]));
                if count > MAX_ENCODINGS {
                    bail!("client sent too many encodings: {count}");
                }
                let mut body = vec![0u8; count * 4];
                reader.read_exact(&mut body).await?;
                let mut desktop_size = false;
                for chunk in body.chunks_exact(4) {
                    if let Ok(arr) = <[u8; 4]>::try_from(chunk)
                        && i32::from_be_bytes(arr) == ENCODING_DESKTOP_SIZE
                    {
                        desktop_size = true;
                    }
                }
                debug!(count, desktop_size, "viewer SetEncodings");
                let mut raw = Vec::with_capacity(3 + body.len());
                raw.push(2);
                raw.extend_from_slice(&head);
                raw.extend_from_slice(&body);
                let _ = events.send(ClientEvent::Encodings { raw, desktop_size });
            }
            3 => {
                // FramebufferUpdateRequest: incremental + x + y + w + h.
                let mut rest = [0u8; 9];
                reader.read_exact(&mut rest).await?;
                let _ = events.send(ClientEvent::WantsFrame);
            }
            4 => {
                // KeyEvent: down-flag(1) + padding(2) + keysym(4).
                let mut rest = [0u8; 7];
                reader.read_exact(&mut rest).await?;
                let [down, _, _, k0, k1, k2, k3] = rest;
                let _ = events.send(ClientEvent::Key {
                    down: down != 0,
                    keysym: u32::from_be_bytes([k0, k1, k2, k3]),
                });
            }
            5 => {
                // PointerEvent: button-mask(1) + x(2) + y(2).
                let mut rest = [0u8; 5];
                reader.read_exact(&mut rest).await?;
                let [buttons, x_hi, x_lo, y_hi, y_lo] = rest;
                let _ = events.send(ClientEvent::Pointer {
                    x: u16::from_be_bytes([x_hi, x_lo]),
                    y: u16::from_be_bytes([y_hi, y_lo]),
                    buttons,
                });
            }
            6 => {
                // ClientCutText: 3 padding + 4 length + text.
                let mut rest = [0u8; 7];
                reader.read_exact(&mut rest).await?;
                let [_, _, _, l0, l1, l2, l3] = rest;
                let len = u32::from_be_bytes([l0, l1, l2, l3]) as usize;
                if len > MAX_STRING_LEN {
                    bail!("client cut text too long: {len}");
                }
                let mut text = vec![0u8; len];
                reader.read_exact(&mut text).await?;
                let _ = events.send(ClientEvent::Clipboard(
                    String::from_utf8_lossy(&text).into_owned(),
                ));
            }
            150 => {
                // EnableContinuousUpdates: enable + x + y + w + h.
                debug!("viewer EnableContinuousUpdates");
                let mut rest = [0u8; 9];
                reader.read_exact(&mut rest).await?;
            }
            248 => {
                // ClientFence: 3 padding + 4 flags + 1 length + payload.
                let mut head = [0u8; 8];
                reader.read_exact(&mut head).await?;
                let [_, _, _, _, _, _, _, len] = head;
                debug!(len, "viewer ClientFence");
                let mut payload = vec![0u8; usize::from(len)];
                reader.read_exact(&mut payload).await?;
            }
            250 => {
                // xvp: padding + version + code.
                debug!("viewer xvp");
                let mut rest = [0u8; 3];
                reader.read_exact(&mut rest).await?;
            }
            251 => {
                // SetDesktopSize: padding + w + h + number-of-screens + padding,
                // then number-of-screens * 16-byte screen descriptors.
                let mut head = [0u8; 7];
                reader.read_exact(&mut head).await?;
                let [_, _, _, _, _, screens, _] = head;
                debug!(screens, "viewer SetDesktopSize");
                let mut bodies = vec![0u8; usize::from(screens) * 16];
                reader.read_exact(&mut bodies).await?;
            }
            other => bail!("unexpected client message type {other}"),
        }
    }
    Ok(reader)
}

pub async fn forward_format_setup<S>(
    backend: &mut S,
    pixel_format: &PixelFormat,
    encodings: Option<&[u8]>,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut set_pixel_format = Vec::with_capacity(20);
    set_pixel_format.push(0); // SetPixelFormat
    set_pixel_format.extend_from_slice(&[0, 0, 0]); // padding
    set_pixel_format.extend_from_slice(&pixel_format.raw);
    backend.write_all(&set_pixel_format).await?;

    if let Some(raw) = encodings {
        backend.write_all(raw).await?;
    }
    backend.flush().await?;
    Ok(())
}

/// Parse the framebuffer width/height from a backend ServerInit message.
pub fn parse_server_init_size(server_init: &[u8]) -> Result<(u16, u16)> {
    let width = server_init
        .get(0..2)
        .and_then(|s| <[u8; 2]>::try_from(s).ok())
        .map(u16::from_be_bytes)
        .context("ServerInit missing width")?;
    let height = server_init
        .get(2..4)
        .and_then(|s| <[u8; 2]>::try_from(s).ok())
        .map(u16::from_be_bytes)
        .context("ServerInit missing height")?;
    Ok((width, height))
}

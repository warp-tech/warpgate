//! Stdio IPC message types shared between Warpgate (`warpgate-protocol-rdp`) and its
//! out-of-workspace helper (`warpgate-rdp-helper`). Both sides of each channel used to
//! declare mirror-image copies of these types; they live here once instead.
//!
//! ## Framing
//!
//! Each channel is a stream of length-delimited **frames** (a big-endian `u32` length
//! prefix + body, matching `tokio_util::codec::LengthDelimitedCodec`'s default, which the
//! async sides use; the blocking client helper writes the same prefix by hand). This
//! module owns only the **body** format:
//!
//! ```text
//! [kind: u8][ payload ]
//!   kind 0 (JSON):  payload = serde_json of the message   — configs + control messages
//!   kind 1 (IMAGE): payload = [x,y,w,h: u16 LE][raw BGRA] — the framebuffer variant
//! ```
//!
//! Framebuffer pixels travel as **raw bytes**, never base64-in-JSON — that base64 + JSON
//! of ~MB payloads per frame was pinning a core and lagging the screen.
//!
//! Kept dependency-light (serde + serde_json) so it slots into the helper's isolated
//! lockfile (which pins IronRDP's RustCrypto pre-releases).

use serde::Serialize;
use serde::de::DeserializeOwned;

pub const KIND_JSON: u8 = 0;
pub const KIND_IMAGE: u8 = 1;

/// Max length-delimited frame size to accept. A full-screen 4K BGRA frame is ~33 MB, so
/// the codec's 8 MB default is too small; set this via
/// `LengthDelimitedCodec::builder().max_frame_length(MAX_FRAME_LEN)` on every reader.
pub const MAX_FRAME_LEN: usize = 64 * 1024 * 1024;

/// A decoded image frame borrowing the wire buffer (no copy until the caller wants one).
pub struct ImageFrame<'a> {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
    pub pixels: &'a [u8],
}

/// Encode a control message as a JSON frame body into `out` (cleared first, so `out` can
/// be a reused scratch buffer).
pub fn encode_json_into<T: Serialize>(msg: &T, out: &mut Vec<u8>) {
    out.clear();
    out.push(KIND_JSON);
    // Infallible for these types; on the impossible error we emit an empty JSON body,
    // which the peer simply ignores.
    let _ = serde_json::to_writer(&mut *out, msg);
}

/// Encode a framebuffer rectangle as a binary IMAGE frame body into `out` (cleared first).
pub fn encode_image_into(x: u16, y: u16, width: u16, height: u16, pixels: &[u8], out: &mut Vec<u8>) {
    out.clear();
    out.reserve(9 + pixels.len());
    out.push(KIND_IMAGE);
    out.extend_from_slice(&x.to_le_bytes());
    out.extend_from_slice(&y.to_le_bytes());
    out.extend_from_slice(&width.to_le_bytes());
    out.extend_from_slice(&height.to_le_bytes());
    out.extend_from_slice(pixels);
}

/// The kind byte of a frame body (`KIND_JSON` for an empty/short frame).
pub fn frame_kind(frame: &[u8]) -> u8 {
    frame.first().copied().unwrap_or(KIND_JSON)
}

/// Parse a JSON control frame body.
pub fn decode_json<T: DeserializeOwned>(frame: &[u8]) -> Option<T> {
    serde_json::from_slice(frame.get(1..)?).ok()
}

/// Parse a binary IMAGE frame body, borrowing its pixels.
pub fn decode_image(frame: &[u8]) -> Option<ImageFrame<'_>> {
    let header = frame.get(0..9)?;
    if *header.first()? != KIND_IMAGE {
        return None;
    }
    let u16_at = |i: usize| -> Option<u16> {
        Some(u16::from_le_bytes(header.get(i..i + 2)?.try_into().ok()?))
    };
    Some(ImageFrame {
        x: u16_at(1)?,
        y: u16_at(3)?,
        width: u16_at(5)?,
        height: u16_at(7)?,
        pixels: frame.get(9..)?,
    })
}

/// Target-facing client channel (`warpgate-rdp-helper connect`): Warpgate drives an RDP
/// client toward the configured target through the helper.
pub mod client {
    use serde::{Deserialize, Serialize};

    /// First frame on stdin: how to reach the target.
    #[derive(Serialize, Deserialize)]
    pub struct ConnectConfig {
        pub host: String,
        pub port: u16,
        pub username: String,
        pub password: String,
        #[serde(default)]
        pub domain: Option<String>,
        #[serde(default = "super::default_width")]
        pub width: u16,
        #[serde(default = "super::default_height")]
        pub height: u16,
        /// Verify the RDP server's TLS certificate against the system root store.
        #[serde(default)]
        pub verify_tls: bool,
    }

    /// Warpgate → helper: viewer input to forward to the target.
    #[derive(Serialize, Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    pub enum Input {
        Pointer { x: u16, y: u16, buttons: u8 },
        Key { keysym: u32, down: bool },
        Scancode { code: u8, extended: bool, down: bool },
        Wheel { vertical: bool, delta: i16 },
    }

    impl Input {
        pub fn encode_into(&self, out: &mut Vec<u8>) {
            super::encode_json_into(self, out);
        }
        pub fn decode(frame: &[u8]) -> Option<Self> {
            super::decode_json(frame)
        }
    }

    /// helper → Warpgate: target framebuffer (raw BGRA) and lifecycle events.
    #[derive(Serialize, Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    pub enum Event {
        Connected {
            width: u16,
            height: u16,
        },
        /// Raw BGRA rect. Sent as a binary IMAGE frame — `data` is never JSON-encoded.
        RawImage {
            x: u16,
            y: u16,
            width: u16,
            height: u16,
            #[serde(skip)]
            data: bytes::Bytes,
        },
        Error {
            message: String,
        },
        Disconnected,
    }

    impl Event {
        pub fn encode_into(&self, out: &mut Vec<u8>) {
            match self {
                Event::RawImage {
                    x,
                    y,
                    width,
                    height,
                    data,
                } => super::encode_image_into(*x, *y, *width, *height, data, out),
                other => super::encode_json_into(other, out),
            }
        }
        /// Takes the owned frame so the image payload is a zero-copy slice of it, not a copy.
        pub fn decode(frame: bytes::Bytes) -> Option<Self> {
            if super::frame_kind(&frame) == super::KIND_IMAGE {
                let img = super::decode_image(&frame)?;
                let (x, y, width, height) = (img.x, img.y, img.width, img.height);
                Some(Event::RawImage {
                    x,
                    y,
                    width,
                    height,
                    data: frame.slice(9..),
                })
            } else {
                super::decode_json(&frame)
            }
        }
    }
}

/// Viewer-facing server channel (`warpgate-rdp-helper serve`): the helper terminates the
/// RDP protocol for a native viewer (mstsc/FreeRDP); Warpgate brokers auth, framebuffer
/// and input over this channel.
pub mod server {
    use serde::{Deserialize, Serialize};

    /// First frame on stdin: TLS material + initial size. The RDP byte stream is *not*
    /// here — Warpgate hands the helper its end of a socketpair as an inherited fd.
    #[derive(Serialize, Deserialize)]
    pub struct ServeConfig {
        pub cert_pem: String,
        pub key_pem: String,
        #[serde(default = "super::default_width")]
        pub width: u16,
        #[serde(default = "super::default_height")]
        pub height: u16,
    }

    /// Warpgate → serve helper: auth verdicts and framebuffer updates (raw BGRA).
    #[derive(Serialize, Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    pub enum Input {
        AuthResponse {
            accept: bool,
        },
        /// Raw BGRA rect. Sent as a binary IMAGE frame — `data` is never JSON-encoded.
        Frame {
            x: u16,
            y: u16,
            width: u16,
            height: u16,
            #[serde(skip)]
            data: bytes::Bytes,
        },
        Resize {
            width: u16,
            height: u16,
        },
        Shutdown,
    }

    impl Input {
        pub fn encode_into(&self, out: &mut Vec<u8>) {
            match self {
                Input::Frame {
                    x,
                    y,
                    width,
                    height,
                    data,
                } => super::encode_image_into(*x, *y, *width, *height, data, out),
                other => super::encode_json_into(other, out),
            }
        }
        /// Takes the owned frame so the image payload is a zero-copy slice of it, not a copy.
        pub fn decode(frame: bytes::Bytes) -> Option<Self> {
            if super::frame_kind(&frame) == super::KIND_IMAGE {
                let img = super::decode_image(&frame)?;
                let (x, y, width, height) = (img.x, img.y, img.width, img.height);
                Some(Input::Frame {
                    x,
                    y,
                    width,
                    height,
                    data: frame.slice(9..),
                })
            } else {
                super::decode_json(&frame)
            }
        }
    }

    /// serve helper → Warpgate: viewer credentials, input, and lifecycle. `domain` is
    /// reported but Warpgate resolves the target's domain from the auth selector.
    #[derive(Serialize, Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    pub enum Event {
        AuthRequest {
            username: String,
            password: String,
            #[serde(default)]
            domain: Option<String>,
        },
        Pointer { x: u16, y: u16, buttons: u8 },
        Scancode { code: u8, extended: bool, down: bool },
        Key { keysym: u32, down: bool },
        Wheel { x: u16, y: u16, vertical: bool, delta: i16 },
        Error { message: String },
        Disconnected,
    }

    impl Event {
        pub fn encode_into(&self, out: &mut Vec<u8>) {
            super::encode_json_into(self, out);
        }
        pub fn decode(frame: &[u8]) -> Option<Self> {
            super::decode_json(frame)
        }
    }
}

fn default_width() -> u16 {
    1280
}
fn default_height() -> u16 {
    800
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_frame_roundtrips_raw() {
        let pixels = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut buf = Vec::new();
        server::Input::Frame {
            x: 10,
            y: 20,
            width: 1,
            height: 2,
            data: bytes::Bytes::from(pixels.clone()),
        }
        .encode_into(&mut buf);
        assert_eq!(frame_kind(&buf), KIND_IMAGE);
        let Some(server::Input::Frame { x, y, width, height, data }) =
            server::Input::decode(bytes::Bytes::from(buf))
        else {
            panic!("wrong variant");
        };
        assert_eq!((x, y, width, height), (10, 20, 1, 2));
        assert_eq!(&data[..], &pixels[..]);
    }

    #[test]
    fn control_frame_roundtrips_json() {
        let mut buf = Vec::new();
        server::Input::Resize { width: 640, height: 480 }.encode_into(&mut buf);
        assert_eq!(frame_kind(&buf), KIND_JSON);
        assert!(matches!(
            server::Input::decode(bytes::Bytes::from(buf)),
            Some(server::Input::Resize { width: 640, height: 480 })
        ));
    }
}

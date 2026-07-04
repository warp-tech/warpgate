//! # VNC-RS
//!
//! ## Description
//! + An async implementation of VNC client side protocol
//!
//! ## Simple example
//!
//! ```no_run
//! use anyhow::{Context, Result};
//! use minifb::{Window, WindowOptions};
//! use tokio::{self, net::TcpStream};
//! use tracing::Level;
//! use vnc::{PixelFormat, Rect, VncConnector, VncEvent, X11Event};
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     // Create tracing subscriber
//!     #[cfg(debug_assertions)]
//!     let subscriber = tracing_subscriber::FmtSubscriber::builder()
//!         .with_max_level(Level::TRACE)
//!         .finish();
//!     #[cfg(not(debug_assertions))]
//!     let subscriber = tracing_subscriber::FmtSubscriber::builder()
//!         .with_max_level(Level::INFO)
//!         .finish();
//!
//!     tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
//!
//!     let tcp = TcpStream::connect("127.0.0.1:5900").await?;
//!     let vnc = VncConnector::new(tcp)
//!         .set_auth_method(async move { Ok("123".to_string()) })
//!         .add_encoding(vnc::VncEncoding::Tight)
//!         .add_encoding(vnc::VncEncoding::Zrle)
//!         .add_encoding(vnc::VncEncoding::CopyRect)
//!         .add_encoding(vnc::VncEncoding::Raw)
//!         .allow_shared(true)
//!         .set_pixel_format(PixelFormat::bgra())
//!         .build()?
//!         .try_start()
//!         .await?
//!         .finish()?;
//!
//!     let mut canvas = CanvasUtils::new()?;
//!
//!     let mut now = std::time::Instant::now();
//!     loop {
//!         match vnc.poll_event().await {
//!             Ok(Some(e)) => {
//!                 let _ = canvas.hande_vnc_event(e);
//!             }
//!             Ok(None) => (),
//!             Err(e) => {
//!                 tracing::error!("{}", e.to_string());
//!                 break;
//!             }
//!         }
//!         if now.elapsed().as_millis() > 16 {
//!             let _ = canvas.flush();
//!             let _ = vnc.input(X11Event::Refresh).await;
//!             now = std::time::Instant::now();
//!         }
//!     }
//!     canvas.close();
//!     let _ = vnc.close().await;
//!     Ok(())
//! }
//!
//! struct CanvasUtils {
//!     window: Window,
//!     video: Vec<u32>,
//!     width: u32,
//!     height: u32,
//! }
//!
//! impl CanvasUtils {
//!     fn new() -> Result<Self> {
//!         Ok(Self {
//!             window: Window::new(
//!                 "mstsc-rs Remote Desktop in Rust",
//!                 800_usize,
//!                 600_usize,
//!                 WindowOptions::default(),
//!             )
//!             .with_context(|| "Unable to create window".to_string())?,
//!             video: vec![],
//!             width: 800,
//!             height: 600,
//!         })
//!     }
//!
//!     fn init(&mut self, width: u32, height: u32) -> Result<()> {
//!         let mut window = Window::new(
//!             "mstsc-rs Remote Desktop in Rust",
//!             width as usize,
//!             height as usize,
//!             WindowOptions::default(),
//!         )
//!         .with_context(|| "Unable to create window")?;
//!         window.limit_update_rate(Some(std::time::Duration::from_micros(16600)));
//!         self.window = window;
//!         self.width = width;
//!         self.height = height;
//!         self.video.resize(height as usize * width as usize, 0);
//!         Ok(())
//!     }
//!
//!     fn draw(&mut self, rect: Rect, data: Vec<u8>) -> Result<()> {
//!         // since we set the PixelFormat as bgra
//!         // the pixels must be sent in [blue, green, red, alpha] in the network order
//!
//!         let mut s_idx = 0;
//!         for y in rect.y..rect.y + rect.height {
//!             let mut d_idx = y as usize * self.width as usize + rect.x as usize;
//!
//!             for _ in rect.x..rect.x + rect.width {
//!                 self.video[d_idx] =
//!                     u32::from_le_bytes(data[s_idx..s_idx + 4].try_into().unwrap()) & 0x00_ff_ff_ff;
//!                 s_idx += 4;
//!                 d_idx += 1;
//!             }
//!         }
//!         Ok(())
//!     }
//!
//!     fn flush(&mut self) -> Result<()> {
//!         self.window
//!             .update_with_buffer(&self.video, self.width as usize, self.height as usize)
//!             .with_context(|| "Unable to update screen buffer")?;
//!         Ok(())
//!     }
//!
//!     fn copy(&mut self, dst: Rect, src: Rect) -> Result<()> {
//!         println!("Copy");
//!         let mut tmp = vec![0; src.width as usize * src.height as usize];
//!         let mut tmp_idx = 0;
//!         for y in 0..src.height as usize {
//!             let mut s_idx = (src.y as usize + y) * self.width as usize + src.x as usize;
//!             for _ in 0..src.width {
//!                 tmp[tmp_idx] = self.video[s_idx];
//!                 tmp_idx += 1;
//!                 s_idx += 1;
//!             }
//!         }
//!         tmp_idx = 0;
//!         for y in 0..src.height as usize {
//!             let mut d_idx = (dst.y as usize + y) * self.width as usize + dst.x as usize;
//!             for _ in 0..src.width {
//!                 self.video[d_idx] = tmp[tmp_idx];
//!                 tmp_idx += 1;
//!                 d_idx += 1;
//!             }
//!         }
//!         Ok(())
//!     }
//!
//!     fn close(&self) {}
//!
//!     fn hande_vnc_event(&mut self, event: VncEvent) -> Result<()> {
//!         match event {
//!             VncEvent::SetResolution(screen) => {
//!                 tracing::info!("Resize {:?}", screen);
//!                 self.init(screen.width as u32, screen.height as u32)?
//!             }
//!             VncEvent::RawImage(rect, data) => {
//!                 self.draw(rect, data)?;
//!             }
//!             VncEvent::Bell => {
//!                 tracing::warn!("Bell event got, but ignore it");
//!             }
//!             VncEvent::SetPixelFormat(_) => unreachable!(),
//!             VncEvent::Copy(dst, src) => {
//!                 self.copy(dst, src)?;
//!             }
//!             VncEvent::JpegImage(_rect, _data) => {
//!                 tracing::warn!("Jpeg event got, but ignore it");
//!             }
//!             VncEvent::SetCursor(rect, data) => {
//!                 if rect.width != 0 {
//!                     self.draw(rect, data)?;
//!                 }
//!             }
//!             VncEvent::Text(string) => {
//!                 tracing::info!("Got clipboard message {}", string);
//!             }
//!             _ => unreachable!(),
//!         }
//!         Ok(())
//!     }
//! }
//!
//! ```
//!
//! ## License
//!
//! Licensed under either of
//!
//!  * Apache License, Version 2.0
//!    ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
//!  * MIT license
//!    ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)
//!
//! at your option.
//!
//! ## Contribution
//!
//! Unless you explicitly state otherwise, any contribution intentionally submitted
//! for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
//! dual licensed as above, without any additional terms or conditions.

pub mod client;
mod codec;
pub mod config;
pub mod error;
pub mod event;

pub use client::VncClient;
pub use client::VncConnector;
// Warpgate fork addition (see PATCHES.md): expose the decode loop for proxy recording.
pub use client::decode_loop;
pub use config::*;
pub use error::*;
pub use event::*;

//! Stdio IPC message types shared between Warpgate (`warpgate-protocol-rdp`) and its
//! out-of-workspace helper (`warpgate-rdp-helper`). Both sides of each line-delimited-JSON
//! channel used to declare mirror-image copies of these types; they live here once instead.
//!
//! Kept dependency-light (serde only) so it can be a path dependency of the helper, which
//! has its own lockfile to isolate IronRDP's RustCrypto pre-release pins.

/// Target-facing client channel (`warpgate-rdp-helper connect`): Warpgate drives an RDP
/// client toward the configured target through the helper.
pub mod client {
    use serde::{Deserialize, Serialize};

    /// First stdin line: how to reach the target.
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

    /// helper → Warpgate: target framebuffer (base64 BGRA) and lifecycle events.
    #[derive(Serialize, Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    pub enum Event {
        Connected { width: u16, height: u16 },
        RawImage { x: u16, y: u16, width: u16, height: u16, data: String },
        Error { message: String },
        Disconnected,
    }
}

/// Viewer-facing server channel (`warpgate-rdp-helper serve`): the helper terminates the
/// RDP protocol for a native viewer (mstsc/FreeRDP); Warpgate brokers auth, framebuffer
/// and input over this channel.
pub mod server {
    use serde::{Deserialize, Serialize};

    /// First stdin line: TLS material + initial size. The RDP byte stream is *not* here —
    /// Warpgate hands the helper its end of a socketpair as an inherited fd (passed as a
    /// CLI argument), so there's no loopback port to name or race.
    #[derive(Serialize, Deserialize)]
    pub struct ServeConfig {
        pub cert_pem: String,
        pub key_pem: String,
        #[serde(default = "super::default_width")]
        pub width: u16,
        #[serde(default = "super::default_height")]
        pub height: u16,
    }

    /// Warpgate → serve helper: auth verdicts and framebuffer updates (base64 BGRA) for
    /// the viewer.
    #[derive(Serialize, Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    pub enum Input {
        AuthResponse { accept: bool },
        Frame { x: u16, y: u16, width: u16, height: u16, data: String },
        Resize { width: u16, height: u16 },
        Shutdown,
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
}

fn default_width() -> u16 {
    1280
}
fn default_height() -> u16 {
    800
}

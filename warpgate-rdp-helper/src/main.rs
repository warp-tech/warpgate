//! Standalone RDP client helper for Warpgate.
//!
//! This binary is intentionally **outside** the Warpgate cargo workspace: IronRDP's
//! CredSSP stack (`sspi`/`picky`) exact-pins RustCrypto pre-release crates that
//! conflict with `russh`'s pins, which cannot coexist in a single lockfile. Building
//! RDP as a separate process with its own lockfile sidesteps the conflict (the same
//! design Apache Guacamole uses with `guacd`).
//!
//! Protocol (line-delimited JSON over stdio):
//! - first line on **stdin**: a [`ConnectConfig`]
//! - subsequent lines on **stdin**: [`InputMessage`]s
//! - lines on **stdout**: [`OutputMessage`]s (framebuffer is BGRA, base64-encoded)

use std::io::{BufRead, Write};
use std::net::TcpStream;
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ironrdp::connector::{self, ConnectionResult, Credentials};
use ironrdp::graphics::image_processing::PixelFormat;
use ironrdp::input::{Database, MouseButton, MousePosition, Operation, Scancode, WheelRotations};
use ironrdp::pdu::gcc::KeyboardType;
use ironrdp::pdu::rdp::capability_sets::MajorPlatformType;
use ironrdp::pdu::rdp::client_info::{PerformanceFlags, TimezoneInfo};
use ironrdp::session::image::DecodedImage;
use ironrdp::session::{ActiveStage, ActiveStageOutput};
use serde::{Deserialize, Serialize};
use sspi::network_client::reqwest_network_client::ReqwestNetworkClient;

#[derive(Deserialize)]
struct ConnectConfig {
    host: String,
    port: u16,
    username: String,
    password: String,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default = "default_width")]
    width: u16,
    #[serde(default = "default_height")]
    height: u16,
}

fn default_width() -> u16 {
    1280
}
fn default_height() -> u16 {
    800
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum InputMessage {
    Pointer { x: u16, y: u16, buttons: u8 },
    Key { keysym: u32, down: bool },
    Wheel { vertical: bool, delta: i16 },
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum OutputMessage<'a> {
    Connected {
        width: u16,
        height: u16,
    },
    RawImage {
        x: u16,
        y: u16,
        width: u16,
        height: u16,
        data: &'a str,
    },
    Error {
        message: String,
    },
    Disconnected,
}

fn emit(msg: &OutputMessage) {
    if let Ok(line) = serde_json::to_string(msg) {
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        let _ = lock.write_all(line.as_bytes());
        let _ = lock.write_all(b"\n");
        let _ = lock.flush();
    }
}

fn main() {
    if let Err(error) = run() {
        emit(&OutputMessage::Error {
            message: format!("{error:#}"),
        });
    }
    emit(&OutputMessage::Disconnected);
}

fn run() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    // First stdin line is the connection config.
    let mut first_line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut first_line)
        .context("reading config line")?;
    let config: ConnectConfig =
        serde_json::from_str(first_line.trim()).context("parsing config")?;

    let connector_config = build_config(&config);
    let (connection_result, framed) =
        connect(connector_config, config.host.clone(), config.port).context("RDP connection")?;

    let width = connection_result.desktop_size.width;
    let height = connection_result.desktop_size.height;
    emit(&OutputMessage::Connected { width, height });

    let mut image = DecodedImage::new(PixelFormat::RgbA32, width, height);

    // Read input messages from stdin on a background thread.
    let (input_tx, input_rx) = mpsc::channel::<InputMessage>();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            let Ok(line) = line else { break };
            if let Ok(msg) = serde_json::from_str::<InputMessage>(line.trim()) {
                if input_tx.send(msg).is_err() {
                    break;
                }
            }
        }
    });

    active_loop(connection_result, framed, &mut image, input_rx)
}

fn active_loop(
    connection_result: ConnectionResult,
    mut framed: UpgradedFramed,
    image: &mut DecodedImage,
    input_rx: mpsc::Receiver<InputMessage>,
) -> Result<()> {
    let mut active_stage = ActiveStage::new(connection_result);
    let mut input_db = Database::new();

    loop {
        // Drain any pending input and forward it to the server.
        let mut ops: Vec<Operation> = Vec::new();
        while let Ok(msg) = input_rx.try_recv() {
            translate_input(msg, &mut ops);
        }
        if !ops.is_empty() {
            let events = input_db.apply(ops);
            let outputs = active_stage
                .process_fastpath_input(image, &events)
                .context("processing input")?;
            if process_outputs(&mut framed, image, outputs)? {
                return Ok(());
            }
        }

        // Read a server PDU (with a short timeout so input stays responsive).
        let (action, payload) = match framed.read_pdu() {
            Ok(v) => v,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(e) => return Err(anyhow::Error::new(e).context("reading PDU")),
        };

        let outputs = active_stage
            .process(image, action, &payload)
            .context("processing PDU")?;
        if process_outputs(&mut framed, image, outputs)? {
            return Ok(());
        }
    }
}

/// Handle a batch of active-stage outputs. Returns `true` if the session should terminate.
fn process_outputs(
    framed: &mut UpgradedFramed,
    image: &DecodedImage,
    outputs: Vec<ActiveStageOutput>,
) -> Result<bool> {
    for out in outputs {
        match out {
            ActiveStageOutput::ResponseFrame(frame) => {
                framed.write_all(&frame).context("writing response")?;
            }
            ActiveStageOutput::GraphicsUpdate(region) => {
                emit_region(image, &region);
            }
            ActiveStageOutput::Terminate(_) => return Ok(true),
            _ => {}
        }
    }
    Ok(false)
}

/// Emit the BGRA pixels for an updated rectangle.
fn emit_region(image: &DecodedImage, region: &ironrdp::pdu::geometry::InclusiveRectangle) {
    let img_w = image.width() as usize;
    let left = region.left as usize;
    let top = region.top as usize;
    let right = region.right as usize;
    let bottom = region.bottom as usize;
    if right < left || bottom < top {
        return;
    }
    let w = right - left + 1;
    let h = bottom - top + 1;
    let src = image.data();

    let mut out = vec![0u8; w * h * 4];
    for row in 0..h {
        let src_row = (top + row) * img_w + left;
        for col in 0..w {
            let s = (src_row + col) * 4;
            let d = (row * w + col) * 4;
            // source is RGBA, emit BGRA
            out[d] = src.get(s + 2).copied().unwrap_or(0);
            out[d + 1] = src.get(s + 1).copied().unwrap_or(0);
            out[d + 2] = src.get(s).copied().unwrap_or(0);
            out[d + 3] = 255;
        }
    }

    emit(&OutputMessage::RawImage {
        x: left as u16,
        y: top as u16,
        width: w as u16,
        height: h as u16,
        data: &STANDARD.encode(&out),
    });
}

fn translate_input(msg: InputMessage, ops: &mut Vec<Operation>) {
    match msg {
        InputMessage::Pointer { x, y, buttons } => {
            ops.push(Operation::MouseMove(MousePosition { x, y }));
            // Reconcile button state from the bitmask (bit0=left, bit1=middle, bit2=right).
            for (bit, button) in [
                (0u8, MouseButton::Left),
                (1, MouseButton::Middle),
                (2, MouseButton::Right),
            ] {
                if buttons & (1 << bit) != 0 {
                    ops.push(Operation::MouseButtonPressed(button));
                } else {
                    ops.push(Operation::MouseButtonReleased(button));
                }
            }
        }
        InputMessage::Wheel { vertical, delta } => {
            ops.push(Operation::WheelRotations(WheelRotations {
                is_vertical: vertical,
                rotation_units: delta,
            }));
        }
        InputMessage::Key { keysym, down } => {
            if let Some((extended, code)) = keysym_to_scancode(keysym) {
                let scancode = Scancode::from_u8(extended, code);
                ops.push(if down {
                    Operation::KeyPressed(scancode)
                } else {
                    Operation::KeyReleased(scancode)
                });
            } else if let Some(c) = char::from_u32(keysym) {
                // Printable key without a known scancode: use Unicode input.
                ops.push(if down {
                    Operation::UnicodeKeyPressed(c)
                } else {
                    Operation::UnicodeKeyReleased(c)
                });
            }
        }
    }
}

/// Maps an X11 keysym (as produced by the browser client) to a US-layout PC/AT
/// scancode (set 1 "make" code) so modifier combinations work. Returns
/// `(extended, code)`.
fn keysym_to_scancode(keysym: u32) -> Option<(bool, u8)> {
    // X11 function/control keysyms (0xff..)
    let special = match keysym {
        0xff08 => (false, 0x0E), // Backspace
        0xff09 => (false, 0x0F), // Tab
        0xff0d => (false, 0x1C), // Enter
        0xff1b => (false, 0x01), // Escape
        0xffff => (true, 0x53),  // Delete
        0xff50 => (true, 0x47),  // Home
        0xff51 => (true, 0x4B),  // Left
        0xff52 => (true, 0x48),  // Up
        0xff53 => (true, 0x4D),  // Right
        0xff54 => (true, 0x50),  // Down
        0xff55 => (true, 0x49),  // PageUp
        0xff56 => (true, 0x51),  // PageDown
        0xff57 => (true, 0x4F),  // End
        0xff63 => (true, 0x52),  // Insert
        0xffe1 => (false, 0x2A), // Shift
        0xffe3 => (false, 0x1D), // Control
        0xffe9 => (false, 0x38), // Alt
        0xffe5 => (false, 0x3A), // CapsLock
        0xffbe..=0xffc7 => (false, 0x3B + (keysym - 0xffbe) as u8), // F1..F10
        0xffc8 => (false, 0x57), // F11
        0xffc9 => (false, 0x58), // F12
        _ => (false, 0xFF),
    };
    if special.1 != 0xFF {
        return Some(special);
    }

    // Printable ASCII -> base-key scancode (shift is sent separately).
    let ch = char::from_u32(keysym)?.to_ascii_lowercase();
    let code = match ch {
        '1' | '!' => 0x02,
        '2' | '@' => 0x03,
        '3' | '#' => 0x04,
        '4' | '$' => 0x05,
        '5' | '%' => 0x06,
        '6' | '^' => 0x07,
        '7' | '&' => 0x08,
        '8' | '*' => 0x09,
        '9' | '(' => 0x0A,
        '0' | ')' => 0x0B,
        '-' | '_' => 0x0C,
        '=' | '+' => 0x0D,
        'q' => 0x10,
        'w' => 0x11,
        'e' => 0x12,
        'r' => 0x13,
        't' => 0x14,
        'y' => 0x15,
        'u' => 0x16,
        'i' => 0x17,
        'o' => 0x18,
        'p' => 0x19,
        '[' | '{' => 0x1A,
        ']' | '}' => 0x1B,
        'a' => 0x1E,
        's' => 0x1F,
        'd' => 0x20,
        'f' => 0x21,
        'g' => 0x22,
        'h' => 0x23,
        'j' => 0x24,
        'k' => 0x25,
        'l' => 0x26,
        ';' | ':' => 0x27,
        '\'' | '"' => 0x28,
        '`' | '~' => 0x29,
        '\\' | '|' => 0x2B,
        'z' => 0x2C,
        'x' => 0x2D,
        'c' => 0x2E,
        'v' => 0x2F,
        'b' => 0x30,
        'n' => 0x31,
        'm' => 0x32,
        ',' | '<' => 0x33,
        '.' | '>' => 0x34,
        '/' | '?' => 0x35,
        ' ' => 0x39,
        _ => return None,
    };
    Some((false, code))
}

fn build_config(config: &ConnectConfig) -> connector::Config {
    connector::Config {
        credentials: Credentials::UsernamePassword {
            username: config.username.clone(),
            password: config.password.clone(),
        },
        domain: config.domain.clone(),
        enable_tls: true,
        enable_credssp: true,
        keyboard_type: KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_layout: 0,
        keyboard_functional_keys_count: 12,
        ime_file_name: String::new(),
        dig_product_id: String::new(),
        desktop_size: connector::DesktopSize {
            width: config.width,
            height: config.height,
        },
        bitmap: None,
        client_build: 0,
        client_name: "warpgate".to_owned(),
        client_dir: "C:\\Windows\\System32\\mstscax.dll".to_owned(),
        platform: MajorPlatformType::UNIX,
        hardware_id: None,
        request_data: None,
        autologon: false,
        enable_audio_playback: false,
        performance_flags: PerformanceFlags::default(),
        license_cache: None,
        timezone_info: TimezoneInfo::default(),
        enable_server_pointer: false,
        pointer_software_rendering: true,
        desktop_scale_factor: 0,
    }
}

type UpgradedFramed =
    ironrdp_blocking::Framed<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>;

fn connect(
    config: connector::Config,
    server_name: String,
    port: u16,
) -> Result<(ConnectionResult, UpgradedFramed)> {
    let tcp_stream = TcpStream::connect((server_name.as_str(), port)).context("TCP connect")?;
    tcp_stream.set_nodelay(true).ok();
    let client_addr = tcp_stream.local_addr().context("local addr")?;

    let mut framed = ironrdp_blocking::Framed::new(tcp_stream);
    let mut connector = connector::ClientConnector::new(config, client_addr);

    let should_upgrade =
        ironrdp_blocking::connect_begin(&mut framed, &mut connector).context("connect_begin")?;

    let initial_stream = framed.into_inner_no_leftover();
    let (upgraded_stream, server_public_key) =
        tls_upgrade(initial_stream, server_name.clone()).context("TLS upgrade")?;

    let upgraded = ironrdp_blocking::mark_as_upgraded(should_upgrade, &mut connector);
    let mut upgraded_framed = ironrdp_blocking::Framed::new(upgraded_stream);

    let mut network_client = ReqwestNetworkClient;
    let connection_result = ironrdp_blocking::connect_finalize(
        upgraded,
        connector,
        &mut upgraded_framed,
        &mut network_client,
        server_name.into(),
        server_public_key,
        None,
    )
    .context("connect_finalize")?;

    // After the handshake, use a short read timeout so we can interleave input.
    upgraded_framed
        .get_inner()
        .0
        .get_ref()
        .set_read_timeout(Some(Duration::from_millis(20)))
        .ok();

    Ok((connection_result, upgraded_framed))
}

mod danger {
    use rustls::DigitallySignedStruct;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{Error, SignatureScheme};

    #[derive(Debug)]
    pub struct NoCertificateVerification;

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
            ]
        }
    }
}

fn tls_upgrade(
    stream: TcpStream,
    server_name: String,
) -> Result<(
    rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
    Vec<u8>,
)> {
    let mut config = rustls::client::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(danger::NoCertificateVerification))
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();

    let config = std::sync::Arc::new(config);
    let server_name = server_name.try_into().context("invalid server name")?;
    let client = rustls::ClientConnection::new(config, server_name)?;
    let mut tls_stream = rustls::StreamOwned::new(client, stream);
    tls_stream.flush()?;

    let cert = tls_stream
        .conn
        .peer_certificates()
        .and_then(|certs| certs.first())
        .context("missing peer certificate")?;
    let server_public_key = extract_tls_server_public_key(cert)?;

    Ok((tls_stream, server_public_key))
}

fn extract_tls_server_public_key(cert: &[u8]) -> Result<Vec<u8>> {
    use x509_cert::der::Decode as _;
    let cert = x509_cert::Certificate::from_der(cert).context("parsing certificate")?;
    let key = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .context("public key not byte-aligned")?
        .to_owned();
    Ok(key)
}

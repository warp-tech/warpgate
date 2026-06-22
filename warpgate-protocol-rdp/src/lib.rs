//! In-workspace RDP integration for Warpgate.
//!
//! The actual RDP/IronRDP work runs in the standalone `warpgate-rdp-helper` binary
//! (which lives outside the cargo workspace to avoid a RustCrypto pre-release version
//! conflict between IronRDP's CredSSP stack and `russh`). The prebuilt helper is
//! embedded into this crate at build time (see `build.rs`) and extracted for
//! use, so Warpgate ships as a single executable. This crate spawns that helper as a
//! subprocess and bridges its line-delimited JSON stdio to the shared
//! [`DesktopEvent`]/[`DesktopInput`] streams, so the existing web-desktop manager and
//! browser canvas renderer work unchanged.

mod helper;

use std::process::Stdio;

use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc::{
    Receiver, Sender, UnboundedReceiver, UnboundedSender, channel, unbounded_channel,
};
use tracing::{Instrument, debug, error, info_span, warn};
use warpgate_common::{ProtocolName, RdpTargetAuth, TargetRdpOptions};
use warpgate_core::{
    DESKTOP_INPUT_CHANNEL_CAPACITY, DesktopEvent, DesktopInput, DesktopRect, DesktopState,
};

pub static PROTOCOL_NAME: ProtocolName = "RDP";

/// Handles for driving a backend RDP client (running in the helper subprocess).
pub struct RdpClientHandles {
    pub event_rx: Receiver<DesktopEvent>,
    pub input_tx: Sender<DesktopInput>,
    pub abort_tx: UnboundedSender<()>,
}

#[derive(Serialize)]
struct ConnectConfig {
    host: String,
    port: u16,
    username: String,
    password: String,
    domain: Option<String>,
    width: u16,
    height: u16,
    /// Whether the helper must verify the RDP server's TLS certificate.
    verify_tls: bool,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum HelperEvent {
    Connected {
        width: u16,
        height: u16,
    },
    RawImage {
        x: u16,
        y: u16,
        width: u16,
        height: u16,
        data: String,
    },
    Error {
        message: String,
    },
    Disconnected,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum HelperInput {
    Pointer { x: u16, y: u16, buttons: u8 },
    Key { keysym: u32, down: bool },
    Wheel { vertical: bool, delta: i16 },
}

/// Spawn the RDP helper for a target and bridge it to normalised desktop streams.
pub fn connect(options: TargetRdpOptions) -> RdpClientHandles {
    let (event_tx, event_rx) = channel::<DesktopEvent>(1024);
    let (input_tx, input_rx) = channel::<DesktopInput>(DESKTOP_INPUT_CHANNEL_CAPACITY);
    let (abort_tx, abort_rx) = unbounded_channel::<()>();

    let span = info_span!("RDP-client", host = %options.host, port = options.port);
    tokio::spawn(
        async move {
            if let Err(error) = run(options, event_tx.clone(), input_rx, abort_rx).await {
                error!(%error, "RDP helper failed");
                let _ = event_tx.send(DesktopEvent::Error(error.to_string())).await;
            }
            let _ = event_tx
                .send(DesktopEvent::State(DesktopState::Disconnected))
                .await;
        }
        .instrument(span),
    );

    RdpClientHandles {
        event_rx,
        input_tx,
        abort_tx,
    }
}

async fn run(
    options: TargetRdpOptions,
    event_tx: tokio::sync::mpsc::Sender<DesktopEvent>,
    mut input_rx: Receiver<DesktopInput>,
    mut abort_rx: UnboundedReceiver<()>,
) -> anyhow::Result<()> {
    event_tx
        .send(DesktopEvent::State(DesktopState::Connecting))
        .await
        .ok();

    let password = match &options.auth {
        RdpTargetAuth::Password(auth) => auth.password.expose_secret().clone(),
    };

    // Kept in scope until after `spawn` so the Linux memfd stays open across exec.
    let helper = helper::resolve()?;

    let mut child = tokio::process::Command::new(helper.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Kill the helper if this task is cancelled/dropped (tokio doesn't by default).
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("spawning RDP helper ({})", helper.path().display()))?;

    let mut stdin = child.stdin.take().context("helper stdin")?;
    let stdout = child.stdout.take().context("helper stdout")?;

    // Surface helper diagnostics (panics, errors) to the log instead of discarding them.
    if let Some(stderr) = child.stderr.take() {
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                debug!(helper = %line, "RDP helper stderr");
            }
        });
    }

    // Send the connection config as the first line.
    let config = ConnectConfig {
        host: options.host.clone(),
        port: options.port,
        username: options.username.clone(),
        password,
        domain: options.domain.clone(),
        width: 1280,
        height: 800,
        verify_tls: options.verify_tls,
    };
    let mut config_line = serde_json::to_string(&config)?;
    config_line.push('\n');
    stdin.write_all(config_line.as_bytes()).await?;
    stdin.flush().await?;

    // Forward input to the helper.
    let input_task = tokio::spawn(async move {
        while let Some(input) = input_rx.recv().await {
            let msg = match input {
                DesktopInput::Pointer { x, y, buttons } => {
                    Some(HelperInput::Pointer { x, y, buttons })
                }
                DesktopInput::Key { keysym, down } => Some(HelperInput::Key { keysym, down }),
                DesktopInput::Wheel {
                    vertical, delta, ..
                } => Some(HelperInput::Wheel {
                    vertical,
                    // RDP wheel rotation units are ~120 per notch.
                    delta: delta.saturating_mul(120),
                }),
                // Clipboard/refresh not yet wired through the helper.
                DesktopInput::Clipboard(_) | DesktopInput::Refresh => None,
            };
            if let Some(msg) = msg
                && let Ok(mut line) = serde_json::to_string(&msg)
            {
                line.push('\n');
                if stdin.write_all(line.as_bytes()).await.is_err() {
                    break;
                }
                let _ = stdin.flush().await;
            }
        }
    });

    // Read events from the helper.
    let mut reader = BufReader::new(stdout).lines();
    loop {
        tokio::select! {
            biased;
            _ = abort_rx.recv() => {
                debug!("RDP client aborted");
                break;
            }
            line = reader.next_line() => {
                let Some(line) = line.context("reading helper output")? else {
                    break;
                };
                if let Ok(event) = serde_json::from_str::<HelperEvent>(line.trim()) {
                    // Race the (possibly blocking) send against abort so a slow consumer
                    // can't starve abort handling while the helper floods stdout.
                    tokio::select! {
                        biased;
                        _ = abort_rx.recv() => break,
                        result = forward_event(&event_tx, event) => {
                            if result.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    input_task.abort();
    let _ = child.kill().await;
    Ok(())
}

async fn forward_event(
    event_tx: &tokio::sync::mpsc::Sender<DesktopEvent>,
    event: HelperEvent,
) -> Result<(), ()> {
    let mapped = match event {
        HelperEvent::Connected { width, height } => {
            event_tx
                .send(DesktopEvent::State(DesktopState::Connected))
                .await
                .map_err(|_| ())?;
            DesktopEvent::Resize { width, height }
        }
        HelperEvent::RawImage {
            x,
            y,
            width,
            height,
            data,
        } => {
            let Ok(bytes) = STANDARD.decode(data) else {
                warn!("invalid base64 in helper raw_image");
                return Ok(());
            };
            DesktopEvent::RawImage {
                rect: DesktopRect {
                    x,
                    y,
                    width,
                    height,
                },
                data: Bytes::from(bytes),
            }
        }
        HelperEvent::Error { message } => DesktopEvent::Error(message),
        HelperEvent::Disconnected => DesktopEvent::State(DesktopState::Disconnected),
    };
    event_tx.send(mapped).await.map_err(|_| ())
}

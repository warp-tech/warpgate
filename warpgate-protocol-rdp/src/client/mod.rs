//! Target-facing RDP client.
//!
//! Drives IronRDP's connection sequence and active stage against the target host and
//! translates both directions into the shared [`DesktopEvent`]/[`DesktopInput`] vocabulary,
//! so the web-desktop manager and the native RDP server front end both work unchanged.

mod input;
mod tls;

use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use ironrdp::connector::{self, ConnectionResult, Credentials};
use ironrdp::graphics::image_processing::PixelFormat;
use ironrdp::pdu::gcc::KeyboardType;
use ironrdp::pdu::geometry::InclusiveRectangle;
use ironrdp::pdu::rdp::capability_sets::MajorPlatformType;
use ironrdp::pdu::rdp::client_info::{PerformanceFlags, TimezoneInfo};
use ironrdp::session::image::DecodedImage;
use ironrdp::session::{ActiveStageBuilder, ActiveStageOutput};
use ironrdp_server::tokio_rustls::client::TlsStream;
use ironrdp_tokio::reqwest::ReqwestNetworkClient;
use ironrdp_tokio::{FramedWrite as _, TokioFramed};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{Receiver, Sender, UnboundedReceiver};
use tracing::warn;
use warpgate_common::{RdpTargetAuth, TargetRdpOptions};
use warpgate_core::{DesktopEvent, DesktopInput, DesktopRect, DesktopState};

/// Deadline for the TCP connect to the target.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Deadline for the RDP handshake (X.224, TLS, CredSSP — the last of which may reach out
/// to a KDC). Without it a target that accepts the TCP connection but stalls mid-handshake
/// would wedge the session forever with no event to report.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

type Framed = TokioFramed<TlsStream<TcpStream>>;

/// Signals that the session was aborted from the Warpgate side.
struct Aborted;

/// Connect to `options` and pump the session until it ends or is aborted.
pub async fn run(
    options: TargetRdpOptions,
    (width, height): (u16, u16),
    event_tx: Sender<DesktopEvent>,
    input_rx: Receiver<DesktopInput>,
    mut abort_rx: UnboundedReceiver<()>,
) -> Result<()> {
    event_tx
        .send(DesktopEvent::State(DesktopState::Connecting))
        .await
        .ok();

    let RdpTargetAuth::Password(auth) = &options.auth;
    let config = build_config(&options, auth.password.expose_secret(), width, height);

    let (connection_result, framed) = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        connect(
            config,
            options.host.clone(),
            options.port,
            options.verify_tls,
        ),
    )
    .await
    .context("RDP handshake timed out")?
    .context("RDP connection")?;

    let width = connection_result.desktop_size.width;
    let height = connection_result.desktop_size.height;
    event_tx
        .send(DesktopEvent::State(DesktopState::Connected))
        .await
        .ok();
    event_tx
        .send(DesktopEvent::Resize { width, height })
        .await
        .ok();

    let mut image = DecodedImage::new(PixelFormat::RgbA32, width, height);
    // `active_loop` reports an abort or a closed channel as a clean end, so anything it
    // returns as an error is a genuine session failure.
    active_loop(
        connection_result,
        framed,
        &mut image,
        input_rx,
        &event_tx,
        &mut abort_rx,
    )
    .await
}

async fn active_loop(
    connection_result: ConnectionResult,
    mut framed: Framed,
    image: &mut DecodedImage,
    mut input_rx: Receiver<DesktopInput>,
    event_tx: &Sender<DesktopEvent>,
    abort_rx: &mut UnboundedReceiver<()>,
) -> Result<()> {
    let mut active_stage = ActiveStageBuilder {
        static_channels: connection_result.static_channels,
        user_channel_id: connection_result.user_channel_id,
        io_channel_id: connection_result.io_channel_id,
        message_channel_id: connection_result.message_channel_id,
        share_id: connection_result.share_id,
        compression_type: connection_result.compression_type,
        enable_server_pointer: connection_result.enable_server_pointer,
        pointer_software_rendering: connection_result.pointer_software_rendering,
    }
    .build();
    let mut input_db = ironrdp::input::Database::new();

    loop {
        let outputs = tokio::select! {
            biased;
            _ = abort_rx.recv() => return Ok(()),
            input = input_rx.recv() => {
                let Some(first) = input else {
                    return Ok(());
                };
                // Coalesce whatever else is already queued so a burst of pointer moves
                // becomes one fastpath batch rather than one round trip each.
                let mut ops = Vec::new();
                input::translate(first, &mut ops);
                while let Ok(next) = input_rx.try_recv() {
                    input::translate(next, &mut ops);
                }
                if ops.is_empty() {
                    continue;
                }
                let events = input_db.apply(ops);
                active_stage
                    .process_fastpath_input(image, &events)
                    .context("processing input")?
            }
            pdu = framed.read_pdu() => {
                let (action, payload) = pdu.context("reading PDU")?;
                active_stage
                    .process(image, action, &payload)
                    .context("processing PDU")?
            }
        };

        match process_outputs(&mut framed, image, outputs, event_tx, abort_rx).await {
            Ok(true) | Err(Aborted) => return Ok(()),
            Ok(false) => {}
        }
    }
}

/// Handle a batch of active-stage outputs. Returns `true` if the session should terminate.
///
/// Protocol responses (crucially, the RDP *frame acknowledgements* that gate the server's
/// flow control) are written and flushed **first**, before the framebuffer tiles are
/// emitted. Emitting a tile can block on channel backpressure when anything downstream is
/// momentarily slow; if the ack sat behind that, the server would stop sending and the
/// frame rate would collapse to a few fps while everything sits idle.
async fn process_outputs(
    framed: &mut Framed,
    image: &DecodedImage,
    outputs: Vec<ActiveStageOutput>,
    event_tx: &Sender<DesktopEvent>,
    abort_rx: &mut UnboundedReceiver<()>,
) -> Result<bool, Aborted> {
    let mut terminate = false;
    for out in &outputs {
        match out {
            ActiveStageOutput::ResponseFrame(frame) => {
                if framed.write_all(frame).await.is_err() {
                    return Err(Aborted);
                }
            }
            ActiveStageOutput::Terminate(_) => terminate = true,
            _ => {}
        }
    }

    for out in outputs {
        if let ActiveStageOutput::GraphicsUpdate(region) = out {
            if let Some(event) = encode_region(image, &region) {
                send_event(event_tx, abort_rx, event).await?;
            }
        }
    }
    Ok(terminate)
}

/// Send one event, racing the (possibly blocking) send against abort so a slow consumer
/// can't starve abort handling while the target floods us with updates.
async fn send_event(
    event_tx: &Sender<DesktopEvent>,
    abort_rx: &mut UnboundedReceiver<()>,
    event: DesktopEvent,
) -> Result<(), Aborted> {
    tokio::select! {
        biased;
        _ = abort_rx.recv() => Err(Aborted),
        result = event_tx.send(event) => result.map_err(|_| Aborted),
    }
}

/// Build the BGRA update for a changed rectangle.
fn encode_region(image: &DecodedImage, region: &InclusiveRectangle) -> Option<DesktopEvent> {
    let img_w = image.width() as usize;
    let img_h = image.height() as usize;
    if img_w == 0 || img_h == 0 {
        return None;
    }
    // Clamp the (inclusive) region to the framebuffer — a malicious/buggy server could
    // send a rectangle exceeding the image, which would over-allocate the output and
    // overflow the `u16` x/y/width/height below. After clamping, all four fit.
    let left = (region.left as usize).min(img_w - 1);
    let top = (region.top as usize).min(img_h - 1);
    let right = (region.right as usize).min(img_w - 1);
    let bottom = (region.bottom as usize).min(img_h - 1);
    if right < left || bottom < top {
        return None;
    }
    let w = right - left + 1;
    let h = bottom - top + 1;
    let src = image.data();
    // Clamping keeps every row slice below in bounds as long as the backing buffer is the
    // expected RGBA size; bail once here rather than bounds-checking every pixel.
    if src.len() < img_w * img_h * 4 {
        return None;
    }

    let mut data = Vec::with_capacity(w * h * 4);
    #[allow(clippy::indexing_slicing)] // bounds guaranteed by the clamp + length check above
    for row in 0..h {
        let src_start = ((top + row) * img_w + left) * 4;
        let src_row = &src[src_start..src_start + w * 4];
        for s in src_row.chunks_exact(4) {
            data.push(s[2]);
            data.push(s[1]);
            data.push(s[0]);
            data.push(255);
        }
    }

    Some(DesktopEvent::RawImage {
        rect: DesktopRect {
            x: left as u16,
            y: top as u16,
            width: w as u16,
            height: h as u16,
        },
        data: Bytes::from(data),
    })
}

fn build_config(
    options: &TargetRdpOptions,
    password: &str,
    width: u16,
    height: u16,
) -> connector::Config {
    connector::Config {
        credentials: Credentials::UsernamePassword {
            username: options.username.clone(),
            password: password.to_owned(),
        },
        domain: options.domain.clone(),
        enable_tls: true,
        enable_credssp: true,
        keyboard_type: KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_layout: 0,
        keyboard_functional_keys_count: 12,
        ime_file_name: String::new(),
        dig_product_id: String::new(),
        desktop_size: connector::DesktopSize { width, height },
        bitmap: None,
        client_build: 0,
        client_name: "warpgate".to_owned(),
        client_dir: "C:\\Windows\\System32\\mstscax.dll".to_owned(),
        alternate_shell: String::new(),
        work_dir: String::new(),
        platform: MajorPlatformType::UNIX,
        hardware_id: None,
        request_data: None,
        // Warpgate always supplies the target credentials, so request autologon to
        // skip the server's own login UI (e.g. xrdp honours INFO_AUTOLOGON).
        autologon: true,
        enable_audio_playback: false,
        performance_flags: PerformanceFlags::default(),
        license_cache: None,
        timezone_info: TimezoneInfo::default(),
        compression_type: None,
        enable_server_pointer: false,
        pointer_software_rendering: true,
        desktop_scale_factor: 0,
        multitransport_flags: None,
    }
}

async fn connect(
    config: connector::Config,
    server_name: String,
    port: u16,
    verify_tls: bool,
) -> Result<(ConnectionResult, Framed)> {
    let tcp_stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((server_name.as_str(), port)),
    )
    .await
    .context("TCP connect timed out")?
    .context("TCP connect")?;
    tcp_stream.set_nodelay(true).ok();
    let client_addr = tcp_stream.local_addr().context("local addr")?;

    let mut framed = TokioFramed::new(tcp_stream);
    let mut connector = connector::ClientConnector::new(config, client_addr);

    let should_upgrade = ironrdp_tokio::connect_begin(&mut framed, &mut connector)
        .await
        .context("connect_begin")?;

    let initial_stream = framed.into_inner_no_leftover();
    let (upgraded_stream, server_public_key) =
        tls::upgrade(initial_stream, server_name.clone(), verify_tls)
            .await
            .context("TLS upgrade")?;

    let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);
    let mut upgraded_framed = TokioFramed::new(upgraded_stream);

    let mut network_client = ReqwestNetworkClient::new();
    let connection_result = ironrdp_tokio::connect_finalize(
        upgraded,
        connector,
        &mut upgraded_framed,
        &mut network_client,
        server_name.into(),
        server_public_key,
        None,
    )
    .await
    .context("connect_finalize")?;

    if connection_result.desktop_size.width == 0 || connection_result.desktop_size.height == 0 {
        warn!("target reported a zero desktop size");
    }

    Ok((connection_result, upgraded_framed))
}

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
use ironrdp::cliprdr::CliprdrClient;
use ironrdp::cliprdr::backend::ClipboardMessage;
use ironrdp::connector::connection_activation::{
    ConnectionActivationFactory, ConnectionActivationState,
};
use ironrdp::connector::{self, ConnectionResult, Credentials};
use ironrdp::core::WriteBuf;
use ironrdp::displaycontrol::client::DisplayControlClient;
use ironrdp::displaycontrol::pdu::MonitorLayoutEntry;
use ironrdp::dvc::DrdynvcClient;
use ironrdp::graphics::image_processing::PixelFormat;
use ironrdp::pdu::gcc::KeyboardType;
use ironrdp::pdu::geometry::InclusiveRectangle;
use ironrdp::pdu::rdp::capability_sets::{MajorPlatformType, client_codecs_capabilities};
use ironrdp::pdu::rdp::client_info::{PerformanceFlags, TimezoneInfo};
use ironrdp::pdu::rdp::headers::ShareDataPdu;
use ironrdp::pdu::rdp::refresh_rectangle::RefreshRectanglePdu;
use ironrdp::session::image::DecodedImage;
use ironrdp::session::{ActiveStage, ActiveStageBuilder, ActiveStageOutput};
use ironrdp_tokio::reqwest::ReqwestNetworkClient;
use ironrdp_tokio::{FramedWrite as _, TokioFramed};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{Receiver, Sender, UnboundedReceiver, UnboundedSender, unbounded_channel};
use tracing::{debug, warn};
use warpgate_common::{RdpTargetAuth, RdpTargetCompression, TargetRdpOptions};
use warpgate_core::{DesktopEvent, DesktopInput, DesktopRect, DesktopState};

use crate::clipboard::{Clipboard, ClipboardSink, TextClipboard};

/// Deadline for the TCP connect to the target.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Deadline for the RDP handshake (X.224, TLS, CredSSP — the last of which may reach out
/// to a KDC). Without it a target that accepts the TCP connection but stalls mid-handshake
/// would wedge the session forever with no event to report.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

type Framed = TokioFramed<tls::TargetTlsStream>;

/// Signals that the session was aborted from the Warpgate side.
struct Aborted;

/// cliprdr passes this to active_loop which owns transport and events
#[derive(Debug)]
enum ClipboardOut {
    Request(ClipboardMessage),
    Text(String),
}

#[derive(Debug, Clone)]
struct ClientClipboardSink(UnboundedSender<ClipboardOut>);

impl ClipboardSink for ClientClipboardSink {
    fn request(&self, message: ClipboardMessage) {
        let _ = self.0.send(ClipboardOut::Request(message));
    }

    fn text_received(&self, text: String) {
        let _ = self.0.send(ClipboardOut::Text(text));
    }
}

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
    // The viewer-supplied size may be odd or out of range; keep the initial desktop within
    // the same bounds the Display Control resize path enforces.
    let (width, height) =
        MonitorLayoutEntry::adjust_display_size(u32::from(width), u32::from(height));
    let password = auth.password.reveal()?;
    let config = build_config(
        &options,
        password.expose_secret(),
        width as u16,
        height as u16,
    );

    let (clipboard_tx, clipboard_rx) = unbounded_channel();
    let clipboard = Clipboard::deferred(ClientClipboardSink(clipboard_tx));

    let (connection_result, framed) = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        connect(
            config,
            options.host.clone(),
            options.port,
            options.verify_tls,
            options.tls_security(),
            clipboard.backend(),
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
        &clipboard,
        clipboard_rx,
    )
    .await
}

#[expect(clippy::too_many_arguments)]
async fn active_loop(
    connection_result: ConnectionResult,
    mut framed: Framed,
    image: &mut DecodedImage,
    mut input_rx: Receiver<DesktopInput>,
    event_tx: &Sender<DesktopEvent>,
    abort_rx: &mut UnboundedReceiver<()>,
    clipboard: &Clipboard<ClientClipboardSink>,
    mut clipboard_rx: UnboundedReceiver<ClipboardOut>,
) -> Result<()> {
    let activation_factory = connection_result.activation_factory;
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
    // The Display Control channel only becomes usable once the target has created it and
    // sent its capabilities, which happens after the connection is already active. A
    // resize requested before then (notably the viewer's initial size) is held here and
    // retried each iteration until `encode_resize` accepts it.
    let mut pending_resize: Option<(u16, u16)> = None;

    loop {
        if let Some((width, height)) = pending_resize
            && send_resize(&mut framed, &mut active_stage, width, height).await?
        {
            pending_resize = None;
        }

        let outputs = tokio::select! {
            biased;
            _ = abort_rx.recv() => return Ok(()),
            input = input_rx.recv() => {
                let Some(first) = input else {
                    return Ok(());
                };
                // Coalesce whatever else is already queued so a burst of pointer moves
                // becomes one fastpath batch rather than one round trip each. Resizes are
                // pulled out and only the latest is kept — each one costs the target a
                // deactivation-reactivation, so intermediate sizes from a window drag are
                // wasted work.
                let mut ops = Vec::new();
                let mut resize = None;
                for input in std::iter::once(first)
                    .chain(std::iter::from_fn(|| input_rx.try_recv().ok()))
                {
                    match input {
                        DesktopInput::Resize { width, height } => resize = Some((width, height)),
                        DesktopInput::Clipboard(text) => clipboard.offer(text),
                        other => input::translate(other, &mut ops),
                    }
                }

                // flush cliprdr offers enqueued in the loop above
                // flushed before the the fastpath messages below
                // so that clipboard is written before ctrl-v arrives
                while let Ok(out) = clipboard_rx.try_recv() {
                    if !handle_clipboard_out(out, &mut framed, &mut active_stage, event_tx, abort_rx)
                        .await?
                    {
                        return Ok(());
                    }
                }
                if resize.is_some() {
                    pending_resize = resize;
                }
                if ops.is_empty() {
                    continue;
                }
                let events = input_db.apply(ops);
                active_stage
                    .process_fastpath_input(image, &events)
                    .context("processing input")?
            }
            out = clipboard_rx.recv() => {
                // The sender is held by `clipboard`, which outlives this loop, so `None`
                // is unreachable; end the session rather than spin if that ever changes.
                let Some(out) = out else {
                    return Ok(());
                };
                if !handle_clipboard_out(out, &mut framed, &mut active_stage, event_tx, abort_rx)
                    .await?
                {
                    return Ok(());
                }
                continue;
            }
            pdu = framed.read_pdu() => {
                let (action, payload) = pdu.context("reading PDU")?;
                active_stage
                    .process(image, action, &payload)
                    .context("processing PDU")?
            }
        };

        let should_reactivate = outputs
            .iter()
            .any(|output| matches!(output, ActiveStageOutput::DeactivateAll));

        match process_outputs(&mut framed, image, outputs, event_tx, abort_rx).await {
            Ok(true) | Err(Aborted) => return Ok(()),
            Ok(false) => {}
        }

        if should_reactivate
            && let Some(size) = reactivate(
                &mut framed,
                &mut active_stage,
                &activation_factory,
                image,
                event_tx,
            )
            .await
            .context("RDP deactivation-reactivation sequence")?
        {
            send_refresh_request(&mut framed, &mut active_stage, size).await?;
        }
    }
}

/// Ask the target to resize its desktop over the Display Control DVC. The target replies
/// with a deactivation-reactivation, which `active_loop` funnels through [`reactivate`].
///
/// Returns `false` when the DVC has not finished negotiating yet; the caller keeps the
/// request pending and retries.
async fn send_resize(
    framed: &mut Framed,
    active_stage: &mut ActiveStage,
    width: u16,
    height: u16,
) -> Result<bool> {
    // The layout PDU rejects odd widths and sizes outside 200..=8192.
    let (width, height) =
        MonitorLayoutEntry::adjust_display_size(u32::from(width), u32::from(height));
    match active_stage.encode_resize(width, height, None, None) {
        Some(frame) => {
            let frame = frame.context("encoding resize request")?;
            framed
                .write_all(&frame)
                .await
                .context("sending resize request")?;
            Ok(true)
        }
        None => Ok(false),
    }
}

async fn handle_clipboard_out(
    out: ClipboardOut,
    framed: &mut Framed,
    active_stage: &mut ActiveStage,
    event_tx: &Sender<DesktopEvent>,
    abort_rx: &mut UnboundedReceiver<()>,
) -> Result<bool> {
    match out {
        ClipboardOut::Request(message) => {
            send_clipboard(framed, active_stage, message).await?;
            Ok(true)
        }
        ClipboardOut::Text(text) => {
            Ok(
                // false = receiver gone
                send_event(event_tx, abort_rx, DesktopEvent::Clipboard(text))
                    .await
                    .is_ok(),
            )
        }
    }
}

async fn send_clipboard(
    framed: &mut Framed,
    active_stage: &mut ActiveStage,
    message: ClipboardMessage,
) -> Result<()> {
    let Some(cliprdr) = active_stage.get_svc_processor_mut::<CliprdrClient>() else {
        return Ok(());
    };
    let encoded = match message {
        ClipboardMessage::SendInitiateCopy(formats) => cliprdr.initiate_copy(&formats),
        ClipboardMessage::SendInitiatePaste(format) => cliprdr.initiate_paste(format),
        ClipboardMessage::SendFormatData(data) => cliprdr.submit_format_data(data),
        // file transfer not supported
        other => {
            warn!(?other, "unsupported clipboard operation");
            return Ok(());
        }
    };
    let messages = match encoded {
        Ok(messages) => messages,
        Err(error) => {
            warn!(%error, "failed to encode clipboard message");
            return Ok(());
        }
    };
    let frame = match active_stage.process_svc_processor_messages(messages) {
        Ok(frame) => frame,
        Err(error) => {
            warn!(%error, "failed to frame clipboard message");
            return Ok(());
        }
    };
    framed
        .write_all(&frame)
        .await
        .context("sending clipboard message")
}

/// Drive the deactivation-reactivation sequence. Returns the new desktop size if the target
/// came back at a different one.
async fn reactivate(
    framed: &mut Framed,
    active_stage: &mut ActiveStage,
    activation_factory: &ConnectionActivationFactory,
    image: &mut DecodedImage,
    event_tx: &Sender<DesktopEvent>,
) -> Result<Option<connector::DesktopSize>> {
    let mut activation = activation_factory.create();
    let mut output = WriteBuf::new();

    loop {
        ironrdp_tokio::single_sequence_step(framed, &mut activation, &mut output)
            .await
            .context("driving connection reactivation")?;

        let ConnectionActivationState::Finalized {
            desktop_size,
            share_id,
            enable_server_pointer,
            ..
        } = activation.connection_activation_state()
        else {
            continue;
        };

        active_stage.set_share_id(share_id);
        active_stage.set_enable_server_pointer(enable_server_pointer);

        if image.width() != desktop_size.width || image.height() != desktop_size.height {
            debug!(
                from = ?(image.width(), image.height()),
                to = ?(desktop_size.width, desktop_size.height),
                "target reactivated at a new desktop size"
            );
            // Reactivation resets the viewer's surface; re-seed it with the pre-resize content
            // (overlap kept, new margin black) so it isn't blank until the full refresh lands.
            let keyframe = encode_resized_keyframe(image, desktop_size);
            *image =
                DecodedImage::new(PixelFormat::RgbA32, desktop_size.width, desktop_size.height);
            event_tx
                .send(DesktopEvent::Resize {
                    width: desktop_size.width,
                    height: desktop_size.height,
                })
                .await
                .context("reporting reactivated desktop size")?;
            if let Some(keyframe) = keyframe {
                event_tx
                    .send(keyframe)
                    .await
                    .context("sending resized keyframe")?;
            }
            return Ok(Some(desktop_size));
        }

        return Ok(None);
    }
}

/// Ask the target to repaint the whole desktop. After a resize the target only sends the
/// regions it considers changed, so the freshly-exposed margin of a grow would stay blank;
/// a full refresh forces it to resend everything for the new size.
///
/// `&mut` even though only `encode_static(&self)` is needed: `ActiveStage` is `Send` but not
/// `Sync`, so a shared borrow held across the write would make the session future non-`Send`.
async fn send_refresh_request(
    framed: &mut Framed,
    active_stage: &mut ActiveStage,
    size: connector::DesktopSize,
) -> Result<()> {
    let (Some(right), Some(bottom)) = (size.width.checked_sub(1), size.height.checked_sub(1))
    else {
        return Ok(());
    };

    let mut output = WriteBuf::new();
    active_stage
        .encode_static(
            &mut output,
            ShareDataPdu::RefreshRectangle(RefreshRectanglePdu {
                areas_to_refresh: vec![InclusiveRectangle {
                    left: 0,
                    top: 0,
                    right,
                    bottom,
                }],
            }),
        )
        .context("encoding refresh rectangle request")?;
    framed
        .write_all(output.filled())
        .await
        .context("requesting refreshed desktop after resize")
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
        if let ActiveStageOutput::GraphicsUpdate(region) = out
            && let Some(event) = encode_region(image, &region)
        {
            send_event(event_tx, abort_rx, event).await?;
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
        for s in src_row.as_chunks::<4>().0 {
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

/// A full BGRA frame for the resized desktop: opaque black with the pre-resize content copied
/// into the overlap.
fn encode_resized_keyframe(
    image: &DecodedImage,
    size: connector::DesktopSize,
) -> Option<DesktopEvent> {
    let old_w = usize::from(image.width());
    let old_h = usize::from(image.height());
    let new_w = usize::from(size.width);
    let new_h = usize::from(size.height);
    if old_w == 0 || old_h == 0 || new_w == 0 || new_h == 0 {
        return None;
    }
    let src = image.data();
    if src.len() < old_w.checked_mul(old_h)?.checked_mul(4)? {
        return None;
    }

    let mut data = [0u8, 0, 0, 255].repeat(new_w.checked_mul(new_h)?);
    // `zip` stops at the shorter side, so this walks exactly the overlap.
    for (src_row, dst_row) in src
        .chunks_exact(old_w * 4)
        .zip(data.chunks_exact_mut(new_w * 4))
    {
        for (src_px, dst_px) in src_row
            .as_chunks::<4>()
            .0
            .iter()
            .zip(dst_row.as_chunks_mut::<4>().0.iter_mut())
        {
            *dst_px = [src_px[2], src_px[1], src_px[0], 255];
        }
    }

    Some(DesktopEvent::RawImage {
        rect: DesktopRect {
            x: 0,
            y: 0,
            width: size.width,
            height: size.height,
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
    let codec_overrides: &[&str] = match options.compression.unwrap_or_default() {
        RdpTargetCompression::RemoteFX => &[],
        RdpTargetCompression::Lossless => &["remotefx:off"],
    };
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
        // The compression mode only controls the codec advertisement: the default set
        // includes RemoteFX, while a `lossless` target advertises no codecs so it sends
        // losslessly-compressed 32bpp bitmap updates instead. `lossy_compression` stays
        // off in every mode — it would advertise the dynamic-color-fidelity / subsampling
        // drawing flags, inviting the target to dither legacy bitmap updates down to
        // 16bpp. (`client_codecs_capabilities` never fails for these inputs; `None` would
        // just drop the flags.)
        bitmap: client_codecs_capabilities(codec_overrides)
            .ok()
            .map(|codecs| connector::BitmapConfig {
                lossy_compression: false,
                color_depth: 32,
                codecs,
            }),
        client_build: 0,
        client_name: "warpgate".to_owned(),
        client_dir: "C:\\Windows\\System32\\mstscax.dll".to_owned(),
        alternate_shell: String::new(),
        work_dir: String::new(),
        platform: MajorPlatformType::UNIX,
        hardware_id: None,
        request_data: None,
        // Warpgate supplies the target credentials, so by default request autologon to
        // skip the server's own login UI (e.g. xrdp honours INFO_AUTOLOGON). An
        // interactive-logon target flips both switches: no autologon flag, and CredSSP
        // delegates no credentials — NLA still authenticates the connection, but the
        // server has nothing to log the session on with and shows its sign-in screen.
        autologon: !options.interactive_logon,
        credssp_credentialless: options.interactive_logon,
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
    tls_security: warpgate_common::RdpTlsSecurity,
    clipboard: TextClipboard<ClientClipboardSink>,
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
    // Advertise the Display Control DVC so viewer-driven resolution changes can be pushed
    // to the target mid-session (MS-RDPEDISP). The capabilities callback has nothing to
    // reply with; `ActiveStage::encode_resize` drives the channel once it is ready.
    let mut connector = connector::ClientConnector::new(config, client_addr)
        .with_static_channel(
            DrdynvcClient::new()
                .with_dynamic_channel(DisplayControlClient::new(|_caps| Ok(Vec::new()))),
        )
        .with_static_channel(CliprdrClient::new(Box::new(clipboard)));

    let should_upgrade = ironrdp_tokio::connect_begin(&mut framed, &mut connector)
        .await
        .context("connect_begin")?;

    let initial_stream = framed.into_inner_no_leftover();
    let (upgraded_stream, server_public_key) = tls::upgrade(
        initial_stream,
        server_name.clone(),
        verify_tls,
        tls_security,
    )
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

#[cfg(test)]
mod tests {
    use ironrdp::graphics::image_processing::PixelFormat;
    use ironrdp::session::image::DecodedImage;
    use warpgate_core::{DesktopEvent, DesktopRect};

    use super::{connector, encode_resized_keyframe};

    #[test]
    fn resized_keyframe_covers_the_new_desktop() {
        let image = DecodedImage::new(PixelFormat::RgbA32, 2, 2);
        let event = encode_resized_keyframe(
            &image,
            connector::DesktopSize {
                width: 4,
                height: 3,
            },
        );

        assert!(matches!(
            event,
            Some(DesktopEvent::RawImage {
                rect: DesktopRect {
                    x: 0,
                    y: 0,
                    width: 4,
                    height: 3,
                },
                data,
            }) if data.len() == 4 * 3 * 4 && data.iter().skip(3).step_by(4).all(|alpha| *alpha == 255)
        ));
    }
}

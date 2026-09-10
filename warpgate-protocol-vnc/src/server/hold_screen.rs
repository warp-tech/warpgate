//! The viewer-facing hold screen: rendered into the VNC framebuffer while connecting to the
//! backend and while collecting an interactive second factor (TOTP typed on the viewer's
//! keyboard, or an out-of-band web approval) after a valid password.

use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use tokio::io::AsyncWrite;
use tokio::sync::{Mutex, mpsc};
use tokio::time::sleep;
use warpgate_common::UserSessionId;
use warpgate_core::{AuthorizedIdentity, Services};
use warpgate_db_entities::Parameters;
use warpgate_desktop_auth::{
    Deadline, HoldEvent, HoldFrame, HoldInputSource, HoldPainter, OtpAction, run_hold_screen,
};
use warpgate_desktop_ui as ui;

use super::RenderState;
use super::protocol::{ClientEvent, write_server_cut_text};

/// Render the hold screen while awaiting future
pub(super) async fn render_while<W, F>(
    viewer_wr: &mut W,
    events_rx: &mut mpsc::UnboundedReceiver<ClientEvent>,
    state: &mut RenderState,
    wait: F,
) -> Result<F::Output>
where
    W: AsyncWrite + Unpin,
    F: Future,
{
    tokio::pin!(wait);
    loop {
        tokio::select! {
            out = &mut wait => return Ok(out),
            event = events_rx.recv(), if !state.reader_done => {
                state.note_event(event.as_ref());
            }
            // Only render when asked to
            () = sleep(SPINNER_INTERVAL), if state.pending_request => {
                state.paint(viewer_wr, ui::render_connecting).await?;
            }
        }
    }
}

/// ui animation frame interval while connecting to the backend
const SPINNER_INTERVAL: Duration = Duration::from_millis(30);

/// Show the login banner, if one is configured, and block until the viewer acknowledges it
/// with any key or pointer button.
pub(super) async fn show_banner<W>(
    viewer_wr: &mut W,
    events_rx: &mut mpsc::UnboundedReceiver<ClientEvent>,
    render: &mut RenderState,
    services: &Services,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let Some(banner) = Parameters::Entity::get(&services.db)
        .await?
        .banner_text()
        .map(str::to_owned)
    else {
        return Ok(());
    };

    loop {
        tokio::select! {
            event = events_rx.recv(), if !render.reader_done => {
                let acknowledged = matches!(
                    event,
                    Some(ClientEvent::Key { down: true, .. })
                        // Any pressed button; a bare move (empty mask) isn't an acknowledgement.
                        | Some(ClientEvent::Pointer { buttons: 1.., .. })
                );
                render.note_event(event.as_ref());
                if acknowledged {
                    return Ok(());
                }
            }
            () = sleep(SPINNER_INTERVAL), if render.pending_request => {
                render.paint(viewer_wr, |screen, tick| ui::render_banner(screen, tick, &banner)).await?;
            }
        }
    }
}

/// Render hold screen UI while collecting OTP/waiting for web auth. Returns
/// the authenticated user once the auth state is fully accepted.
pub(super) async fn collect_additional_credentials<W>(
    viewer_wr: &mut W,
    events_rx: &mut mpsc::UnboundedReceiver<ClientEvent>,
    render: &mut RenderState,
    services: &Services,
    state_id: UserSessionId,
    username: &str,
    remote_ip: IpAddr,
) -> Result<AuthorizedIdentity>
where
    W: AsyncWrite + Unpin + Send,
{
    // The hold-screen input and painter are separate objects (so the driver can await input
    // and paint without aliasing one `&mut` across its `select!`); they share the viewer
    // render state through a lock, seeded from `render` and copied back once done.
    let shared = Arc::new(Mutex::new(render.clone()));
    let mut input = VncHoldInput {
        events_rx,
        render: shared.clone(),
    };
    let mut painter = VncHoldPainter {
        viewer_wr,
        render: shared.clone(),
    };

    let result = run_hold_screen(
        services,
        state_id,
        crate::PROTOCOL_NAME,
        username,
        remote_ip,
        &mut input,
        &mut painter,
        Deadline::until_auth_state_expires(),
    )
    .await;

    *render = shared.lock().await.clone();
    match result? {
        Some(identity) => Ok(identity),
        None => bail!("VNC interactive authentication was not completed"),
    }
}

/// Reads VNC viewer input for the hold screen, mapping X11 keysyms to OTP actions and folding
/// every other message into the shared [`RenderState`] via `note_event`.
struct VncHoldInput<'a> {
    events_rx: &'a mut mpsc::UnboundedReceiver<ClientEvent>,
    render: Arc<Mutex<RenderState>>,
}

impl HoldInputSource for VncHoldInput<'_> {
    async fn next(&mut self) -> HoldEvent {
        match self.events_rx.recv().await {
            None => {
                self.render.lock().await.note_event(None);
                HoldEvent::Disconnected
            }
            some => {
                let mut render = self.render.lock().await;
                match render.note_event(some.as_ref()).and_then(keysym_otp_action) {
                    Some(action) => {
                        // Repaint so the typed digit shows even though the viewer only
                        // requests frames on its own schedule.
                        render.pending_request = true;
                        HoldEvent::Otp(action)
                    }
                    None => HoldEvent::Other,
                }
            }
        }
    }
}

/// Paints the VNC hold screen, gated on an outstanding viewer frame request (VNC is
/// pull-based), and delivers the web-approval URL via server-cut-text.
struct VncHoldPainter<'a, W> {
    viewer_wr: &'a mut W,
    render: Arc<Mutex<RenderState>>,
}

impl<W: AsyncWrite + Unpin + Send> HoldPainter for VncHoldPainter<'_, W> {
    async fn paint(&mut self, frame: HoldFrame<'_>) -> Result<()> {
        let mut render = self.render.lock().await;
        if !render.pending_request {
            return Ok(());
        }
        match frame {
            HoldFrame::Prompt(prompt) => {
                render
                    .paint(self.viewer_wr, |screen, tick| {
                        ui::render_authentication(screen, tick, prompt)
                    })
                    .await
            }
            HoldFrame::Connecting => render.paint(self.viewer_wr, ui::render_connecting).await,
        }
    }

    async fn present_web_approval_url(&mut self, url: Option<&str>) -> Result<()> {
        if let Some(url) = url {
            write_server_cut_text(self.viewer_wr, url).await.ok();
        }
        Ok(())
    }

    fn render_interval(&self) -> Duration {
        SPINNER_INTERVAL
    }
}

// X11 keysyms accepted in the OTP field
const KEYSYM_DIGIT_0: u32 = 0x0030;
const KEYSYM_DIGIT_9: u32 = 0x0039;
const KEYSYM_KP_0: u32 = 0xFFB0;
const KEYSYM_KP_9: u32 = 0xFFB9;
const KEYSYM_BACKSPACE: u32 = 0xFF08;
const KEYSYM_RETURN: u32 = 0xFF0D;
const KEYSYM_KP_ENTER: u32 = 0xFF8D;

/// Map an X11 keysym (what VNC viewers send) to an OTP-field action. The field state machine
/// and validation live in the shared [`OtpEntry`].
fn keysym_otp_action(keysym: u32) -> Option<OtpAction> {
    Some(match keysym {
        KEYSYM_DIGIT_0..=KEYSYM_DIGIT_9 => OtpAction::Digit(char::from(keysym as u8)),
        KEYSYM_KP_0..=KEYSYM_KP_9 => {
            OtpAction::Digit(char::from(b'0' + (keysym - KEYSYM_KP_0) as u8))
        }
        KEYSYM_BACKSPACE => OtpAction::Backspace,
        KEYSYM_RETURN | KEYSYM_KP_ENTER => OtpAction::Submit,
        _ => return None,
    })
}

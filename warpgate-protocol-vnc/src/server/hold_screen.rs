//! The viewer-facing hold screen: rendered into the VNC framebuffer while connecting to the
//! backend and while collecting an interactive second factor (TOTP typed on the viewer's
//! keyboard, or an out-of-band web approval) after a valid password.

use std::future::Future;
use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::AsyncWrite;
use tokio::sync::mpsc;
use tokio::time::sleep;
use uuid::Uuid;
use warpgate_common::auth::AuthResult;
use warpgate_core::Services;
use warpgate_desktop_auth::{OtpAction, OtpActionApplyOutcome, OtpEntry, auth_prompt};
use warpgate_desktop_ui::{self as ui, AuthPrompt};

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
                state.note_event(event);
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

/// Render hold screen UI while collecting OTP/waiting for web auth
pub(super) async fn collect_additional_credentials<W>(
    viewer_wr: &mut W,
    events_rx: &mut mpsc::UnboundedReceiver<ClientEvent>,
    render: &mut RenderState,
    services: &Services,
    state_id: Uuid,
    username: &str,
    remote_ip: IpAddr,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let state = services
        .auth_state_store
        .lock()
        .await
        .get(&state_id)
        .context("auth state expired")?;

    let mut otp = OtpEntry::new("vnc");
    let mut approval = services.auth_state_store.lock().await.subscribe(state_id);

    'next_prompt: loop {
        // Bind to a local so the state guard drops before `complete()` re-locks the same
        // AuthState mutex — holding a match-scrutinee guard across it deadlocks (same reason
        // RDP's `run_hold_screen` does this).
        let verification = state.lock().await.verify();
        let need = match verification {
            AuthResult::Accepted { .. } => {
                services
                    .auth_state_store
                    .lock()
                    .await
                    .complete(&state_id)
                    .await;
                return Ok(());
            }
            AuthResult::Rejected => bail!("VNC authentication rejected"),
            AuthResult::Need(need) => need,
        };

        let Some(mut prompt) = auth_prompt(services, &state, &need, otp.entered()).await else {
            bail!("authentication policy requires a factor that cannot be collected over VNC");
        };

        if let AuthPrompt::WebApproval { url, .. } = &prompt {
            if let Some(url) = url {
                write_server_cut_text(viewer_wr, &url).await.ok();
            }
        }

        loop {
            tokio::select! {
                // Browser approval landed (or the signal lagged/closed); the loop re-verifies.
                _ = approval.recv(), if matches!(prompt, ui::AuthPrompt::WebApproval { ..}) => {
                    continue 'next_prompt // web approval accepted
                }
                event = events_rx.recv(), if !render.reader_done => {
                    if let Some(keysym) = render.note_event(event)
                        && let AuthPrompt::Otp { entered } = &mut prompt
                    {
                        if let Some(action) = keysym_otp_action(keysym)

                        {
                            match otp.apply(action, services, &state, username, remote_ip).await {
                                OtpActionApplyOutcome::Applied => {
                                    *entered = otp.entered().to_string();
                                },
                                OtpActionApplyOutcome::AcceptedAndValidated => break,
                                OtpActionApplyOutcome::TooManyFailures => {
                                    bail!("too many incorrect one-time passwords");
                                }
                            }
                        }
                        render.pending_request = true; // reflect the input on the next paint
                        continue 'next_prompt // OTP might have been accepted or rejected
                    }
                }
                () = sleep(SPINNER_INTERVAL), if render.pending_request => {
                    render.paint(viewer_wr, |tick| ui::render_authentication(tick, &prompt)).await?;
                }
            }
        }
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

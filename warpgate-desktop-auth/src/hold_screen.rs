//! The shared interactive-second-factor hold-screen loop for the native desktop protocols.
//!
//! After a valid password, when the credential policy still needs a TOTP or an out-of-band
//! web approval, both RDP and VNC render a "holding screen" to the viewer and collect that
//! factor over the live session before dialing the target. The state machine — verify →
//! prompt → feed keystrokes into the OTP field (or await a browser approval) → interpret —
//! and the single enforced [`Deadline`] live here once. Each protocol supplies only its
//! transport: how to read a keypress ([`HoldInputSource`]) and how to paint ([`HoldPainter`]),
//! kept as separate objects so the driver can await input and paint without aliasing one
//! `&mut` across the `select!`.

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::time::{MissedTickBehavior, Sleep, interval, sleep};
use tracing::warn;
use warpgate_common::auth::AuthResult;
use warpgate_common::{Protocol, UserSessionId};
use warpgate_core::{AuthorizedIdentity, Services, TIMEOUT};
use warpgate_desktop_ui::AuthPrompt;

use crate::{OtpAction, OtpActionApplyOutcome, OtpEntry, auth_prompt};

/// One viewer event, as the shared driver sees it. Protocol code has already applied any
/// side effects (capability / size updates, repaint requests) to its own state and mapped a
/// keypress to an [`OtpAction`] where one applies.
pub enum HoldEvent {
    /// A key that maps to an OTP-field action.
    Otp(OtpAction),
    /// Anything else (mouse, an unmapped key, a resize the source handled internally). The
    /// driver just loops to re-check state and repaint.
    Other,
    /// The viewer disconnected.
    Disconnected,
}

/// What the driver asks the painter to render.
pub enum HoldFrame<'a> {
    /// The interactive prompt (OTP field / web-approval instructions).
    Prompt(&'a AuthPrompt),
    /// A "connecting to target" screen, shown once authentication completes.
    Connecting,
}

/// Reads viewer input for the hold screen, mapping the protocol's raw keyboard encoding
/// (RDP scancodes / VNC X11 keysyms) to an [`OtpAction`]. Awaiting `next` must borrow only
/// the event source — never state the painter also touches — so the two can coexist in the
/// driver's `select!`.
pub trait HoldInputSource {
    fn next(&mut self) -> impl Future<Output = HoldEvent> + Send;
}

/// Renders the hold screen to the viewer. Implementations own their pixel format and render
/// cadence, including any protocol-required request-gating (VNC only paints when the viewer
/// has asked for a frame); the driver decides only *what* to show and *when* to tick.
pub trait HoldPainter {
    fn paint(&mut self, frame: HoldFrame<'_>) -> impl Future<Output = Result<()>> + Send;

    /// Deliver the web-approval URL out of band (e.g. VNC cut-text). Default no-op, for
    /// protocols that render the URL inside the prompt.
    fn present_web_approval_url(
        &mut self,
        _url: Option<&str>,
    ) -> impl Future<Output = Result<()>> + Send {
        async { Ok(()) }
    }

    /// The animation repaint interval.
    fn render_interval(&self) -> Duration;
}

/// A single deadline for the whole interactive phase. Constructed once and threaded through so
/// no protocol-level handshake timeout can cap the interactive phase (and thus 2FA) shorter.
pub struct Deadline {
    sleep: Pin<Box<Sleep>>,
}

impl Deadline {
    /// Until the auth state is vacuumed from the store (`TIMEOUT`). Past that an approval can
    /// no longer arrive, so holding the viewer any longer is pointless.
    #[must_use]
    pub fn until_auth_state_expires() -> Self {
        Self {
            sleep: Box::pin(sleep(*TIMEOUT)),
        }
    }

    fn elapsed(&mut self) -> Pin<&mut Sleep> {
        self.sleep.as_mut()
    }
}

/// Drive the interactive second-factor hold screen until the auth state is accepted.
///
/// Returns the authenticated user on success, or `None` on rejection, timeout, an
/// uncollectable required factor, or viewer disconnect. On success, clears the user's
/// brute-force counters and paints a "connecting" screen before returning, so every protocol
/// clears counters at the same point.
#[allow(clippy::too_many_arguments)]
pub async fn run_hold_screen<I, P>(
    services: &Services,
    state_id: UserSessionId,
    protocol: Protocol,
    username: &str,
    remote_ip: IpAddr,
    input: &mut I,
    painter: &mut P,
    mut deadline: Deadline,
) -> Result<Option<AuthorizedIdentity>>
where
    I: HoldInputSource,
    P: HoldPainter,
{
    let state = services
        .auth_state_store
        .lock()
        .await
        .get(&state_id)
        .context("auth state expired")?;
    let mut approval = state.lock().await.subscribe();

    let mut otp = OtpEntry::new(protocol);
    let mut ticker = interval(painter.render_interval());
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    'next_prompt: loop {
        // Bind to a local so the `state` guard drops here — the arms below re-lock the same
        // mutex (`auth_prompt`, OTP validation).
        let need = {
            let state = state.lock().await;
            match state.verify() {
                AuthResult::Accepted { user_info } => {
                    let identity = AuthorizedIdentity::from_auth_state(&state);
                    drop(state);
                    let _ = services
                        .login_protection
                        .clear_failed_attempts(&remote_ip, &user_info.username)
                        .await;
                    // Feedback before the caller blocks on the backend connect
                    let _ = painter.paint(HoldFrame::Connecting).await;
                    return Ok(identity);
                }
                AuthResult::Rejected => return Ok(None),
                AuthResult::Need(need) => need,
            }
        };

        let Some(mut prompt) = auth_prompt(services, &state, &need, otp.entered()).await else {
            warn!(
                "desktop auth policy requires a factor that can't be collected on the hold screen"
            );
            return Ok(None);
        };

        let awaiting_web = matches!(prompt, AuthPrompt::WebApproval { .. });
        if let AuthPrompt::WebApproval { url, .. } = &prompt {
            painter.present_web_approval_url(url.as_deref()).await?;
        }

        loop {
            tokio::select! {
                // Browser approval landed (or the signal lagged); re-verify on the next loop.
                _ = approval.recv(), if awaiting_web => continue 'next_prompt,
                () = deadline.elapsed() => {
                    warn!("desktop interactive authentication timed out");
                    return Ok(None);
                }
                event = input.next() => match event {
                    HoldEvent::Disconnected => return Ok(None),
                    HoldEvent::Other => {}
                    HoldEvent::Otp(action) => {
                        if !awaiting_web
                            && let AuthPrompt::Otp { entered } = &mut prompt
                        {
                            match otp
                                .apply(action, services, &state, username, remote_ip)
                                .await
                            {
                                OtpActionApplyOutcome::Applied => {
                                    *entered = otp.entered().to_string();
                                }
                                OtpActionApplyOutcome::AcceptedAndValidated => continue 'next_prompt,
                                OtpActionApplyOutcome::TooManyFailures => {
                                    warn!("too many incorrect one-time passwords");
                                    return Ok(None);
                                }
                            }
                        }
                    }
                },
                _ = ticker.tick() => {
                    painter.paint(HoldFrame::Prompt(&prompt)).await?;
                }
            }
        }
    }
}

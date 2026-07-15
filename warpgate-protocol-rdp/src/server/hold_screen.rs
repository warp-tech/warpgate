//! The interactive second-factor "holding screen": rendered to the RDP viewer after a
//! valid password (NLA) when the credential policy still needs a TOTP or web approval.
//! Collects that factor over the live RDP session before the target is dialed.

use std::convert::Infallible;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::sync::mpsc::UnboundedSender;
use tokio_stream::StreamExt;
use tracing::warn;
use warpgate_common::auth::{AuthResult, AuthStateUserInfo};
use warpgate_core::Services;
use warpgate_desktop_auth::{
    InteractiveAuth, OtpAction, OtpActionApplyOutcome, OtpEntry, auth_prompt,
};
use warpgate_desktop_ui::{self as ui, AuthPrompt};
use warpgate_rdp_ipc::server::{Event as ServerHelperEvent, Input as ServerHelperInput};

use super::HelperReader;

/// How often the holding screen repaints (spinner animation cadence).
const HOLD_RENDER_INTERVAL: Duration = Duration::from_millis(100);

/// Render a holding screen to the viewer and collect the interactive second factor — a
/// TOTP typed on the viewer's keyboard, or an out-of-band web approval — until the auth
/// state is fully accepted. Returns the authenticated user on success, `None` on failure
/// or viewer disconnect. Input events are read from the same serve-helper channel as the
/// main control loop, so it hands us `&mut lines` for the duration.
pub(super) async fn run_hold_screen(
    services: &Services,
    interactive: &InteractiveAuth,
    frames: &mut HelperReader,
    helper_in_tx: &UnboundedSender<ServerHelperInput>,
) -> Result<Option<AuthStateUserInfo>> {
    let state = services
        .auth_state_store
        .lock()
        .await
        .get(&interactive.state_id)
        .context("auth state expired")?;
    let mut approval = services
        .auth_state_store
        .lock()
        .await
        .subscribe(interactive.state_id);

    // Size the viewer to the UI canvas; the target's real size follows once it connects.
    let _ = helper_in_tx.send(ServerHelperInput::Resize {
        width: ui::SCREEN_W,
        height: ui::SCREEN_H,
    });

    let mut otp = OtpEntry::new("rdp");
    let mut painter = HoldPainter::new();
    let mut ticker = tokio::time::interval(HOLD_RENDER_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        // Bind to a local so the `state` guard drops here — `complete()` below re-locks
        // the same AuthState mutex, and holding a match-scrutinee guard across it deadlocks.
        let verification = state.lock().await.verify();
        let need = match verification {
            AuthResult::Accepted { user_info } => {
                let _ = services
                    .login_protection
                    .clear_failed_attempts(&interactive.remote_ip, &user_info.username)
                    .await;
                services
                    .auth_state_store
                    .lock()
                    .await
                    .complete(&interactive.state_id)
                    .await;
                // Swap the OTP prompt for a "Connecting" screen before the caller blocks on
                // the backend connect, so the viewer gets feedback instead of a frozen frame.
                let _ = painter.paint(helper_in_tx, ui::render_connecting);
                return Ok(Some(user_info));
            }
            AuthResult::Rejected => return Ok(None),
            AuthResult::Need(need) => need,
        };

        let Some(mut prompt) = auth_prompt(services, &state, &need, otp.entered()).await else {
            warn!(
                "RDP auth policy requires a factor that can't be collected on the holding screen"
            );
            return Ok(None);
        };

        let awaiting_web = matches!(prompt, ui::AuthPrompt::WebApproval { .. });

        loop {
            tokio::select! {
                // Browser approval landed (or the signal lagged/closed); re-verify on the next loop.
                _ = approval.recv(), if awaiting_web => break,
                frame = frames.next() => {
                    let Some(frame) = frame else {
                        return Ok(None);
                    };
                    let frame = frame.context("reading serve helper output")?;
                    let action = match ServerHelperEvent::decode(&frame) {
                        Some(ServerHelperEvent::Disconnected) => return Ok(None),
                        Some(ServerHelperEvent::Scancode { code, down, .. }) if down => {
                            scancode_otp_action(code)
                        }
                        Some(ServerHelperEvent::Key { keysym, down }) if down => key_otp_action(keysym),
                        _ => None,
                    };
                    if !awaiting_web
                        && let Some(action) = action
                        && let AuthPrompt::Otp { entered } = &mut prompt
                        {
                        match otp
                            .apply(action, services, &state, &interactive.username, interactive.remote_ip)
                            .await {
                                OtpActionApplyOutcome::Applied =>  {
                                    *entered = otp.entered().to_string();
                                },
                                OtpActionApplyOutcome::AcceptedAndValidated => break,
                                OtpActionApplyOutcome::TooManyFailures => {
                                    warn!("too many incorrect one-time passwords");
                                    return Ok(None);
                                }
                            }
                        }
                },
                _ = ticker.tick() => {
                    painter.paint(helper_in_tx, |tick| ui::render_authentication(tick, &prompt))?;
                },
            }
        }
    }
}

/// Paints the full-screen hold-screen UI to the RDP viewer via the serve helper, owning the
/// spinner tick. `paint` takes a UI render function (`ui::render_*`) so the prompt and
/// "Connecting" screens go through one code path.
struct HoldPainter {
    tick: u64,
}

impl HoldPainter {
    const fn new() -> Self {
        Self { tick: 0 }
    }

    /// Render one frame with `render_frame(tick)` (RGB888), convert it to the BGRA the serve
    /// helper expects, and push it as a full-screen frame. Advances the spinner tick.
    fn paint(
        &mut self,
        helper_in_tx: &UnboundedSender<ServerHelperInput>,
        render_frame: impl FnOnce(u64) -> Result<Vec<u8>, Infallible>,
    ) -> Result<()> {
        let rgb = render_frame(self.tick).unwrap_or_default();
        self.tick = self.tick.wrapping_add(1);

        let mut bgra = Vec::with_capacity(rgb.len() / 3 * 4);
        for px in rgb.chunks_exact(3) {
            if let Some(&[r, g, b]) = px.first_chunk::<3>() {
                bgra.extend_from_slice(&[b, g, r, 255]);
            }
        }
        if helper_in_tx
            .send(ServerHelperInput::Frame {
                x: 0,
                y: 0,
                width: ui::SCREEN_W,
                height: ui::SCREEN_H,
                data: bgra.into(),
            })
            .is_err()
        {
            bail!("serve helper channel closed");
        }
        Ok(())
    }
}

/// Map a PC/AT set-1 scancode (what mstsc/FreeRDP send) to an OTP action.
fn scancode_otp_action(code: u8) -> Option<OtpAction> {
    Some(match code {
        0x02..=0x0a => OtpAction::Digit(char::from(b'1' + (code - 0x02))), // top row 1..9
        0x0b | 0x52 => OtpAction::Digit('0'),                              // keypad 0
        0x4f => OtpAction::Digit('1'),
        0x50 => OtpAction::Digit('2'),
        0x51 => OtpAction::Digit('3'),
        0x4b => OtpAction::Digit('4'),
        0x4c => OtpAction::Digit('5'),
        0x4d => OtpAction::Digit('6'),
        0x47 => OtpAction::Digit('7'),
        0x48 => OtpAction::Digit('8'),
        0x49 => OtpAction::Digit('9'),
        0x0e => OtpAction::Backspace,
        0x1c => OtpAction::Submit, // Enter (main + keypad)
        _ => return None,
    })
}

/// Map a Unicode keypress (viewers that send `Key` instead of scancodes) to an OTP action.
fn key_otp_action(keysym: u32) -> Option<OtpAction> {
    Some(match keysym {
        0x30..=0x39 => OtpAction::Digit(char::from(u8::try_from(keysym).ok()?)), // '0'..'9'
        0x08 => OtpAction::Backspace,
        0x0d | 0x0a => OtpAction::Submit, // CR / LF
        _ => return None,
    })
}

#[cfg(test)]
mod otp_input_tests {
    use super::{OtpAction, key_otp_action, scancode_otp_action};

    fn digit(action: Option<OtpAction>) -> Option<char> {
        match action {
            Some(OtpAction::Digit(c)) => Some(c),
            _ => None,
        }
    }

    #[test]
    fn scancode_number_row() {
        // 0x02..=0x0a is the '1'..'9' row (computed, so guard the ends), 0x0b is '0'.
        assert_eq!(digit(scancode_otp_action(0x02)), Some('1'));
        assert_eq!(digit(scancode_otp_action(0x0a)), Some('9'));
        assert_eq!(digit(scancode_otp_action(0x0b)), Some('0'));
    }

    #[test]
    fn scancode_keypad() {
        for (code, expected) in [
            (0x52u8, '0'),
            (0x4f, '1'),
            (0x50, '2'),
            (0x51, '3'),
            (0x4b, '4'),
            (0x4c, '5'),
            (0x4d, '6'),
            (0x47, '7'),
            (0x48, '8'),
            (0x49, '9'),
        ] {
            assert_eq!(
                digit(scancode_otp_action(code)),
                Some(expected),
                "scancode {code:#x}"
            );
        }
    }

    #[test]
    fn scancode_control_and_unmapped() {
        assert!(matches!(
            scancode_otp_action(0x0e),
            Some(OtpAction::Backspace)
        ));
        assert!(matches!(scancode_otp_action(0x1c), Some(OtpAction::Submit)));
        assert!(scancode_otp_action(0x3b).is_none()); // F1 — not an OTP key
        assert!(scancode_otp_action(0x00).is_none());
    }

    #[test]
    fn keysym_digits_control_and_unmapped() {
        for d in 0..=9u8 {
            let c = char::from(b'0' + d);
            assert_eq!(digit(key_otp_action(u32::from(c))), Some(c));
        }
        assert!(matches!(key_otp_action(0x08), Some(OtpAction::Backspace)));
        assert!(matches!(key_otp_action(0x0d), Some(OtpAction::Submit)));
        assert!(matches!(key_otp_action(0x0a), Some(OtpAction::Submit)));
        assert!(key_otp_action(u32::from('A')).is_none());
        assert!(key_otp_action(u32::from(' ')).is_none());
    }
}

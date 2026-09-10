//! The interactive second-factor "holding screen": rendered to the RDP viewer after a
//! valid password (NLA) when the credential policy still needs a TOTP or web approval.
//! Collects that factor over the live RDP session before the target is dialed.

use std::convert::Infallible;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Result, anyhow};
use tokio::sync::mpsc::{Sender, UnboundedReceiver};
use warpgate_core::{AuthorizedIdentity, DesktopInput, Scancode, Services};
use warpgate_desktop_auth::{
    Deadline, HoldEvent, HoldFrame, HoldInputSource, HoldPainter as HoldPainterExt,
    InteractiveAuth, OtpAction, run_hold_screen as run_hold_screen_driver,
};
use warpgate_desktop_ui as ui;

use super::protocol::{Event as ServerEvent, Input as ServerInput};

/// How often the holding screen repaints (spinner animation cadence).
const HOLD_RENDER_INTERVAL: Duration = Duration::from_millis(100);

/// Render a holding screen to the viewer and collect the interactive second factor — a
/// TOTP typed on the viewer's keyboard, or an out-of-band web approval — until the auth
/// state is fully accepted. Returns the authenticated user on success, `None` on failure
/// or viewer disconnect. Input events are read from the same channel as the main control
/// loop, so it hands us `&mut events` for the duration.
pub(super) async fn run_hold_screen(
    services: &Services,
    interactive: &InteractiveAuth,
    events: &mut UnboundedReceiver<ServerEvent>,
    server_in_tx: &Sender<ServerInput>,
    screen: &mut ui::Screen,
) -> Result<Option<AuthorizedIdentity>> {
    // A resize can arrive mid-hold (a viewer window drag, or mstsc's initial Display Control
    // layout): the input reader records it here and the painter follows it. Shared behind a
    // lock because the reader and the painter are separate objects (so the driver can await
    // input and paint without aliasing one `&mut` across its `select!`); the lock is never
    // held across an await, which keeps the reader cancel-safe.
    let shared_screen = Arc::new(Mutex::new(*screen));
    let mut input = RdpHoldInput {
        events,
        screen: shared_screen.clone(),
    };
    let mut painter = RdpHoldPainter {
        inner: HoldPainter::new(*screen),
        server_in_tx: server_in_tx.clone(),
        screen: shared_screen.clone(),
    };

    let result = run_hold_screen_driver(
        services,
        interactive.state_id,
        crate::PROTOCOL_NAME,
        &interactive.username,
        interactive.remote_ip,
        &mut input,
        &mut painter,
        Deadline::until_auth_state_expires(),
    )
    .await;

    // Hand the negotiated size back to the caller so it dials the target at it.
    *screen = *shared_screen.lock().unwrap_or_else(PoisonError::into_inner);
    result
}

/// Reads RDP viewer input for the hold screen, mapping scancodes / Unicode keys to OTP
/// actions and tracking the viewer's negotiated size.
struct RdpHoldInput<'a> {
    events: &'a mut UnboundedReceiver<ServerEvent>,
    screen: Arc<Mutex<ui::Screen>>,
}

impl HoldInputSource for RdpHoldInput<'_> {
    async fn next(&mut self) -> HoldEvent {
        match self.events.recv().await {
            None => HoldEvent::Disconnected,
            Some(ServerEvent::Input(DesktopInput::Key {
                keysym,
                scancode,
                down: true,
            })) => scancode
                .and_then(scancode_otp_action)
                .or_else(|| keysym.and_then(key_otp_action))
                .map_or(HoldEvent::Other, HoldEvent::Otp),
            Some(
                ServerEvent::Size { width, height } | ServerEvent::ResizeRequest { width, height },
            ) => {
                *self.screen.lock().unwrap_or_else(PoisonError::into_inner) =
                    ui::Screen { width, height };
                HoldEvent::Other
            }
            Some(_) => HoldEvent::Other,
        }
    }
}

/// Paints the RDP hold screen: renders the UI to RGB, converts to BGRA and pushes a
/// full-screen frame via the shared [`HoldPainter`].
struct RdpHoldPainter {
    inner: HoldPainter,
    server_in_tx: Sender<ServerInput>,
    screen: Arc<Mutex<ui::Screen>>,
}

impl HoldPainterExt for RdpHoldPainter {
    async fn paint(&mut self, frame: HoldFrame<'_>) -> Result<()> {
        self.inner
            .set_screen(*self.screen.lock().unwrap_or_else(PoisonError::into_inner));
        match frame {
            HoldFrame::Prompt(prompt) => {
                self.inner
                    .paint(&self.server_in_tx, |screen, tick| {
                        ui::render_authentication(screen, tick, prompt)
                    })
                    .await
            }
            HoldFrame::Connecting => {
                self.inner
                    .paint(&self.server_in_tx, ui::render_connecting)
                    .await
            }
        }
    }

    fn render_interval(&self) -> Duration {
        HOLD_RENDER_INTERVAL
    }
}

/// Show the login banner and block until the viewer acknowledges it with any key or click.
/// Returns `false` if the viewer disconnected instead. Like [`run_hold_screen`], it tracks
/// the viewer's negotiated size in `screen` while it holds the event stream.
pub(super) async fn run_banner_screen(
    banner: &str,
    events: &mut UnboundedReceiver<ServerEvent>,
    server_in_tx: &Sender<ServerInput>,
    screen: &mut ui::Screen,
) -> Result<bool> {
    let mut painter = HoldPainter::new(*screen);
    let mut ticker = tokio::time::interval(HOLD_RENDER_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            event = events.recv() => {
                let Some(event) = event else {
                    return Ok(false);
                };
                match event {
                    ServerEvent::Input(DesktopInput::Key { down: true, .. }) => return Ok(true),
                    // Any button press
                    ServerEvent::Input(DesktopInput::Pointer { buttons, .. }) if buttons != 0 => {
                        return Ok(true);
                    }
                    ServerEvent::Size { width, height }
                    | ServerEvent::ResizeRequest { width, height } => {
                        *screen = ui::Screen { width, height };
                        painter.set_screen(*screen);
                    }
                    _ => (),
                }
            },
            _ = ticker.tick() => {
                painter
                    .paint(server_in_tx, |screen, tick| ui::render_banner(screen, tick, banner))
                    .await?;
            },
        }
    }
}

/// Paints the full-screen hold-screen UI to the RDP viewer, owning the spinner tick and
/// keeping the RDP server's desktop in step with the negotiated size. `paint` takes a UI
/// render function (`ui::render_*`) so the prompt and "Connecting" screens go through one
/// code path.
struct HoldPainter {
    tick: u64,
    screen: ui::Screen,
    /// The size the RDP server was last told to run at.
    server_screen: ui::Screen,
}

impl HoldPainter {
    const fn new(screen: ui::Screen) -> Self {
        Self {
            tick: 0,
            screen,
            server_screen: screen,
        }
    }

    const fn set_screen(&mut self, screen: ui::Screen) {
        self.screen = screen;
    }

    /// Render one frame with `render_frame(tick)` (RGB888), convert it to the BGRA the RDP
    /// server expects, and push it as a full-screen frame. Advances the spinner tick.
    ///
    /// A changed size is pushed to the server first, so it never sees a frame larger than
    /// its desktop. Pre-dial there is no target to consult, so a viewer's resize request is
    /// granted as-is (a size the server already runs at is ignored by it). This happens here
    /// rather than where the resize event is read because the input reader is polled inside
    /// the driver's `select!` and can be dropped mid-await, whereas `paint` runs to completion.
    async fn paint(
        &mut self,
        server_in_tx: &Sender<ServerInput>,
        render_frame: impl FnOnce(ui::Screen, u64) -> Result<Vec<u8>, Infallible>,
    ) -> Result<()> {
        if self.screen != self.server_screen {
            Self::send(
                server_in_tx,
                ServerInput::Resize {
                    width: self.screen.width,
                    height: self.screen.height,
                },
            )
            .await?;
            self.server_screen = self.screen;
        }

        let rgb = render_frame(self.screen, self.tick).unwrap_or_default();
        self.tick = self.tick.wrapping_add(1);

        let mut bgra = Vec::with_capacity(rgb.len() / 3 * 4);
        for px in rgb.as_chunks::<3>().0 {
            if let Some(&[r, g, b]) = px.first_chunk::<3>() {
                bgra.extend_from_slice(&[b, g, r, 255]);
            }
        }
        Self::send(
            server_in_tx,
            ServerInput::Frame {
                x: 0,
                y: 0,
                width: self.screen.width,
                height: self.screen.height,
                data: bgra.into(),
            },
        )
        .await
    }

    async fn send(server_in_tx: &Sender<ServerInput>, input: ServerInput) -> Result<()> {
        server_in_tx
            .send(input)
            .await
            .map_err(|_| anyhow!("RDP server channel closed"))
    }
}

/// Map a PC/AT set-1 scancode (what mstsc/FreeRDP send) to an OTP action.
fn scancode_otp_action(scancode: Scancode) -> Option<OtpAction> {
    let Scancode { code, extended } = scancode;
    // The nav cluster shares its make codes with the keypad and is told apart only by the
    // E0 prefix, so without this an arrow key would type a digit. Numpad Enter is the one
    // extended key that still means something here.
    if extended && code != 0x1c {
        return None;
    }
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
    use super::{OtpAction, Scancode, key_otp_action, scancode_otp_action};

    fn digit(action: Option<OtpAction>) -> Option<char> {
        match action {
            Some(OtpAction::Digit(c)) => Some(c),
            _ => None,
        }
    }

    fn plain(code: u8) -> Option<OtpAction> {
        scancode_otp_action(Scancode {
            code,
            extended: false,
        })
    }

    fn e0(code: u8) -> Option<OtpAction> {
        scancode_otp_action(Scancode {
            code,
            extended: true,
        })
    }

    #[test]
    fn scancode_number_row() {
        // 0x02..=0x0a is the '1'..'9' row (computed, so guard the ends), 0x0b is '0'.
        assert_eq!(digit(plain(0x02)), Some('1'));
        assert_eq!(digit(plain(0x0a)), Some('9'));
        assert_eq!(digit(plain(0x0b)), Some('0'));
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
            assert_eq!(digit(plain(code)), Some(expected), "scancode {code:#x}");
        }
    }

    /// The nav cluster repeats the keypad's make codes under an E0 prefix; pressing an
    /// arrow must not enter a digit.
    #[test]
    fn scancode_nav_cluster_is_not_a_digit() {
        for code in [0x47u8, 0x48, 0x49, 0x4b, 0x4d, 0x4f, 0x50, 0x51, 0x52] {
            assert!(e0(code).is_none(), "extended scancode {code:#x}");
        }
        assert!(matches!(e0(0x1c), Some(OtpAction::Submit))); // numpad Enter
    }

    #[test]
    fn scancode_control_and_unmapped() {
        assert!(matches!(plain(0x0e), Some(OtpAction::Backspace)));
        assert!(matches!(plain(0x1c), Some(OtpAction::Submit)));
        assert!(plain(0x3b).is_none()); // F1 — not an OTP key
        assert!(plain(0x00).is_none());
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

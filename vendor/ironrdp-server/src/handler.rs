use ironrdp_ainput as ainput;
use ironrdp_pdu::input::fast_path::{self, SynchronizeFlags};
use ironrdp_pdu::input::mouse::PointerFlags;
use ironrdp_pdu::input::mouse_rel::PointerRelFlags;
use ironrdp_pdu::input::mouse_x::PointerXFlags;
use ironrdp_pdu::input::sync::SyncToggleFlags;
use ironrdp_pdu::input::{MousePdu, MouseRelPdu, MouseXPdu, scan_code, unicode};

/// Keyboard Event
///
/// Describes a keyboard event received from the client
///
#[derive(Debug)]
pub enum KeyboardEvent {
    Pressed { code: u8, extended: bool },
    Released { code: u8, extended: bool },
    UnicodePressed(u16),
    UnicodeReleased(u16),
    Synchronize(SynchronizeFlags),
}

/// Mouse Event
///
/// Describes a mouse event received from the client
///
#[derive(Debug)]
#[non_exhaustive]
pub enum MouseEvent {
    Move {
        x: u16,
        y: u16,
    },
    /// A button press or release at the absolute position the event source
    /// carries (`MousePdu`, `MouseXPdu`, `ainput::MousePdu`).
    Button {
        x: u16,
        y: u16,
        button: MouseButton,
        pressed: bool,
    },
    /// A button press or release with a relative motion delta instead of an
    /// absolute position. Per MS-RDPBCGR 2.2.8.1.1.3.1.1.7, a `MouseRelPdu`
    /// button flag reports the press or release at the position produced by
    /// applying `x`/`y` to the previous position, so the delta belongs to
    /// this event and is not a separate `RelMove`.
    ButtonRel {
        x: i32,
        y: i32,
        button: MouseButton,
        pressed: bool,
    },
    VerticalScroll {
        value: i16,
    },
    HorizontalScroll {
        value: i16,
    },
    Scroll {
        x: i32,
        y: i32,
    },
    RelMove {
        x: i32,
        y: i32,
    },
}

/// Mouse button identity, shared by [`MouseEvent::Button`] and
/// [`MouseEvent::ButtonRel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MouseButton {
    Left,
    Right,
    Middle,
    /// Extended button 1, also known as button 4 or the "back" button.
    X1,
    /// Extended button 2, also known as button 5 or the "forward" button.
    X2,
}

/// Input Event Handler for an RDP server
///
/// Whenever the RDP server will receive an input event from a client, the relevant callback from
/// this handler will be called
///
/// # Example
///
/// ```
/// use ironrdp_server::{KeyboardEvent, MouseEvent, RdpServerInputHandler};
///
/// pub struct InputHandler;
///
/// impl RdpServerInputHandler for InputHandler {
///     fn keyboard(&mut self, event: KeyboardEvent) {
///         match event {
///             KeyboardEvent::Pressed { code, .. } => println!("Pressed {}", code),
///             KeyboardEvent::Released { code, .. } => println!("Released {}", code),
///             other => println!("unhandled event: {:?}", other),
///         };
///     }
///
///     fn mouse(&mut self, event: MouseEvent) {
///         let result = match event {
///             MouseEvent::Move { x, y } => println!("Moved mouse to {} {}", x, y),
///             other => println!("unhandled event: {:?}", other),
///         };
///     }
/// }
/// ```
pub trait RdpServerInputHandler: Send {
    fn keyboard(&mut self, event: KeyboardEvent);
    fn mouse(&mut self, event: MouseEvent);
}

impl From<(u8, fast_path::KeyboardFlags)> for KeyboardEvent {
    fn from((key, flags): (u8, fast_path::KeyboardFlags)) -> Self {
        let extended = flags.contains(fast_path::KeyboardFlags::EXTENDED);
        if flags.contains(fast_path::KeyboardFlags::RELEASE) {
            KeyboardEvent::Released { code: key, extended }
        } else {
            KeyboardEvent::Pressed { code: key, extended }
        }
    }
}

impl From<(u16, fast_path::KeyboardFlags)> for KeyboardEvent {
    fn from((key, flags): (u16, fast_path::KeyboardFlags)) -> Self {
        if flags.contains(fast_path::KeyboardFlags::RELEASE) {
            KeyboardEvent::UnicodeReleased(key)
        } else {
            KeyboardEvent::UnicodePressed(key)
        }
    }
}

impl From<(u16, scan_code::KeyboardFlags)> for KeyboardEvent {
    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        reason = "we are truncating the value on purpose"
    )]
    fn from((key, flags): (u16, scan_code::KeyboardFlags)) -> Self {
        let extended = flags.contains(scan_code::KeyboardFlags::EXTENDED);

        if flags.contains(scan_code::KeyboardFlags::RELEASE) {
            KeyboardEvent::Released {
                code: key as u8,
                extended,
            }
        } else {
            KeyboardEvent::Pressed {
                code: key as u8,
                extended,
            }
        }
    }
}

impl From<(u16, unicode::KeyboardFlags)> for KeyboardEvent {
    fn from((key, flags): (u16, unicode::KeyboardFlags)) -> Self {
        if flags.contains(unicode::KeyboardFlags::RELEASE) {
            KeyboardEvent::UnicodeReleased(key)
        } else {
            KeyboardEvent::UnicodePressed(key)
        }
    }
}

impl From<SynchronizeFlags> for KeyboardEvent {
    fn from(value: SynchronizeFlags) -> Self {
        KeyboardEvent::Synchronize(value)
    }
}

impl From<SyncToggleFlags> for KeyboardEvent {
    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        reason = "we are truncating the value on purpose"
    )]
    fn from(value: SyncToggleFlags) -> Self {
        KeyboardEvent::Synchronize(SynchronizeFlags::from_bits_retain(value.bits() as u8))
    }
}

impl From<MousePdu> for MouseEvent {
    fn from(value: MousePdu) -> Self {
        let x = value.x_position;
        let y = value.y_position;
        let pressed = value.flags.contains(PointerFlags::DOWN);

        // Per MS-RDPBCGR 2.2.8.1.2.2.3: "If both PTRFLAGS_WHEEL and
        // PTRFLAGS_HWHEEL are specified, then PTRFLAGS_WHEEL takes
        // precedence." xPos/yPos are spec-defined as unreliable on wheel
        // events ("SHOULD be ignored by the server"), so wheel variants
        // stay position-less rather than carrying this PDU's x/y.
        if value.flags.contains(PointerFlags::VERTICAL_WHEEL) {
            MouseEvent::VerticalScroll {
                value: value.number_of_wheel_rotation_units,
            }
        } else if value.flags.contains(PointerFlags::HORIZONTAL_WHEEL) {
            MouseEvent::HorizontalScroll {
                value: value.number_of_wheel_rotation_units,
            }
        } else if value.flags.contains(PointerFlags::LEFT_BUTTON) {
            MouseEvent::Button {
                x,
                y,
                button: MouseButton::Left,
                pressed,
            }
        } else if value.flags.contains(PointerFlags::RIGHT_BUTTON) {
            MouseEvent::Button {
                x,
                y,
                button: MouseButton::Right,
                pressed,
            }
        } else if value.flags.contains(PointerFlags::MIDDLE_BUTTON_OR_WHEEL) {
            MouseEvent::Button {
                x,
                y,
                button: MouseButton::Middle,
                pressed,
            }
        } else {
            // PTRFLAGS_MOVE, or no recognized flag at all: every reference
            // server implementation studied (FreeRDP, xrdp, KDE krdp, GNOME
            // Remote Desktop) treats this the same way, a move to whatever
            // position the PDU carries.
            MouseEvent::Move { x, y }
        }
    }
}

impl From<MouseXPdu> for MouseEvent {
    fn from(value: MouseXPdu) -> Self {
        let x = value.x_position;
        let y = value.y_position;
        let pressed = value.flags.contains(PointerXFlags::DOWN);

        // Per MS-RDPBCGR 2.2.8.1.2.2.4: PTRXFLAGS_BUTTON1 is "Extended mouse
        // button 1 (also referred to as button 4)", PTRXFLAGS_BUTTON2 is
        // "Extended mouse button 2 (also referred to as button 5)" — the
        // X1/X2 side buttons, not primary left/right. This PDU's pointerFlags
        // carries no other semantics (no move/wheel bits exist for it), so
        // the fallback genuinely always means Move, unlike MousePdu.
        if value.flags.contains(PointerXFlags::BUTTON1) {
            MouseEvent::Button {
                x,
                y,
                button: MouseButton::X1,
                pressed,
            }
        } else if value.flags.contains(PointerXFlags::BUTTON2) {
            MouseEvent::Button {
                x,
                y,
                button: MouseButton::X2,
                pressed,
            }
        } else {
            MouseEvent::Move { x, y }
        }
    }
}

impl From<MouseRelPdu> for MouseEvent {
    fn from(value: MouseRelPdu) -> Self {
        // Per MS-RDPBCGR 2.2.8.1.1.3.1.1.7, xDelta/yDelta are present on every
        // relative event, including button events: PTRFLAGS_DOWN is defined as
        // the press occurring at the position produced by applying this same
        // delta to the previous position. So a button flag never discards it.
        let x = value.x_delta.into();
        let y = value.y_delta.into();
        let pressed = value.flags.contains(PointerRelFlags::DOWN);

        if value.flags.contains(PointerRelFlags::BUTTON1) {
            MouseEvent::ButtonRel {
                x,
                y,
                button: MouseButton::Left,
                pressed,
            }
        } else if value.flags.contains(PointerRelFlags::BUTTON2) {
            MouseEvent::ButtonRel {
                x,
                y,
                button: MouseButton::Right,
                pressed,
            }
        } else if value.flags.contains(PointerRelFlags::BUTTON3) {
            MouseEvent::ButtonRel {
                x,
                y,
                button: MouseButton::Middle,
                pressed,
            }
        } else if value.flags.contains(PointerRelFlags::XBUTTON1) {
            MouseEvent::ButtonRel {
                x,
                y,
                button: MouseButton::X1,
                pressed,
            }
        } else if value.flags.contains(PointerRelFlags::XBUTTON2) {
            MouseEvent::ButtonRel {
                x,
                y,
                button: MouseButton::X2,
                pressed,
            }
        } else {
            // PTRRELFLAGS_MOVE, or no recognized flag: a relative delta is
            // additive rather than a teleport, so applying whatever delta
            // the PDU carries is a safe default even for an unrecognized
            // flag combination.
            MouseEvent::RelMove { x, y }
        }
    }
}

impl From<ainput::MousePdu> for MouseEvent {
    fn from(value: ainput::MousePdu) -> Self {
        use ainput::MouseEventFlags;

        // Unlike MousePdu/MouseXPdu, this PDU carries x/y on every event
        // regardless of which flag is set, including button events — so
        // buttons get position here too, not just Move.
        let pos = || -> (u16, u16) {
            // assume positions are 0 <= u16::MAX
            (value.x.try_into().unwrap_or(0), value.y.try_into().unwrap_or(0))
        };
        let pressed = value.flags.contains(MouseEventFlags::DOWN);

        if value.flags.contains(MouseEventFlags::BUTTON1) {
            let (x, y) = pos();
            MouseEvent::Button {
                x,
                y,
                button: MouseButton::Left,
                pressed,
            }
        } else if value.flags.contains(MouseEventFlags::BUTTON2) {
            let (x, y) = pos();
            MouseEvent::Button {
                x,
                y,
                button: MouseButton::Right,
                pressed,
            }
        } else if value.flags.contains(MouseEventFlags::BUTTON3) {
            let (x, y) = pos();
            MouseEvent::Button {
                x,
                y,
                button: MouseButton::Middle,
                pressed,
            }
        } else if value.flags.contains(MouseEventFlags::WHEEL) {
            MouseEvent::Scroll { x: value.x, y: value.y }
        } else if value.flags.contains(MouseEventFlags::REL) {
            MouseEvent::RelMove { x: value.x, y: value.y }
        } else if value.flags.contains(MouseEventFlags::MOVE) {
            let (x, y) = pos();
            MouseEvent::Move { x, y }
        } else {
            MouseEvent::Move { x: 0, y: 0 }
        }
    }
}

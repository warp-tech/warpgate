//! Translation of normalised desktop input into IronRDP input operations.

use ironrdp::input::{MouseButton, MousePosition, Operation, Scancode, WheelRotations};
use warpgate_core::DesktopInput;

/// RDP expresses wheel movement in rotation units; one notch is 120 of them.
const WHEEL_UNITS_PER_NOTCH: i16 = 120;

/// Append the IronRDP operations for one input event. Events RDP has no equivalent for
/// (clipboard, refresh) produce nothing.
pub fn translate(input: DesktopInput, ops: &mut Vec<Operation>) {
    match input {
        DesktopInput::Pointer { x, y, buttons } => {
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
        DesktopInput::Wheel {
            vertical, delta, ..
        } => {
            ops.push(Operation::WheelRotations(WheelRotations {
                is_vertical: vertical,
                rotation_units: delta.saturating_mul(WHEEL_UNITS_PER_NOTCH),
            }));
        }
        DesktopInput::Scancode {
            code,
            extended,
            down,
        } => {
            // Native RDP viewers already send PC/AT scancodes; forward them verbatim
            // (no keysym round-trip) so every key — including layout-dependent ones — is
            // delivered to the target exactly as typed.
            let scancode = Scancode::from_u8(extended, code);
            ops.push(if down {
                Operation::KeyPressed(scancode)
            } else {
                Operation::KeyReleased(scancode)
            });
        }
        DesktopInput::Key { keysym, down } => {
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
        DesktopInput::Clipboard(_) | DesktopInput::Refresh => {}
    }
}

/// Maps an X11 keysym (as produced by the browser client) to a US-layout PC/AT
/// scancode (set 1 "make" code) so modifier combinations work. Returns
/// `(extended, code)`.
fn keysym_to_scancode(keysym: u32) -> Option<(bool, u8)> {
    // X11 function/control keysyms (0xff..)
    let special = match keysym {
        0xff08 => (false, 0x0E),                                    // Backspace
        0xff09 => (false, 0x0F),                                    // Tab
        0xff0d => (false, 0x1C),                                    // Enter
        0xff1b => (false, 0x01),                                    // Escape
        0xffff => (true, 0x53),                                     // Delete
        0xff50 => (true, 0x47),                                     // Home
        0xff51 => (true, 0x4B),                                     // Left
        0xff52 => (true, 0x48),                                     // Up
        0xff53 => (true, 0x4D),                                     // Right
        0xff54 => (true, 0x50),                                     // Down
        0xff55 => (true, 0x49),                                     // PageUp
        0xff56 => (true, 0x51),                                     // PageDown
        0xff57 => (true, 0x4F),                                     // End
        0xff63 => (true, 0x52),                                     // Insert
        0xffe1 => (false, 0x2A),                                    // Shift
        0xffe3 => (false, 0x1D),                                    // Control
        0xffe9 => (false, 0x38),                                    // Alt
        0xffe5 => (false, 0x3A),                                    // CapsLock
        0xffbe..=0xffc7 => (false, 0x3B + (keysym - 0xffbe) as u8), // F1..F10
        0xffc8 => (false, 0x57),                                    // F11
        0xffc9 => (false, 0x58),                                    // F12
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

// Decoding viewer-input recording items into human-readable key labels and click
// positions, for the recording player's live-input overlay. Keyboard input arrives
// two ways: X11 keysyms (VNC path) and raw PC/AT set-1 scancodes (native RDP path).

// Hex keys are intentional (they mirror the wire values); quoting them would change
// the property name, so keep them as numeric literals.
/* eslint-disable quote-props */

export interface KeyPress {
    time: number
    label: string
}
export interface Click {
    time: number
    x: number
    y: number
}

// Named X11 keysyms (non-printable keys). Printable Latin-1 keysyms equal their
// Unicode code point, so they fall through to `String.fromCharCode` below.
const KEYSYM_NAMES: Record<number, string> = {
    0x20: 'Space',
    0xff08: 'Backspace',
    0xff09: 'Tab',
    0xff0d: 'Enter',
    0xff1b: 'Esc',
    0xff50: 'Home',
    0xff51: '←',
    0xff52: '↑',
    0xff53: '→',
    0xff54: '↓',
    0xff55: 'PgUp',
    0xff56: 'PgDn',
    0xff57: 'End',
    0xff63: 'Insert',
    0xffff: 'Delete',
    0xffe1: 'Shift',
    0xffe2: 'Shift',
    0xffe3: 'Ctrl',
    0xffe4: 'Ctrl',
    0xffe5: 'CapsLock',
    0xffe9: 'Alt',
    0xffea: 'Alt',
    0xffeb: 'Super',
    0xffec: 'Super',
    0xffbe: 'F1',
    0xffbf: 'F2',
    0xffc0: 'F3',
    0xffc1: 'F4',
    0xffc2: 'F5',
    0xffc3: 'F6',
    0xffc4: 'F7',
    0xffc5: 'F8',
    0xffc6: 'F9',
    0xffc7: 'F10',
    0xffc8: 'F11',
    0xffc9: 'F12',
}

export function keysymLabel(keysym: number): string {
    const named = KEYSYM_NAMES[keysym]
    if (named) {
        return named
    }
    if (keysym >= 0x21 && keysym <= 0xff) {
        return String.fromCharCode(keysym)
    }
    // Native RDP sends Unicode code points on its key path.
    try {
        const s = String.fromCodePoint(keysym)
        if (s.trim()) {
            return s
        }
    } catch {
        /* invalid code point */
    }
    return `0x${keysym.toString(16)}`
}

// PC/AT set-1 "make" codes. The nav cluster (arrows/Home/End/…) shares codes with
// the keypad; the `extended` flag disambiguates, but the labels are the same either
// way, so we don't need it here.
const SCANCODE_NAMES: Record<number, string> = {
    0x01: 'Esc',
    0x02: '1',
    0x03: '2',
    0x04: '3',
    0x05: '4',
    0x06: '5',
    0x07: '6',
    0x08: '7',
    0x09: '8',
    0x0a: '9',
    0x0b: '0',
    0x0c: '-',
    0x0d: '=',
    0x0e: 'Backspace',
    0x0f: 'Tab',
    0x10: 'Q',
    0x11: 'W',
    0x12: 'E',
    0x13: 'R',
    0x14: 'T',
    0x15: 'Y',
    0x16: 'U',
    0x17: 'I',
    0x18: 'O',
    0x19: 'P',
    0x1a: '[',
    0x1b: ']',
    0x1c: 'Enter',
    0x1d: 'Ctrl',
    0x1e: 'A',
    0x1f: 'S',
    0x20: 'D',
    0x21: 'F',
    0x22: 'G',
    0x23: 'H',
    0x24: 'J',
    0x25: 'K',
    0x26: 'L',
    0x27: ';',
    0x28: "'",
    0x29: '`',
    0x2a: 'Shift',
    0x2b: '\\',
    0x2c: 'Z',
    0x2d: 'X',
    0x2e: 'C',
    0x2f: 'V',
    0x30: 'B',
    0x31: 'N',
    0x32: 'M',
    0x33: ',',
    0x34: '.',
    0x35: '/',
    0x36: 'Shift',
    0x37: '*',
    0x38: 'Alt',
    0x39: 'Space',
    0x3a: 'CapsLock',
    0x3b: 'F1',
    0x3c: 'F2',
    0x3d: 'F3',
    0x3e: 'F4',
    0x3f: 'F5',
    0x40: 'F6',
    0x41: 'F7',
    0x42: 'F8',
    0x43: 'F9',
    0x44: 'F10',
    0x57: 'F11',
    0x58: 'F12',
    0x45: 'NumLock',
    0x46: 'ScrollLock',
    0x47: 'Home',
    0x48: '↑',
    0x49: 'PgUp',
    0x4b: '←',
    0x4d: '→',
    0x4f: 'End',
    0x50: '↓',
    0x51: 'PgDn',
    0x52: 'Insert',
    0x53: 'Delete',
}

export function scancodeLabel(code: number): string {
    return SCANCODE_NAMES[code] ?? `0x${code.toString(16)}`
}

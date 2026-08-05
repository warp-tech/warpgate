// Decoding viewer-input recording items into human-readable key labels and click
// positions, for the recording player's live-input overlay. Keyboard input arrives
// two ways: X11 keysyms (VNC path) and raw PC/AT set-1 scancodes (native RDP path).

// Hex keys are intentional (they mirror the wire values); quoting them would change
// the property name, so keep them as numeric literals.

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
    32: 'Space',
    65288: 'Backspace',
    65289: 'Tab',
    65293: 'Enter',
    65307: 'Esc',
    65360: 'Home',
    65361: '←',
    65362: '↑',
    65363: '→',
    65364: '↓',
    65365: 'PgUp',
    65366: 'PgDn',
    65367: 'End',
    65379: 'Insert',
    65535: 'Delete',
    65505: 'Shift',
    65506: 'Shift',
    65507: 'Ctrl',
    65508: 'Ctrl',
    65509: 'CapsLock',
    65513: 'Alt',
    65514: 'Alt',
    65515: 'Super',
    65516: 'Super',
    65470: 'F1',
    65471: 'F2',
    65472: 'F3',
    65473: 'F4',
    65474: 'F5',
    65475: 'F6',
    65476: 'F7',
    65477: 'F8',
    65478: 'F9',
    65479: 'F10',
    65480: 'F11',
    65481: 'F12',
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
    1: 'Esc',
    2: '1',
    3: '2',
    4: '3',
    5: '4',
    6: '5',
    7: '6',
    8: '7',
    9: '8',
    10: '9',
    11: '0',
    12: '-',
    13: '=',
    14: 'Backspace',
    15: 'Tab',
    16: 'Q',
    17: 'W',
    18: 'E',
    19: 'R',
    20: 'T',
    21: 'Y',
    22: 'U',
    23: 'I',
    24: 'O',
    25: 'P',
    26: '[',
    27: ']',
    28: 'Enter',
    29: 'Ctrl',
    30: 'A',
    31: 'S',
    32: 'D',
    33: 'F',
    34: 'G',
    35: 'H',
    36: 'J',
    37: 'K',
    38: 'L',
    39: ';',
    40: "'",
    41: '`',
    42: 'Shift',
    43: '\\',
    44: 'Z',
    45: 'X',
    46: 'C',
    47: 'V',
    48: 'B',
    49: 'N',
    50: 'M',
    51: ',',
    52: '.',
    53: '/',
    54: 'Shift',
    55: '*',
    56: 'Alt',
    57: 'Space',
    58: 'CapsLock',
    59: 'F1',
    60: 'F2',
    61: 'F3',
    62: 'F4',
    63: 'F5',
    64: 'F6',
    65: 'F7',
    66: 'F8',
    67: 'F9',
    68: 'F10',
    87: 'F11',
    88: 'F12',
    69: 'NumLock',
    70: 'ScrollLock',
    71: 'Home',
    72: '↑',
    73: 'PgUp',
    75: '←',
    77: '→',
    79: 'End',
    80: '↓',
    81: 'PgDn',
    82: 'Insert',
    83: 'Delete',
}

export function scancodeLabel(code: number): string {
    return SCANCODE_NAMES[code] ?? `0x${code.toString(16)}`
}

// `KeyboardEvent.code` -> PC/AT set-1 make code, with the 0xE000 bit standing in for the
// E0 prefix. `code` names the *physical* key regardless of the client's keyboard layout,
// which is exactly what RDP wants on the wire: the target applies its own layout. Keys
// with no set-1 code (media keys, Pause's multi-byte sequence) are absent and fall back
// to keysym input.
const CODE_TO_SCANCODE: Record<string, number> = {
    Escape: 0x01,
    Digit1: 0x02,
    Digit2: 0x03,
    Digit3: 0x04,
    Digit4: 0x05,
    Digit5: 0x06,
    Digit6: 0x07,
    Digit7: 0x08,
    Digit8: 0x09,
    Digit9: 0x0a,
    Digit0: 0x0b,
    Minus: 0x0c,
    Equal: 0x0d,
    Backspace: 0x0e,
    Tab: 0x0f,
    KeyQ: 0x10,
    KeyW: 0x11,
    KeyE: 0x12,
    KeyR: 0x13,
    KeyT: 0x14,
    KeyY: 0x15,
    KeyU: 0x16,
    KeyI: 0x17,
    KeyO: 0x18,
    KeyP: 0x19,
    BracketLeft: 0x1a,
    BracketRight: 0x1b,
    Enter: 0x1c,
    ControlLeft: 0x1d,
    KeyA: 0x1e,
    KeyS: 0x1f,
    KeyD: 0x20,
    KeyF: 0x21,
    KeyG: 0x22,
    KeyH: 0x23,
    KeyJ: 0x24,
    KeyK: 0x25,
    KeyL: 0x26,
    Semicolon: 0x27,
    Quote: 0x28,
    Backquote: 0x29,
    ShiftLeft: 0x2a,
    Backslash: 0x2b,
    KeyZ: 0x2c,
    KeyX: 0x2d,
    KeyC: 0x2e,
    KeyV: 0x2f,
    KeyB: 0x30,
    KeyN: 0x31,
    KeyM: 0x32,
    Comma: 0x33,
    Period: 0x34,
    Slash: 0x35,
    ShiftRight: 0x36,
    NumpadMultiply: 0x37,
    AltLeft: 0x38,
    Space: 0x39,
    CapsLock: 0x3a,
    F1: 0x3b,
    F2: 0x3c,
    F3: 0x3d,
    F4: 0x3e,
    F5: 0x3f,
    F6: 0x40,
    F7: 0x41,
    F8: 0x42,
    F9: 0x43,
    F10: 0x44,
    NumLock: 0x45,
    ScrollLock: 0x46,
    Numpad7: 0x47,
    Numpad8: 0x48,
    Numpad9: 0x49,
    NumpadSubtract: 0x4a,
    Numpad4: 0x4b,
    Numpad5: 0x4c,
    Numpad6: 0x4d,
    NumpadAdd: 0x4e,
    Numpad1: 0x4f,
    Numpad2: 0x50,
    Numpad3: 0x51,
    Numpad0: 0x52,
    NumpadDecimal: 0x53,
    // The extra key ISO keyboards fit next to the left Shift — `<>` on AZERTY.
    IntlBackslash: 0x56,
    F11: 0x57,
    F12: 0x58,
    IntlRo: 0x73,
    IntlYen: 0x7d,
    NumpadEnter: 0xe01c,
    ControlRight: 0xe01d,
    NumpadDivide: 0xe035,
    PrintScreen: 0xe037,
    AltRight: 0xe038,
    Home: 0xe047,
    ArrowUp: 0xe048,
    PageUp: 0xe049,
    ArrowLeft: 0xe04b,
    ArrowRight: 0xe04d,
    End: 0xe04f,
    ArrowDown: 0xe050,
    PageDown: 0xe051,
    Insert: 0xe052,
    Delete: 0xe053,
    MetaLeft: 0xe05b,
    MetaRight: 0xe05c,
    ContextMenu: 0xe05d,
}

export interface Scancode {
    code: number
    extended: boolean
}

export function codeToScancode(code: string): Scancode | null {
    const value = CODE_TO_SCANCODE[code]
    if (value === undefined) {
        return null
    }
    return { code: value & 0xff, extended: (value & 0xe000) !== 0 }
}

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

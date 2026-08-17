// Bidirectional clipboard sync for the web desktop viewer.
//
// Remote -> local: text the target copied is written to the local clipboard.
// Local -> remote: the browser's `paste` event is the only way to read the local
// clipboard without a permission prompt, so the platform paste combo is left
// alone in the key handler and replayed as a synthesised Ctrl+V after the text
// has been forwarded.

export interface SyntheticKey {
    keysym: number
    scancode: number
    extended: boolean
}

const CONTROL_KEY: SyntheticKey = {
    keysym: 0xffe3,
    scancode: 0x1d,
    extended: false,
}
const V_KEY: SyntheticKey = { keysym: 0x76, scancode: 0x2f, extended: false }
// Left Win / Super.
const META_KEY: SyntheticKey = {
    keysym: 0xffeb,
    scancode: 0x5b,
    extended: true,
}

export class DesktopClipboard {
    // Only the platform's own paste combo is intercepted: it is the one the browser
    // turns into a `paste` event, and the others (Ctrl+V on a Mac) must keep reaching
    // the remote as plain keystrokes.
    private readonly isMac = /Mac|iPhone|iPad/.test(navigator.platform)

    // Whether the viewer physically holds Ctrl/Meta. Their keydowns were forwarded, so
    // the remote holds them too — `onPaste` has to account for that when it synthesises
    // its own keystrokes.
    private controlHeld = false
    private metaHeld = false

    // Text the target copied that isn't written to the local clipboard yet: the write
    // can fail outside a user gesture or while the document is unfocused (notably in
    // Firefox), so it is retried on subsequent input until it lands.
    private pendingRemoteText: string | null = null

    constructor(
        private readonly sendText: (text: string) => void,
        private readonly sendKey: (key: SyntheticKey, down: boolean) => void,
    ) {}

    // Text the target copied, from the server's `clipboard` message.
    onRemoteCopy(text: string): void {
        this.pendingRemoteText = text
        this.flush()
    }

    // Retry the pending remote->local write; called on local user gestures, which is
    // when the browser lets `writeText` succeed.
    flush(): void {
        const text = this.pendingRemoteText
        if (text === null) {
            return
        }
        navigator.clipboard
            ?.writeText(text)
            .then(() => {
                if (this.pendingRemoteText === text) {
                    this.pendingRemoteText = null
                }
            })
            .catch(() => {})
    }

    // Tracks held modifiers (and retries the write-back); call for every key event
    // before deciding whether to forward it.
    onKey(e: KeyboardEvent, down: boolean): void {
        if (down) {
            this.flush()
        }
        if (e.key === 'Control') {
            this.controlHeld = down
        }
        if (e.key === 'Meta') {
            this.metaHeld = down
        }
    }

    // Modifier keyups are missed while the window is unfocused; a stale flag would
    // make `onPaste` leave a synthesised Ctrl held down on the remote.
    onBlur(): void {
        this.controlHeld = false
        this.metaHeld = false
    }

    // Whether this event is the platform paste combo, which must be left alone —
    // neither forwarded nor preventDefault-ed — so the browser still fires its own
    // `paste`. Matched both by position and by resolved key: Cyrillic-style layouts
    // trigger paste positionally (`key` is a non-Latin letter), while on Dvorak-style
    // layouts the resolved letter sits on a different physical key (`code` differs).
    isPasteCombo(e: KeyboardEvent): boolean {
        return (
            (this.isMac ? e.metaKey : e.ctrlKey) &&
            (e.code === 'KeyV' || e.key.toLowerCase() === 'v')
        )
    }

    // Local -> remote clipboard sync. The text goes first and its order against the
    // keystroke is preserved all the way to the target, so the remote has it before the
    // paste arrives — forwarding the keystroke as it happened would paste whatever the
    // remote held previously.
    onPaste(e: ClipboardEvent): void {
        e.preventDefault()
        const text = e.clipboardData?.getData('text/plain')
        // Local text matching the pending write-back is the target's own copy coming
        // straight back — the target already holds it, so just replay the keystroke.
        // Different text means the viewer copied something newer locally (which also
        // makes the write-back stale), and either way the write-back is settled: drop
        // it so a browser that never lets `writeText` succeed can't wedge forwarding.
        // No text at all (empty clipboard, an image) also just replays the keystroke,
        // pasting whatever the target holds.
        if (text) {
            if (text !== this.pendingRemoteText) {
                this.sendText(text)
            }
            this.pendingRemoteText = null
        }
        this.flush()
        // Synthesised, not forwarded: a macOS viewer pressed Cmd+V, and the target's
        // paste shortcut is Ctrl+V regardless of what the viewer runs.
        this.sendKey(CONTROL_KEY, true)
        // A held Cmd was forwarded as the Win key; release it after Ctrl goes down (a
        // bare Win press-and-release opens the Start menu) so the target sees a clean
        // Ctrl+V rather than Win+Ctrl+V. Its real keyup later is a harmless repeat.
        if (this.metaHeld) {
            this.sendKey(META_KEY, false)
        }
        this.sendKey(V_KEY, true)
        this.sendKey(V_KEY, false)
        // A physically held Ctrl is released by its own forwarded keyup instead.
        if (!this.controlHeld) {
            this.sendKey(CONTROL_KEY, false)
        }
    }
}

pub const fn sane_terminal_size(cols: u16, rows: u16) -> (u16, u16) {
    (
        if cols < 2 { 80 } else { cols },
        if rows < 2 { 24 } else { rows },
    )
}

/// Headless VT that can make snapshots
pub struct TerminalScreen {
    parser: vt100::Parser,
}

impl Default for TerminalScreen {
    fn default() -> Self {
        Self::new(80, 24)
    }
}

impl TerminalScreen {
    pub fn new(cols: u16, rows: u16) -> Self {
        let (cols, rows) = sane_terminal_size(cols, rows);
        Self {
            parser: vt100::Parser::new(rows, cols, 0),
        }
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.parser.process(data);
    }

    pub fn resize(&mut self, cols: u16, rows: u16) {
        let (cols, rows) = sane_terminal_size(cols, rows);
        self.parser.set_size(rows, cols);
    }

    pub fn snapshot(&self) -> Vec<u8> {
        let screen = self.parser.screen();
        let mut out = Vec::new();
        if screen.alternate_screen() {
            // state_formatted() output does not include this alt mode switch
            out.extend_from_slice(b"\x1b[?1049h");
        }
        out.extend_from_slice(&screen.state_formatted());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn restored(snapshot: &[u8], cols: u16, rows: u16) -> TerminalScreen {
        let mut restored = TerminalScreen::new(cols, rows);
        restored.feed(snapshot);
        restored
    }

    fn contents(screen: &TerminalScreen) -> String {
        screen.parser.screen().contents()
    }

    #[test]
    fn snapshot_reproduces_the_screen() {
        let mut screen = TerminalScreen::new(80, 24);
        screen.feed(b"hello\r\n\x1b[31mworld\x1b[0m\r\nthird line");
        let restored = restored(&screen.snapshot(), 80, 24);
        assert_eq!(contents(&restored), contents(&screen));
        assert!(contents(&restored).contains("world"));
    }

    #[test]
    fn snapshot_reproduces_the_screen_after_a_resize() {
        let mut screen = TerminalScreen::new(80, 24);
        screen.feed(b"before resize\r\n");
        screen.resize(100, 40);
        screen.feed(b"after resize");
        let restored = restored(&screen.snapshot(), 100, 40);
        assert_eq!(contents(&restored), contents(&screen));
    }

    #[test]
    fn alternate_screen_snapshot_restores_into_alternate_mode() {
        let mut screen = TerminalScreen::new(80, 24);
        screen.feed(b"shell output\r\n");
        screen.feed(b"\x1b[?1049hfullscreen app");
        let restored = restored(&screen.snapshot(), 80, 24);
        assert!(restored.parser.screen().alternate_screen());
        assert_eq!(contents(&restored), contents(&screen));
        assert!(contents(&restored).contains("fullscreen app"));
    }

    #[test]
    fn degenerate_size_does_not_panic() {
        let mut screen = TerminalScreen::new(0, 0);
        screen.feed(b"still fine");
        screen.resize(0, 0);
        assert!(!screen.snapshot().is_empty());
    }
}

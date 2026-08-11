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

    pub fn snapshot(&self) -> Option<Vec<u8>> {
        let screen = self.parser.screen();
        (!screen.alternate_screen()).then(|| screen.state_formatted())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn restored(snapshot: &[u8], cols: u16, rows: u16) -> String {
        let mut restored = TerminalScreen::new(cols, rows);
        restored.feed(snapshot);
        restored.parser.screen().contents()
    }

    #[test]
    fn snapshot_reproduces_the_screen() {
        let mut screen = TerminalScreen::new(80, 24);
        screen.feed(b"hello\r\n\x1b[31mworld\x1b[0m\r\nthird line");
        let snapshot = screen.snapshot().expect("restorable");
        assert_eq!(
            restored(&snapshot, 80, 24),
            screen.parser.screen().contents()
        );
        assert!(restored(&snapshot, 80, 24).contains("world"));
    }

    #[test]
    fn snapshot_reproduces_the_screen_after_a_resize() {
        let mut screen = TerminalScreen::new(80, 24);
        screen.feed(b"before resize\r\n");
        screen.resize(100, 40);
        screen.feed(b"after resize");
        let snapshot = screen.snapshot().expect("restorable");
        assert_eq!(
            restored(&snapshot, 100, 40),
            screen.parser.screen().contents()
        );
    }

    #[test]
    fn alternate_screen_has_no_restorable_snapshot() {
        let mut screen = TerminalScreen::new(80, 24);
        screen.feed(b"shell output\r\n");
        assert!(screen.snapshot().is_some());
        screen.feed(b"\x1b[?1049h");
        assert!(screen.snapshot().is_none());
        screen.feed(b"\x1b[?1049l");
        assert!(screen.snapshot().is_some());
    }

    #[test]
    fn degenerate_size_does_not_panic() {
        let mut screen = TerminalScreen::new(0, 0);
        screen.feed(b"still fine");
        screen.resize(0, 0);
        assert!(screen.snapshot().is_some());
    }
}

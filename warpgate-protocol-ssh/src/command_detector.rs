//! Heuristic recovery of shell commands from an interactive PTY byte stream.
//!
//! Warpgate only sees opaque terminal traffic, so there are no command
//! boundaries to read directly. Rather than reconstruct commands from
//! keystrokes — which is unreliable the moment the user touches arrow keys,
//! history recall, or tab completion — we drive a headless terminal emulator
//! from the *output* stream and read the fully-echoed command line straight
//! off the emulated screen when the user submits it. Every kind of line
//! editing is thereby handled for free, because we read the *result* of the
//! shell's own echo, not the individual edits.
//!
//! The input stream is used only to locate the prompt boundary and to spot
//! Enter and Ctrl-C — never for text content.
//!
//! This is an audit aid, not a security boundary: a determined user can defeat
//! any stream-derived logging. Known heuristic limitations, all exercised by
//! the tests below:
//! - Input into a main-screen REPL (python, psql, …) is logged as a command.
//! - Multi-command paste in a single burst captures only the first command.
//! - A command that wraps past the bottom of the screen may be skipped.

const CR: u8 = 0x0d;
const LF: u8 = 0x0a;
const ETX: u8 = 0x03; // Ctrl-C

/// Once a command is submitted, stop waiting for the terminating newline after
/// this many output bytes, so a shell that never echoes one cannot wedge the
/// detector on a single line forever.
const MAX_PENDING_OUTPUT: usize = 2048;

const fn sane_size(cols: u16, rows: u16) -> (u16, u16) {
    (
        if cols < 2 { 80 } else { cols },
        if rows < 2 { 24 } else { rows },
    )
}

#[derive(Clone, Copy)]
enum State {
    /// Before the target has produced any output. Input is ignored so that
    /// pre-prompt typeahead cannot seed a bogus prompt boundary.
    Idle,
    /// At or after a prompt, with no line edit in progress.
    Output,
    /// The user is editing a command line. `row`/`col` mark the cell where the
    /// prompt ends and typed input begins.
    Editing { row: u16, col: u16 },
    /// Enter was pressed; waiting for the shell to echo the line terminator
    /// that guarantees the whole command has finished rendering.
    Submitted { row: u16, col: u16, scanned: usize },
    /// A resize invalidated the saved prompt boundary while the user was
    /// editing. Ignore the rest of this line rather than logging a suffix.
    Discarding,
    /// The invalidated line was submitted; waiting for its output terminator
    /// before detecting commands again.
    Discarded { scanned: usize },
}

pub struct CommandDetector {
    parser: vt100::Parser,
    state: State,
}

impl CommandDetector {
    pub fn new(cols: u16, rows: u16) -> Self {
        let (cols, rows) = sane_size(cols, rows);
        Self {
            parser: vt100::Parser::new(rows, cols, 0),
            state: State::Idle,
        }
    }

    pub fn on_resize(&mut self, cols: u16, rows: u16) {
        let (cols, rows) = sane_size(cols, rows);
        self.parser.set_size(rows, cols);
        self.state = match self.state {
            State::Editing { .. } => State::Discarding,
            State::Submitted { scanned, .. } => State::Discarded { scanned },
            state => state,
        };
    }

    /// Feed client keystrokes. Drives state transitions only; input bytes are
    /// never rendered (the target echoes them back through `on_output`).
    pub fn on_input(&mut self, data: &[u8]) {
        for &b in data {
            match self.state {
                State::Idle | State::Submitted { .. } | State::Discarded { .. } => {}
                State::Output => {
                    if !self.parser.screen().alternate_screen() {
                        let (row, col) = self.parser.screen().cursor_position();
                        self.state = State::Editing { row, col };
                        self.step_input(b);
                    }
                }
                State::Editing { .. } | State::Discarding => self.step_input(b),
            }
        }
    }

    /// Feed target output. Returns a command when one has just been submitted
    /// and fully rendered.
    #[must_use]
    pub fn on_output(&mut self, data: &[u8]) -> Option<String> {
        if matches!(self.state, State::Idle) {
            self.state = State::Output;
        }

        if let State::Discarded { scanned } = self.state {
            self.parser.process(data);
            let scanned = scanned.saturating_add(data.len());
            if data.iter().any(|&b| b == LF || b == CR)
                || self.parser.screen().alternate_screen()
                || scanned >= MAX_PENDING_OUTPUT
            {
                self.state = State::Output;
            } else {
                self.state = State::Discarded { scanned };
            }
            return None;
        }

        let State::Submitted { row, col, scanned } = self.state else {
            self.parser.process(data);
            return None;
        };

        // The client's Enter can arrive before the target has echoed the tail
        // of the line, so we don't snapshot at Enter. The shell echoes the
        // Enter as CR/LF only after echoing everything before it, so the first
        // CR or LF in the output stream is the point at which the whole command
        // is guaranteed rendered.
        if let Some(p) = data.iter().position(|&b| b == LF || b == CR) {
            let (before, after) = data.split_at(p);
            self.parser.process(before);
            let command = self.extract(row, col);
            self.parser.process(after);
            self.state = State::Output;
            return command;
        }

        self.parser.process(data);
        let scanned = scanned.saturating_add(data.len());

        // A full-screen app (vim/less/…) launched by the command switches to
        // the alternate screen before any newline; give up rather than read the
        // alternate buffer.
        if self.parser.screen().alternate_screen() {
            self.state = State::Output;
            return None;
        }

        if scanned >= MAX_PENDING_OUTPUT {
            let command = self.extract(row, col);
            self.state = State::Output;
            return command;
        }

        self.state = State::Submitted { row, col, scanned };
        None
    }

    const fn step_input(&mut self, b: u8) {
        match self.state {
            State::Editing { .. } if b == ETX => {
                self.state = State::Output;
            }
            State::Editing { row, col } if b == CR || b == LF => {
                self.state = State::Submitted {
                    row,
                    col,
                    scanned: 0,
                };
            }
            State::Discarding if b == ETX || b == CR || b == LF => {
                self.state = State::Discarded { scanned: 0 };
            }
            _ => {}
        }
    }

    /// Read the typed text between the prompt boundary and the cursor. The
    /// prompt (before `col`) and any zsh RPROMPT (right of the cursor) fall
    /// outside the range; soft-wrapped continuation rows are joined without a
    /// newline. A password prompt echoes nothing, so the range is empty.
    fn extract(&self, row: u16, col: u16) -> Option<String> {
        let screen = self.parser.screen();
        let (cur_row, cur_col) = screen.cursor_position();
        if cur_row < row || (cur_row == row && cur_col <= col) {
            return None;
        }
        let text = screen.contents_between(row, col, cur_row, cur_col);
        let trimmed = text.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive a prompt appearing on screen (positions the cursor).
    fn prompt(d: &mut CommandDetector, s: &str) {
        assert!(d.on_output(s.as_bytes()).is_none());
    }

    /// Simulate the user typing `s`, with the shell echoing it verbatim.
    fn typed(d: &mut CommandDetector, s: &str) {
        d.on_input(s.as_bytes());
        assert!(d.on_output(s.as_bytes()).is_none());
    }

    /// Simulate pressing Enter: the shell echoes CR/LF, finalizing the line.
    fn enter(d: &mut CommandDetector) -> Option<String> {
        d.on_input(b"\r");
        d.on_output(b"\r\n")
    }

    #[test]
    fn plain_command() {
        let mut d = CommandDetector::new(80, 24);
        prompt(&mut d, "user@host:~$ ");
        typed(&mut d, "ls -la");
        assert_eq!(enter(&mut d).as_deref(), Some("ls -la"));
    }

    #[test]
    fn empty_enter_emits_nothing() {
        let mut d = CommandDetector::new(80, 24);
        prompt(&mut d, "$ ");
        assert_eq!(enter(&mut d), None);
    }

    #[test]
    fn degenerate_pty_size_does_not_panic() {
        // A 0x0 pty-req (e.g. an `expect` spawn with no controlling tty) must
        // not build an emulator small enough to underflow vt100 on wrapping
        // output — under release `panic = "abort"` that aborts the whole
        // process. The detector falls back to 80x24 and still works.
        let mut d = CommandDetector::new(0, 0);
        prompt(&mut d, "user@host:~$ ");
        typed(&mut d, "echo hello world");
        assert_eq!(enter(&mut d).as_deref(), Some("echo hello world"));
        d.on_resize(0, 0);
        prompt(&mut d, "user@host:~$ ");
        typed(&mut d, "id");
        assert_eq!(enter(&mut d).as_deref(), Some("id"));
    }

    #[test]
    fn input_before_output_is_ignored() {
        let mut d = CommandDetector::new(80, 24);
        // Typeahead before the first prompt must not seed a boundary.
        d.on_input(b"whoami\r");
        prompt(&mut d, "$ ");
        typed(&mut d, "id");
        assert_eq!(enter(&mut d).as_deref(), Some("id"));
    }

    #[test]
    fn history_recall_reads_the_final_line() {
        let mut d = CommandDetector::new(80, 24);
        prompt(&mut d, "$ ");
        // Up-arrow: input carries only an escape sequence; the recalled command
        // appears purely as echoed output.
        d.on_input(b"\x1b[A");
        assert!(d.on_output(b"git status").is_none());
        assert_eq!(enter(&mut d).as_deref(), Some("git status"));
    }

    #[test]
    fn tab_completion_reads_the_expanded_line() {
        let mut d = CommandDetector::new(80, 24);
        prompt(&mut d, "$ ");
        // User types "gi\t"; the shell echoes the expansion.
        d.on_input(b"gi\t");
        assert!(d.on_output(b"git ").is_none());
        typed(&mut d, "log");
        assert_eq!(enter(&mut d).as_deref(), Some("git log"));
    }

    #[test]
    fn backspace_editing_reads_corrected_line() {
        let mut d = CommandDetector::new(80, 24);
        prompt(&mut d, "$ ");
        typed(&mut d, "sl");
        // Two backspaces: shell moves left and clears to end of line.
        d.on_input(b"\x7f\x7f");
        assert!(d.on_output(b"\x08\x08\x1b[K").is_none());
        typed(&mut d, "ls");
        assert_eq!(enter(&mut d).as_deref(), Some("ls"));
    }

    #[test]
    fn rprompt_is_excluded() {
        let mut d = CommandDetector::new(80, 24);
        prompt(&mut d, "$ ");
        typed(&mut d, "date");
        // zsh RPROMPT is painted to the right of the cursor before Enter.
        assert!(d.on_output(b"\x1b7\x1b[75G12:00\x1b8").is_none());
        assert_eq!(enter(&mut d).as_deref(), Some("date"));
    }

    #[test]
    fn enter_before_echo_and_split_newline() {
        let mut d = CommandDetector::new(80, 24);
        prompt(&mut d, "$ ");
        // Whole burst (command + Enter) arrives on input before any echo.
        d.on_input(b"ls\r");
        // Echo of the command arrives first, without a terminator yet.
        assert!(d.on_output(b"ls").is_none());
        // The terminating newline arrives in a later chunk.
        assert_eq!(d.on_output(b"\r\n").as_deref(), Some("ls"));
    }

    #[test]
    fn wrapped_long_command_is_joined() {
        let mut d = CommandDetector::new(10, 24);
        prompt(&mut d, "$ ");
        // 8 + 8 chars wrap across the 10-column screen with no hard newline.
        typed(&mut d, "echo abc");
        typed(&mut d, "defghij");
        assert_eq!(enter(&mut d).as_deref(), Some("echo abcdefghij"));
    }

    #[test]
    fn password_prompt_emits_nothing() {
        let mut d = CommandDetector::new(80, 24);
        prompt(&mut d, "$ ");
        typed(&mut d, "sudo id");
        assert_eq!(enter(&mut d).as_deref(), Some("sudo id"));
        // sudo prints a prompt, then reads the password without echoing it.
        assert!(d.on_output(b"[sudo] password for user: ").is_none());
        d.on_input(b"hunter2\r");
        assert_eq!(d.on_output(b"\r\n"), None);
    }

    #[test]
    fn ctrl_c_discards() {
        let mut d = CommandDetector::new(80, 24);
        prompt(&mut d, "$ ");
        typed(&mut d, "rm -rf /");
        d.on_input(b"\x03");
        assert!(d.on_output(b"^C\r\n").is_none());
        prompt(&mut d, "$ ");
        typed(&mut d, "ls");
        assert_eq!(enter(&mut d).as_deref(), Some("ls"));
    }

    #[test]
    fn alternate_screen_suppresses_detection() {
        let mut d = CommandDetector::new(80, 24);
        prompt(&mut d, "$ ");
        typed(&mut d, "vim");
        assert_eq!(enter(&mut d).as_deref(), Some("vim"));
        // vim switches to the alternate screen.
        assert!(d.on_output(b"\x1b[?1049h").is_none());
        // Keystrokes inside vim, including Enter, must not be captured.
        d.on_input(b"iHello, world\x1b:wq\r");
        assert!(d.on_output(b"redrawing").is_none());
        // Back to the main screen.
        assert!(d.on_output(b"\x1b[?1049l").is_none());
        prompt(&mut d, "$ ");
        typed(&mut d, "pwd");
        assert_eq!(enter(&mut d).as_deref(), Some("pwd"));
    }

    #[test]
    fn runaway_output_without_newline_recovers() {
        let mut d = CommandDetector::new(80, 24);
        prompt(&mut d, "$ ");
        typed(&mut d, "yes");
        d.on_input(b"\r");
        // A shell that submits but never echoes a terminating newline must not
        // wedge the detector: a best-effort capture fires and returns to Output.
        let mut emitted = None;
        for _ in 0..40 {
            if let Some(c) = d.on_output(&[b'y'; 100]) {
                emitted = Some(c);
                break;
            }
        }
        assert!(emitted.is_some());
        // The next command is still detected cleanly.
        prompt(&mut d, "\r\n$ ");
        typed(&mut d, "ls");
        assert_eq!(enter(&mut d).as_deref(), Some("ls"));
    }

    #[test]
    fn resize_between_commands_preserves_detection() {
        let mut d = CommandDetector::new(80, 24);
        prompt(&mut d, "$ ");
        d.on_resize(120, 40);
        typed(&mut d, "top");
        assert_eq!(enter(&mut d).as_deref(), Some("top"));
    }

    #[test]
    fn resize_while_editing_discards_stale_boundary_and_recovers() {
        let mut d = CommandDetector::new(80, 24);
        prompt(&mut d, "$ ");
        typed(&mut d, "echo this command");
        d.on_resize(10, 24);
        typed(&mut d, " is invalidated");
        assert_eq!(enter(&mut d), None);

        prompt(&mut d, "$ ");
        typed(&mut d, "pwd");
        assert_eq!(enter(&mut d).as_deref(), Some("pwd"));
    }
}

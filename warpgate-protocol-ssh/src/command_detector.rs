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
//! A paste submits several commands in one input burst. Every Enter beyond the
//! first is counted, and each is resolved in turn: when one line's terminator
//! arrives, the next line is read off the screen row the terminator moved to,
//! after stripping the prompt that was snapshotted at the last
//! `Output → Editing` transition (the shell may or may not re-print it there).
//!
//! This is an audit aid, not a security boundary: a determined user can defeat
//! any stream-derived logging. Known heuristic limitations, all exercised by
//! the tests below:
//! - Input into a main-screen REPL (python, psql, …) is logged as a command.
//! - A command that wraps past the bottom of the screen may be skipped.
//! - Text right of the cursor containing a wide run of spaces is cut there.

use warpgate_core::sane_terminal_size as sane_size;

const CR: u8 = 0x0d;
const LF: u8 = 0x0a;
const ETX: u8 = 0x03; // Ctrl-C

/// Once a command is submitted, stop waiting for the terminating newline after
/// this many output bytes, so a shell that never echoes one cannot wedge the
/// detector on a single line forever.
const MAX_PENDING_OUTPUT: usize = 2048;

/// A run of this many blank cells on the last input row marks the end of the
/// input; anything after it (a zsh RPROMPT) is not part of the command.
/// ponytail: a command whose text right of the cursor holds this many
/// consecutive spaces loses its tail; raise if that ever shows up in practice.
const RPROMPT_GAP: u16 = 8;

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
    /// that guarantees the whole command has finished rendering. `queued`
    /// counts further Enters the user already sent (a paste), each of which
    /// submits the next line once this one lands.
    Submitted {
        row: u16,
        col: u16,
        scanned: usize,
        queued: usize,
    },
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
    /// The prompt as rendered, snapshotted at the `Output → Editing`
    /// transition: the cells on the cursor's row to the left of the cursor.
    /// Escape sequences are already gone (vt100 processed them), so this is
    /// plain text. A continuation row of a multi-line paste may carry the same
    /// prompt again, and `extract` strips it from what it reads there.
    prompt_text: String,
}

impl CommandDetector {
    pub fn new(cols: u16, rows: u16) -> Self {
        let (cols, rows) = sane_size(cols, rows);
        Self {
            parser: vt100::Parser::new(rows, cols, 0),
            state: State::Idle,
            prompt_text: String::new(),
        }
    }

    pub fn on_resize(&mut self, cols: u16, rows: u16) {
        let (cols, rows) = sane_size(cols, rows);
        self.parser.screen_mut().set_size(rows, cols);
        // The saved boundary is meaningless at the new width, and the rows a
        // queued paste would land on have moved: both transitions below drop
        // any commands still queued behind the current line.
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
                State::Idle | State::Discarded { .. } => {}
                State::Submitted { .. } => self.step_input(b),
                State::Output => {
                    if !self.parser.screen().alternate_screen() {
                        let (row, col) = self.parser.screen().cursor_position();
                        let prompt_text = self.parser.screen().contents_between(row, 0, row, col);
                        self.prompt_text = prompt_text;
                        self.state = State::Editing { row, col };
                        self.step_input(b);
                    }
                }
                State::Editing { .. } | State::Discarding => self.step_input(b),
            }
        }
    }

    /// Feed target output. Returns every command submitted and fully rendered
    /// by this chunk, in order: a paste submits several lines in one burst, so
    /// a single chunk can complete more than one command and none may be
    /// dropped for sharing a chunk with an earlier one.
    #[must_use]
    pub fn on_output(&mut self, data: &[u8]) -> Vec<String> {
        let mut commands = Vec::new();

        if matches!(self.state, State::Idle) {
            self.state = State::Output;
        }

        let mut rest = data;
        loop {
            match self.state {
                State::Idle | State::Output | State::Editing { .. } | State::Discarding => {
                    // Not waiting on a terminator: nothing here can complete.
                    self.parser.process(rest);
                    break;
                }
                State::Discarded { scanned } => {
                    self.parser.process(rest);
                    let scanned = scanned.saturating_add(rest.len());
                    self.state = if rest.iter().any(|&b| b == LF || b == CR)
                        || self.parser.screen().alternate_screen()
                        || scanned >= MAX_PENDING_OUTPUT
                    {
                        State::Output
                    } else {
                        State::Discarded { scanned }
                    };
                    break;
                }
                State::Submitted {
                    row,
                    col,
                    scanned: bytes_scanned,
                    queued,
                } => {
                    let Some(p) = rest.iter().position(|&b| b == LF || b == CR) else {
                        // No terminator yet: this line is still rendering.
                        self.parser.process(rest);
                        let scanned = bytes_scanned.saturating_add(rest.len());

                        // A full-screen app (vim/less/…) launched by the
                        // command switches to the alternate screen before any
                        // newline; give up rather than read the alternate
                        // buffer, and drop the commands queued behind it —
                        // their rows are no longer on the main screen.
                        if self.parser.screen().alternate_screen() {
                            self.state = State::Output;
                        } else if scanned >= MAX_PENDING_OUTPUT {
                            // Best effort on a line that never terminates;
                            // whatever was queued behind it is unrecoverable.
                            commands.extend(self.extract(row, col));
                            self.state = State::Output;
                        } else {
                            self.state = State::Submitted {
                                row,
                                col,
                                scanned,
                                queued,
                            };
                        }
                        break;
                    };

                    // The shell echoes the Enter as CR/LF only after echoing
                    // everything before it, so this is the point at which the
                    // whole command is guaranteed rendered.
                    let (before, after) = rest.split_at(p);
                    self.parser.process(before);
                    commands.extend(self.extract(row, col));

                    // `p` is the position of a terminator, so `after` is
                    // never empty and always starts with CR or LF.
                    let term_len = if after.starts_with(&[CR, LF]) { 2 } else { 1 };
                    let (terminator, tail) = after.split_at(term_len);
                    self.parser.process(terminator);
                    rest = tail;

                    self.state = if queued > 0 {
                        // Another Enter is already waiting. The terminator
                        // moved the cursor to the row the next pasted line
                        // renders on; its prompt is unknown, so read that row
                        // from column 0 and let `extract` strip the prompt.
                        let (next_row, _) = self.parser.screen().cursor_position();
                        State::Submitted {
                            row: next_row,
                            col: 0,
                            scanned: 0,
                            queued: queued - 1,
                        }
                    } else {
                        State::Output
                    };
                }
            }
        }

        commands
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
                    queued: 0,
                };
            }
            // Enters past the first one belong to lines the target has not
            // echoed yet; each is resolved as the line before it completes.
            State::Submitted {
                row,
                col,
                scanned,
                queued,
            } if b == CR || b == LF => {
                self.state = State::Submitted {
                    row,
                    col,
                    scanned,
                    queued: queued.saturating_add(1),
                };
            }
            State::Discarding if b == ETX || b == CR || b == LF => {
                self.state = State::Discarded { scanned: 0 };
            }
            _ => {}
        }
    }

    /// Read the typed text from the prompt boundary to the end of the input.
    /// The end is found on the screen, not from the cursor: readline accepts a
    /// line without moving the cursor, so after Home/←+Enter the cursor can be
    /// anywhere in the input. Soft-wrapped continuation rows are followed and
    /// joined without a newline. On the last row the input ends at the first
    /// run of `RPROMPT_GAP` blank cells, which keeps a zsh RPROMPT out; the
    /// cursor still counts as inside the input, so a shell that moves it to
    /// the end (zsh) is read exactly. A password prompt echoes nothing, so the
    /// range is empty.
    fn extract(&self, row: u16, col: u16) -> Option<String> {
        let screen = self.parser.screen();
        let (rows, cols) = screen.size();
        let mut last_row = row;
        while last_row.saturating_add(1) < rows && screen.row_wrapped(last_row) {
            last_row = last_row.saturating_add(1);
        }
        let start = if last_row == row { col } else { 0 };
        let mut end = start;
        let mut blanks = 0;
        for c in start..cols {
            let blank = !screen
                .cell(last_row, c)
                .is_some_and(vt100::Cell::has_contents);
            blanks = if blank { blanks + 1 } else { 0 };
            if blanks >= RPROMPT_GAP {
                break;
            }
            if !blank {
                end = c.saturating_add(1);
            }
        }
        let (cur_row, cur_col) = screen.cursor_position();
        if cur_row == last_row {
            end = end.max(cur_col);
        }
        if end <= start {
            return None;
        }
        let text = screen.contents_between(row, col, last_row, end);
        let trimmed = text.trim();
        // A continuation row is read from column 0 because its prompt boundary
        // is unknown; when the shell re-printed the prompt there, it comes
        // back verbatim as the leading cells, so drop it.
        let trimmed = if col == 0 {
            match trimmed.strip_prefix(self.prompt_text.as_str()) {
                Some(rest) => rest.trim_start(),
                None => trimmed,
            }
        } else {
            trimmed
        };
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
        assert!(d.on_output(s.as_bytes()).is_empty());
    }

    /// Simulate the user typing `s`, with the shell echoing it verbatim.
    fn typed(d: &mut CommandDetector, s: &str) {
        d.on_input(s.as_bytes());
        assert!(d.on_output(s.as_bytes()).is_empty());
    }

    /// A chunk that must not complete more than one command.
    fn single(commands: Vec<String>) -> Option<String> {
        assert!(
            commands.len() <= 1,
            "expected at most one command, got {commands:?}"
        );
        commands.into_iter().next()
    }

    /// Simulate pressing Enter: the shell echoes CR/LF, finalizing the line.
    fn enter(d: &mut CommandDetector) -> Option<String> {
        d.on_input(b"\r");
        let mut commands = d.on_output(b"\r\n");
        assert!(
            commands.len() <= 1,
            "expected at most one command, got {commands:?}"
        );
        commands.pop()
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
        assert!(d.on_output(b"git status").is_empty());
        assert_eq!(enter(&mut d).as_deref(), Some("git status"));
    }

    #[test]
    fn tab_completion_reads_the_expanded_line() {
        let mut d = CommandDetector::new(80, 24);
        prompt(&mut d, "$ ");
        // User types "gi\t"; the shell echoes the expansion.
        d.on_input(b"gi\t");
        assert!(d.on_output(b"git ").is_empty());
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
        assert!(d.on_output(b"\x08\x08\x1b[K").is_empty());
        typed(&mut d, "ls");
        assert_eq!(enter(&mut d).as_deref(), Some("ls"));
    }

    #[test]
    fn rprompt_is_excluded() {
        let mut d = CommandDetector::new(80, 24);
        prompt(&mut d, "$ ");
        typed(&mut d, "date");
        // zsh RPROMPT is painted to the right of the cursor before Enter.
        assert!(d.on_output(b"\x1b7\x1b[75G12:00\x1b8").is_empty());
        assert_eq!(enter(&mut d).as_deref(), Some("date"));
    }

    #[test]
    fn cursor_moved_left_reads_whole_line() {
        let mut d = CommandDetector::new(80, 24);
        prompt(&mut d, "$ ");
        typed(&mut d, "ls /tmp");
        // Four ← presses: readline echoes a cursor move, nothing else.
        d.on_input(b"\x1b[D\x1b[D\x1b[D\x1b[D");
        assert!(d.on_output(b"\x1b[4D").is_empty());
        assert_eq!(enter(&mut d).as_deref(), Some("ls /tmp"));
    }

    #[test]
    fn cursor_at_line_start_reads_whole_line() {
        let mut d = CommandDetector::new(80, 24);
        prompt(&mut d, "$ ");
        typed(&mut d, "ls /tmp");
        d.on_input(b"\x01");
        assert!(d.on_output(b"\x1b[3G").is_empty());
        assert_eq!(enter(&mut d).as_deref(), Some("ls /tmp"));
    }

    #[test]
    fn rprompt_is_excluded_with_cursor_mid_line() {
        let mut d = CommandDetector::new(80, 24);
        prompt(&mut d, "$ ");
        typed(&mut d, "date");
        assert!(d.on_output(b"\x1b7\x1b[75G12:00\x1b8").is_empty());
        d.on_input(b"\x1b[D\x1b[D");
        assert!(d.on_output(b"\x1b[2D").is_empty());
        assert_eq!(enter(&mut d).as_deref(), Some("date"));
    }

    #[test]
    fn wrapped_command_with_cursor_on_first_row() {
        let mut d = CommandDetector::new(10, 24);
        prompt(&mut d, "$ ");
        typed(&mut d, "echo abc");
        typed(&mut d, "defghij");
        // Cursor back up onto the first row; readline's accept-line then only
        // prints newlines to get below the input.
        d.on_input(b"\x1b[A");
        assert!(d.on_output(b"\x1b[A").is_empty());
        d.on_input(b"\r");
        assert_eq!(
            single(d.on_output(b"\n\r\n")).as_deref(),
            Some("echo abcdefghij")
        );
    }

    #[test]
    fn enter_before_echo_and_split_newline() {
        let mut d = CommandDetector::new(80, 24);
        prompt(&mut d, "$ ");
        // Whole burst (command + Enter) arrives on input before any echo.
        d.on_input(b"ls\r");
        // Echo of the command arrives first, without a terminator yet.
        assert!(d.on_output(b"ls").is_empty());
        // The terminating newline arrives in a later chunk.
        assert_eq!(single(d.on_output(b"\r\n")).as_deref(), Some("ls"));
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
        assert!(d.on_output(b"[sudo] password for user: ").is_empty());
        d.on_input(b"hunter2\r");
        assert!(d.on_output(b"\r\n").is_empty());
    }

    #[test]
    fn ctrl_c_discards() {
        let mut d = CommandDetector::new(80, 24);
        prompt(&mut d, "$ ");
        typed(&mut d, "rm -rf /");
        d.on_input(b"\x03");
        assert!(d.on_output(b"^C\r\n").is_empty());
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
        assert!(d.on_output(b"\x1b[?1049h").is_empty());
        // Keystrokes inside vim, including Enter, must not be captured.
        d.on_input(b"iHello, world\x1b:wq\r");
        assert!(d.on_output(b"redrawing").is_empty());
        // Back to the main screen.
        assert!(d.on_output(b"\x1b[?1049l").is_empty());
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
            if let Some(c) = single(d.on_output(&[b'y'; 100])) {
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
    fn restore_cursor_after_shrink_does_not_panic() {
        let mut d = CommandDetector::new(80, 24);
        // Prompt saves the cursor (DECSC) on row 20; the terminal then shrinks
        // below that row and the shell redraws with DECRC + text.
        prompt(&mut d, "\x1b[21;1H$ \x1b7");
        d.on_resize(80, 10);
        prompt(&mut d, "\x1b8$ ");
        typed(&mut d, "ls");
        assert_eq!(enter(&mut d).as_deref(), Some("ls"));
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

    #[test]
    fn paste_of_two_commands_emits_both() {
        let mut d = CommandDetector::new(80, 24);
        prompt(&mut d, "user@host:~$ ");
        // One input burst carrying two Enters.
        d.on_input(b"echo one\recho two\r");
        // The shell echoes the first line, re-prints the prompt and echoes the
        // second line, all before the detector sees any of it.
        let commands = d.on_output(b"echo one\r\nuser@host:~$ echo two\r\n");
        assert_eq!(commands, ["echo one", "echo two"]);
    }

    #[test]
    fn paste_of_three_commands_with_reprinted_prompts() {
        let mut d = CommandDetector::new(80, 24);
        prompt(&mut d, "user@host:~$ ");
        d.on_input(b"echo one\recho two\recho three\r");
        let commands =
            d.on_output(b"echo one\r\nuser@host:~$ echo two\r\nuser@host:~$ echo three\r\n");
        assert_eq!(commands, ["echo one", "echo two", "echo three"]);
    }

    #[test]
    fn paste_of_three_commands_without_reprinted_prompts() {
        let mut d = CommandDetector::new(80, 24);
        prompt(&mut d, "user@host:~$ ");
        d.on_input(b"echo one\recho two\recho three\r");
        // Some shells echo the pasted newlines without re-printing the prompt
        // for each line. Reading a continuation row from column 0 is what keeps
        // the old prompt column from cutting these down to a suffix.
        let commands = d.on_output(b"echo one\r\necho two\r\necho three\r\n");
        assert_eq!(commands, ["echo one", "echo two", "echo three"]);
    }

    #[test]
    fn paste_then_typed_command_emits_all_three_without_duplicates() {
        let mut d = CommandDetector::new(80, 24);
        prompt(&mut d, "user@host:~$ ");
        d.on_input(b"echo one\recho two\r");
        assert_eq!(
            d.on_output(b"echo one\r\nuser@host:~$ echo two\r\n"),
            ["echo one", "echo two"]
        );
        // Back to ordinary editing, with a freshly snapshotted prompt.
        prompt(&mut d, "user@host:~$ ");
        typed(&mut d, "pwd");
        assert_eq!(enter(&mut d).as_deref(), Some("pwd"));
    }

    #[test]
    fn paste_into_a_screen_app_drops_queued_commands() {
        let mut d = CommandDetector::new(80, 24);
        prompt(&mut d, "user@host:~$ ");
        // A two-line paste whose first command is a full-screen app: the
        // second Enter is queued, then the app takes over before the line
        // holding it ever terminates.
        d.on_input(b"vim\r:wq\r");
        assert_eq!(d.on_output(b"vim\r\n\x1b[?1049h"), ["vim"]);
        // The queued line must not be recovered from the alternate screen.
        assert!(d.on_output(b"hello\x1b[?1049l\r\n").is_empty());
        // Detection resumes on the main screen.
        prompt(&mut d, "user@host:~$ ");
        typed(&mut d, "ls");
        assert_eq!(enter(&mut d).as_deref(), Some("ls"));
    }

    #[test]
    fn resize_mid_paste_drops_queued_commands() {
        let mut d = CommandDetector::new(80, 24);
        prompt(&mut d, "user@host:~$ ");
        d.on_input(b"echo one\recho two\r");
        // The first line completes, leaving the second one queued ...
        assert_eq!(d.on_output(b"echo one\r\n"), ["echo one"]);
        // ... then a resize invalidates the row it would have landed on.
        d.on_resize(40, 24);
        // The rest of the paste must not surface as a suffix of the new layout.
        assert!(d.on_output(b"user@host:~$ echo two\r\n").is_empty());
        // Detection recovers at the new width.
        prompt(&mut d, "user@host:~$ ");
        typed(&mut d, "pwd");
        assert_eq!(enter(&mut d).as_deref(), Some("pwd"));
    }
}

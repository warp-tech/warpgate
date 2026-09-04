use std::borrow::Cow;
use std::fmt::Display;
use std::io::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use termcolor::{Buffer, Color, ColorSpec, WriteColor as _};
use tokio::sync::{Mutex, broadcast, mpsc};

const SEG_LEN: usize = 5;
const ANIM_FRAME_DURATION: Duration = Duration::from_millis(100);

const CH_SEGMENT_ANIMATION: [char; 3] = ['┈', '─', '┈'];
const CH_SEGMENT_CONNECTED: char = '─';
const CH_SEGMENT_NOT_CONNECTED: char = '─';
const CH_TARGET_CONNECTED: char = '●';
const CH_TARGET_NOT_CONNECTED: char = '○';
const CURSOR_UP: &str = "\x1b[1A";
const ERASE_LINE: &str = "\x1b[2K";

#[must_use]
pub(super) fn paint_fg<S: Display>(fg: Color, dimmed: bool, text: S) -> String {
    let mut buf = Buffer::ansi();
    let _ = buf.set_color(ColorSpec::new().set_fg(Some(fg)).set_dimmed(dimmed));
    let _ = write!(buf, "{text}");
    let _ = buf.reset();
    String::from_utf8_lossy(buf.as_slice()).to_string()
}

#[derive(Clone)]
pub enum VisualConnectionChainItem {
    Text(String),
    Link { text: String, url: String },
}

/// Strips control characters from a string on its way to a terminal.
///
/// The chain is drawn from target *names*, and a name is free text an operator
/// types into the admin UI. Written straight out, a name containing `\x1b[2J`
/// clears the screen of every user who connects through that target, and one
/// containing an OSC-8 sequence draws a hyperlink pointing wherever it likes —
/// in the frame Warpgate itself is printing, which is where a user has most
/// reason to trust what they see.
///
/// The same class as the certificate-derived text in the client, at lower
/// severity: a target name needs `TargetsEdit`, so this is not a privilege
/// boundary, and the audience is whoever connects rather than whoever
/// configures. Same fix regardless.
fn without_control_characters(text: &str) -> Cow<'_, str> {
    if text.chars().any(char::is_control) {
        Cow::Owned(text.chars().filter(|c| !c.is_control()).collect())
    } else {
        Cow::Borrowed(text)
    }
}

/// The same, but a line break survives.
///
/// This is the form the PTY sinks use. `emit_service_message` turns `\n` into
/// `\r\n` itself, so stripping every control character there would silently
/// join the lines of any multi-line message instead of escaping anything.
///
/// Separate from `without_control_characters` rather than a flag on it: the
/// chain renderer must not keep newlines — a name with one in it would break the
/// drawing — and a shared function with a boolean would eventually be called
/// with the wrong one.
pub(super) fn without_control_characters_except_newline(text: &str) -> Cow<'_, str> {
    if text.chars().any(|c| c.is_control() && c != '\n') {
        Cow::Owned(
            text.chars()
                .filter(|c| !c.is_control() || *c == '\n')
                .collect(),
        )
    } else {
        Cow::Borrowed(text)
    }
}

impl VisualConnectionChainItem {
    pub fn ansi(&self) -> Cow<'_, str> {
        match self {
            Self::Text(s) => without_control_characters(s),
            // The escapes here are Warpgate's own, wrapped around text and a URL
            // that are not.
            Self::Link { text, url } => Cow::Owned(format!(
                "\x1b]8;;{}\x1b\\{}\x1b]8;;\x1b\\",
                without_control_characters(url),
                without_control_characters(text)
            )),
        }
    }
}

/// Describes the connection chain hosts and how many hops are fully connected.
pub struct VisualConnectionChainState {
    /// Host display names
    pub items: Vec<VisualConnectionChainItem>,
    /// Number of segments (between adjacent hosts) that are fully connected (green).
    /// Starts at 1 because the you → warpgate link is always established.
    pub connected_hops: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SegmentState {
    Connected,
    Connecting,
    Pending,
}

#[must_use]
fn render_segment_line(state: SegmentState, tick: usize) -> String {
    match state {
        SegmentState::Connected => paint_fg(
            Color::Green,
            false,
            CH_SEGMENT_CONNECTED.to_string().repeat(SEG_LEN),
        ),
        SegmentState::Connecting => {
            let active_seg = tick % (SEG_LEN * 2);
            #[allow(clippy::indexing_slicing, reason = "wraps")]
            (0..SEG_LEN)
                .map(|j| {
                    let seg_ch = CH_SEGMENT_ANIMATION[(tick + j) % (CH_SEGMENT_ANIMATION.len())];
                    paint_fg(
                        Color::Blue,
                        (active_seg > j) || (active_seg + 10 < j + 10 - 2),
                        seg_ch,
                    )
                })
                .collect()
        }
        SegmentState::Pending => paint_fg(
            Color::White,
            true,
            CH_SEGMENT_NOT_CONNECTED.to_string().repeat(SEG_LEN),
        ),
    }
}

/// Render the full connection chain graph for a given animation tick
#[must_use]
pub fn render_connection_chain(chain: &VisualConnectionChainState, tick: usize) -> String {
    let mut out = String::new();

    for (seg_index, host) in chain.items.iter().enumerate() {
        #[allow(clippy::comparison_chain)]
        let state = if seg_index < chain.connected_hops + 1 {
            SegmentState::Connected
        } else if seg_index == chain.connected_hops + 1 {
            SegmentState::Connecting
        } else {
            SegmentState::Pending
        };

        if seg_index > 0 {
            out.push(' ');
            out.push_str(&render_segment_line(state, tick));
            out.push(' ');
        }

        out.push_str(&paint_fg(
            match state {
                SegmentState::Connected => Color::Green,
                SegmentState::Connecting => Color::Blue,
                SegmentState::Pending => Color::White,
            },
            state == SegmentState::Pending,
            match state {
                SegmentState::Connected => CH_TARGET_CONNECTED,
                _ => CH_TARGET_NOT_CONNECTED,
            },
        ));
        out.push(' ');
        out.push_str(&paint_fg(
            match state {
                SegmentState::Connecting => Color::Blue,
                SegmentState::Connected | SegmentState::Pending => Color::White,
            },
            state == SegmentState::Pending,
            host.ansi(),
        ));
    }

    out.push_str("\r\n");

    out
}

#[derive(Clone)]
pub struct ServiceOutput {
    progress_visible: Arc<AtomicBool>,
    /// is progress the last thing printed to the terminal?
    on_screen: Arc<AtomicBool>,
    chain: Arc<Mutex<Option<VisualConnectionChainState>>>,
    abort_tx: mpsc::Sender<()>,
    output_tx: broadcast::Sender<Bytes>,
}

impl ServiceOutput {
    pub fn new() -> Self {
        let progress_visible = Arc::new(AtomicBool::new(false));
        let on_screen = Arc::new(AtomicBool::new(false));
        let chain: Arc<Mutex<Option<VisualConnectionChainState>>> = Arc::new(Mutex::new(None));
        let (abort_tx, mut abort_rx) = mpsc::channel(1);
        let output_tx = broadcast::channel(32).0;

        tokio::spawn({
            let output_tx = output_tx.clone();
            let progress_visible = progress_visible.clone();
            let chain = chain.clone();
            let mut tick = 0usize;
            async move {
                loop {
                    tokio::select! {
                        _ = abort_rx.recv() => return,
                        () = tokio::time::sleep(ANIM_FRAME_DURATION) => {
                            if progress_visible.load(Ordering::Relaxed) {
                                tick += 1;
                                let guard = chain.lock().await;
                                if let Some(c) = &*guard {
                                    let frame = render_connection_chain(c, tick);
                                    let _ = output_tx.send(Bytes::from(frame.into_bytes()));
                                }
                            }
                        }
                    }
                }
            }
        });

        Self {
            progress_visible,
            on_screen,
            chain,
            abort_tx,
            output_tx,
        }
    }

    pub async fn start_progress(&self, hosts: Vec<VisualConnectionChainItem>) {
        *self.chain.lock().await = Some(VisualConnectionChainState {
            items: hosts,
            connected_hops: 1,
        });
        self.progress_visible.store(true, Ordering::Relaxed);
    }

    pub async fn notify_hop_connected(&self) {
        let mut guard = self.chain.lock().await;
        if let Some(c) = &mut *guard {
            c.connected_hops += 1;
        }
    }

    /// Re-enable the animation (e.g. after pausing for a host-key prompt).
    pub fn show_progress(&self) {
        self.progress_visible.store(true, Ordering::Relaxed);
    }

    pub fn stop_progress(&self) {
        self.progress_visible.store(false, Ordering::Relaxed);
    }

    pub fn progress_visible(&self) -> bool {
        self.progress_visible.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn take_frame(&self, frame: &Bytes) -> Option<Bytes> {
        if !self.progress_visible() {
            return None;
        }
        if !self.on_screen.swap(true, Ordering::Relaxed) {
            // Nothing to repaint over: the cursor already sits on a free line.
            return Some(frame.clone());
        }
        let mut out = BytesMut::with_capacity(CURSOR_UP.len() + 1 + frame.len());
        out.extend_from_slice(CURSOR_UP.as_bytes());
        out.extend_from_slice(b"\r");
        out.extend_from_slice(frame);
        Some(out.freeze())
    }

    #[must_use]
    pub async fn render_final_success_static_frame(&self) -> String {
        self.progress_visible.store(false, Ordering::Relaxed);
        let chain = self.chain.lock().await;
        let graph = if let Some(c) = &*chain {
            let n = c.items.len();
            let all_green = VisualConnectionChainState {
                items: c.items.clone(),
                connected_hops: n,
            };
            render_connection_chain(&all_green, 0)
        } else {
            "".into()
        };
        drop(chain);
        format!("{}{}\r\n", self.erase_display(), graph)
    }

    /// String that erases the progress line, if one is on screen
    #[must_use]
    pub fn erase_display(&self) -> String {
        if self.on_screen.swap(false, Ordering::Relaxed) {
            format!("{CURSOR_UP}\r{ERASE_LINE}")
        } else {
            String::new()
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Bytes> {
        self.output_tx.subscribe()
    }
}

impl Drop for ServiceOutput {
    fn drop(&mut self) {
        let signal = std::mem::replace(&mut self.abort_tx, mpsc::channel(1).0);
        tokio::spawn(async move { signal.send(()).await });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn repaints_in_place_only_while_the_frame_is_on_screen() {
        let output = ServiceOutput::new();
        let frame = Bytes::from_static(b"chain\r\n");

        assert_eq!(output.take_frame(&frame), None, "not started yet");

        output.start_progress(vec![]).await;
        assert_eq!(
            output.take_frame(&frame).as_deref(),
            Some(&b"chain\r\n"[..])
        );
        assert_eq!(
            output.take_frame(&frame).as_deref(),
            Some(format!("{CURSOR_UP}\rchain\r\n").as_bytes())
        );

        // Pausing for a prompt: queued frames are dropped, and the prompt
        // erases the progress line it replaces.
        output.stop_progress();
        assert_eq!(output.take_frame(&frame), None);
        assert_eq!(output.erase_display(), format!("{CURSOR_UP}\r{ERASE_LINE}"));
        assert_eq!(output.erase_display(), "", "nothing left to erase");

        // Resuming draws on the free line below the prompt, not over it.
        output.show_progress();
        assert_eq!(
            output.take_frame(&frame).as_deref(),
            Some(&b"chain\r\n"[..])
        );
    }


    /// A target name is free text an operator types; it is drawn into the PTY of
    /// everyone who connects through that target.
    #[test]
    fn a_target_name_cannot_write_escape_sequences_to_the_terminal() {
        let hostile = VisualConnectionChainItem::Text("prod\x1b[2J\x1b[H".to_owned());
        let rendered = hostile.ansi();
        assert_eq!(rendered, "prod[2J[H");
        assert!(!rendered.contains('\x1b'), "{rendered:?}");
    }

    /// Asserted as a property rather than a literal: the wrapper emits four
    /// escapes of its own, and the data must contribute none. Writing the
    /// expected bytes out by hand got this wrong in a way that looked like a
    /// code bug — the surviving backslash is inert, because the `ESC` that
    /// would have made it an OSC terminator is gone.
    #[test]
    fn a_link_keeps_its_own_escapes_but_not_the_data_s() {
        let item = VisualConnectionChainItem::Link {
            text: "Warp\x1bgate".to_owned(),
            url: "https://example.com/\x1b]8;;evil\x1b\\".to_owned(),
        };
        let rendered = item.ansi();
        assert_eq!(
            rendered.matches('\x1b').count(),
            4,
            "the data contributed an escape: {rendered:?}"
        );
        assert!(rendered.contains("Warpgate"), "{rendered:?}");
    }
}

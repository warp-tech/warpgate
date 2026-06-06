use std::borrow::Cow;
use std::fmt::Display;
use std::io::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
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

#[must_use]
pub(super) fn paint_fg<S: Display>(fg: Color, dimmed: bool, text: S) -> String {
    let mut buf = Buffer::ansi();
    let _ = buf.set_color(ColorSpec::new().set_fg(Some(fg)).set_dimmed(dimmed));
    let _ = write!(buf, "{text}");
    let _ = buf.reset();
    String::from_utf8_lossy(buf.as_slice()).to_string()
}

#[derive(Clone)]
pub enum ConnectionChainHost {
    Text(String),
    Link { text: String, url: String },
}

impl ConnectionChainHost {
    pub fn ansi<'a>(&'a self) -> Cow<'a, String> {
        match self {
            ConnectionChainHost::Text(s) => Cow::Borrowed(s),
            ConnectionChainHost::Link { text, url } => {
                Cow::Owned(format!("\x1b]8;;{url}\x1b\\{text}\x1b]8;;\x1b\\"))
            }
        }
    }
}

/// Describes the connection chain hosts and how many hops are fully connected.
pub struct ConnectionChain {
    /// Host display names
    pub hosts: Vec<ConnectionChainHost>,
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
            &CH_SEGMENT_CONNECTED.to_string().repeat(SEG_LEN),
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
                        // (j + ANIM_PERIOD - tick % ANIM_PERIOD) % ANIM_PERIOD != ANIM_PERIOD - 1,
                        &seg_ch,
                    )
                })
                .collect()
        }
        SegmentState::Pending => paint_fg(
            Color::White,
            true,
            &CH_SEGMENT_NOT_CONNECTED.to_string().repeat(SEG_LEN),
        ),
    }
}

/// Render the full connection chain graph for a given animation tick
#[must_use]
pub fn render_connection_graph(chain: &ConnectionChain, tick: usize) -> String {
    let mut out = String::new();

    for (seg_index, host) in chain.hosts.iter().enumerate() {
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
                SegmentState::Connected => Color::White,
                SegmentState::Connecting => Color::Blue,
                SegmentState::Pending => Color::White,
            },
            state == SegmentState::Pending,
            &host.ansi(),
        ));
    }

    out.push_str("\r\n");

    out
}

fn erase_for_width(w: usize) -> String {
    format!("{CURSOR_UP}\r{}\r", " ".repeat(w))
}

#[derive(Clone)]
pub struct ServiceOutput {
    progress_visible: Arc<AtomicBool>,
    last_progress_width: Arc<AtomicUsize>,
    chain: Arc<Mutex<Option<ConnectionChain>>>,
    abort_tx: mpsc::Sender<()>,
    output_tx: broadcast::Sender<Bytes>,
}

impl ServiceOutput {
    pub fn new() -> Self {
        let progress_visible = Arc::new(AtomicBool::new(false));
        let last_progress_width = Arc::new(AtomicUsize::new(0));
        let chain: Arc<Mutex<Option<ConnectionChain>>> = Arc::new(Mutex::new(None));
        let (abort_tx, mut abort_rx) = mpsc::channel(1);
        let output_tx = broadcast::channel(32).0;

        tokio::spawn({
            let output_tx = output_tx.clone();
            let last_progress_width = last_progress_width.clone();
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
                                    let frame = format!("{CURSOR_UP}\r{}", render_connection_graph(c, tick));
                                    last_progress_width.store(frame.len(), Ordering::Relaxed);
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
            last_progress_width,
            chain,
            abort_tx,
            output_tx,
        }
    }

    pub async fn start_progress(&self, hosts: Vec<ConnectionChainHost>) {
        *self.chain.lock().await = Some(ConnectionChain {
            hosts,
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
    pub async fn render_final_success_static_frame(&self) -> String {
        self.progress_visible.store(false, Ordering::Relaxed);
        let chain = self.chain.lock().await;
        let graph = if let Some(c) = &*chain {
            let n = c.hosts.len();
            let all_green = ConnectionChain {
                hosts: c.hosts.clone(),
                connected_hops: n,
            };
            render_connection_graph(&all_green, 0)
        } else {
            "".into()
        };
        drop(chain);
        format!("{}{}\r\n", self.erase_display(), graph)
    }

    /// String that erases the last graph line
    #[must_use]
    pub fn erase_display(&self) -> String {
        erase_for_width(self.last_progress_width.load(Ordering::Relaxed))
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

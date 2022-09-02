use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use ansi_term::Colour;
use bytes::Bytes;
use tokio::sync::{broadcast, mpsc};

pub const ERASE_PROGRESS_SPINNER: &str = "\r                        \r";
pub const ERASE_PROGRESS_SPINNER_BUF: &[u8] = ERASE_PROGRESS_SPINNER.as_bytes();
pub const LINEBREAK: &[u8] = "\n".as_bytes();

#[derive(Clone)]
pub struct ServiceOutput {
    progress_visible: Arc<AtomicBool>,
    abort_tx: mpsc::Sender<()>,
    output_tx: broadcast::Sender<Bytes>,
}

impl ServiceOutput {
    pub fn new() -> Self {
        let progress_visible = Arc::new(AtomicBool::new(false));
        let (abort_tx, mut abort_rx) = mpsc::channel(1);
        let output_tx = broadcast::channel(32).0;

        tokio::spawn({
            let output_tx = output_tx.clone();
            let progress_visible = progress_visible.clone();
            let ticks = "⠁⠁⠉⠙⠚⠒⠂⠂⠒⠲⠴⠤⠄⠄⠤⠠⠠⠤⠦⠖⠒⠐⠐⠒⠓⠋⠉⠈⠈".chars().collect::<Vec<_>>();
            let mut tick_index = 0;
            async move {
                loop {
                    tokio::select! {
                        _ = abort_rx.recv() => {
                            return;
                        }
                        _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                            if progress_visible.load(std::sync::atomic::Ordering::Relaxed) {
                                tick_index = (tick_index + 1) % ticks.len();
                                #[allow(clippy::indexing_slicing)]
                                let tick = ticks[tick_index];
                                let badge = Colour::Black.on(Colour::Blue).paint(format!(" {} Warpgate connecting ", tick)).to_string();
                                let _ = output_tx.send(Bytes::from([ERASE_PROGRESS_SPINNER_BUF, badge.as_bytes()].concat()));
                            }
                        }
                    }
                }
            }
        });

        ServiceOutput {
            progress_visible,
            abort_tx,
            output_tx,
        }
    }

    pub fn show_progress(&mut self) {
        self.progress_visible
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub async fn hide_progress(&mut self) {
        self.progress_visible
            .store(false, std::sync::atomic::Ordering::Relaxed);
        self.emit_output(Bytes::from_static(ERASE_PROGRESS_SPINNER_BUF));
        self.emit_output(Bytes::from_static(LINEBREAK));
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Bytes> {
        self.output_tx.subscribe()
    }

    pub fn emit_output(&mut self, output: Bytes) {
        let _ = self.output_tx.send(output);
    }
}

impl Drop for ServiceOutput {
    fn drop(&mut self) {
        let _ = self.abort_tx.send(());
    }
}

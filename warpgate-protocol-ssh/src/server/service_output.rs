use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use ansi_term::Colour;
use anyhow::Result;
use tokio::sync::{mpsc, Mutex};

pub const ERASE_PROGRESS_SPINNER: &str = "\r                        \r";

pub type Callback = dyn Fn(&[u8]) -> Result<()> + Send + 'static;

#[derive(Clone)]
pub struct ServiceOutput {
    progress_visible: Arc<AtomicBool>,
    callback: Arc<Mutex<Box<Callback>>>,
    abort_tx: mpsc::Sender<()>,
}

impl ServiceOutput {
    pub fn new(callback: Box<Callback>) -> Self {
        let callback = Arc::new(Mutex::new(callback));
        let progress_visible = Arc::new(AtomicBool::new(false));
        let (abort_tx, mut abort_rx) = mpsc::channel(1);
        tokio::spawn({
            let progress_visible = progress_visible.clone();
            let callback = callback.clone();
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
                                let tick = ticks[tick_index];
                                let badge = Colour::Black.on(Colour::Blue).paint(format!(" {} Warpgate connecting ", tick));
                                let output = format!("{ERASE_PROGRESS_SPINNER}{badge}");
                                if callback.lock().await(output.as_bytes()).is_err() {
                                    return;
                                }
                            }
                        }
                    }
                }
            }
        });
        ServiceOutput {
            progress_visible,
            callback,
            abort_tx,
        }
    }

    pub fn show_progress(&mut self) {
        self.progress_visible
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub async fn hide_progress(&mut self) {
        self.progress_visible
            .store(false, std::sync::atomic::Ordering::Relaxed);
        let cb = self.callback.lock().await;
        let _ = cb(ERASE_PROGRESS_SPINNER.as_bytes());
        let _ = cb("\n".as_bytes());
    }
}

impl Drop for ServiceOutput {
    fn drop(&mut self) {
        let _ = self.abort_tx.send(());
    }
}

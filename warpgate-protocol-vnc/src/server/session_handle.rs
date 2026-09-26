use tokio::sync::mpsc;
use warpgate_core::SessionHandle;

pub struct VncSessionHandle {
    abort_tx: mpsc::UnboundedSender<()>,
}

impl VncSessionHandle {
    pub fn new() -> (Self, mpsc::UnboundedReceiver<()>) {
        let (abort_tx, abort_rx) = mpsc::unbounded_channel();
        (Self { abort_tx }, abort_rx)
    }
}

impl SessionHandle for VncSessionHandle {
    fn close(&mut self) {
        let _ = self.abort_tx.send(());
    }
}

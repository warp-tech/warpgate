use tokio::sync::mpsc;
use warpgate_core::SessionHandle;

pub struct SocksSessionHandle {
    abort_tx: mpsc::UnboundedSender<()>,
}

impl SocksSessionHandle {
    pub fn new() -> (Self, mpsc::UnboundedReceiver<()>) {
        let (abort_tx, abort_rx) = mpsc::unbounded_channel();
        (Self { abort_tx }, abort_rx)
    }
}

impl SessionHandle for SocksSessionHandle {
    fn close(&mut self) {
        let _ = self.abort_tx.send(());
    }
}

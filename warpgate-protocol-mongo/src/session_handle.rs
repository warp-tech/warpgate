use tokio::sync::mpsc;
use warpgate_core::SessionHandle;

pub struct MongoSessionHandle {
    abort_tx: mpsc::UnboundedSender<()>,
}

impl MongoSessionHandle {
    pub fn new() -> (Self, mpsc::UnboundedReceiver<()>) {
        let (abort_tx, abort_rx) = mpsc::unbounded_channel();
        (Self { abort_tx }, abort_rx)
    }
}

impl SessionHandle for MongoSessionHandle {
    fn close(&mut self) {
        let _ = self.abort_tx.send(());
    }
}

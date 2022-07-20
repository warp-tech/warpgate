use tokio::sync::mpsc;
use warpgate_common::SessionHandle;

pub struct MySqlSessionHandle {
    abort_tx: mpsc::UnboundedSender<()>,
}

impl MySqlSessionHandle {
    pub fn new() -> (Self, mpsc::UnboundedReceiver<()>) {
        let (abort_tx, abort_rx) = mpsc::unbounded_channel();
        (MySqlSessionHandle { abort_tx }, abort_rx)
    }
}

impl SessionHandle for MySqlSessionHandle {
    fn close(&mut self) {
        let _ = self.abort_tx.send(());
    }
}

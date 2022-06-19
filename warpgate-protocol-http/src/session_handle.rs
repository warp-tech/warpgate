use tokio::sync::mpsc;
use warpgate_common::SessionHandle;

#[derive(Clone, Debug, PartialEq)]
pub enum SessionHandleCommand {
    Close,
}

pub struct HttpSessionHandle {
    sender: mpsc::UnboundedSender<SessionHandleCommand>,
}

impl HttpSessionHandle {
    pub fn new() -> (Self, mpsc::UnboundedReceiver<SessionHandleCommand>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        (HttpSessionHandle { sender }, receiver)
    }
}

impl SessionHandle for HttpSessionHandle {
    fn close(&mut self) {
        let _ = self.sender.send(SessionHandleCommand::Close);
    }
}

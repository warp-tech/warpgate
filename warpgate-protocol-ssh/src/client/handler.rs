use russh::client::Session;
use russh_keys::key::PublicKey;
use tokio::sync::mpsc::UnboundedSender;
use tracing::*;

pub struct ClientHandler {
    pub tx: UnboundedSender<ClientHandlerEvent>,
}

#[derive(Debug)]
pub enum ClientHandlerEvent {
    Disconnect,
}

impl russh::client::Handler for ClientHandler {
    type Error = anyhow::Error;
    type FutureUnit = futures::future::Ready<Result<(Self, Session), anyhow::Error>>;
    type FutureBool = futures::future::Ready<Result<(Self, bool), anyhow::Error>>;

    fn finished_bool(self, b: bool) -> Self::FutureBool {
        futures::future::ready(Ok((self, b)))
    }

    fn finished(self, session: Session) -> Self::FutureUnit {
        futures::future::ready(Ok((self, session)))
    }

    fn check_server_key(self, server_public_key: &PublicKey) -> Self::FutureBool {
        debug!("check_server_key: {:?}", server_public_key);
        self.finished_bool(true)
    }
}

impl Drop for ClientHandler {
    fn drop(&mut self) {
        let _ = self.tx.send(ClientHandlerEvent::Disconnect);
        debug!("Dropped");
    }
}

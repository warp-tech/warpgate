use std::sync::Arc;

use tokio::sync::watch;
use warpgate_vault::VaultClient;

/// Houses a replaceable reference to the Vault client, so that editing the
/// `vault:` section takes effect the way editing any other section does.
///
/// Built on a `watch` channel for the same reason the listener supervisors are:
/// a client is not something a session can hold across a reload, since the
/// address, the mount or the way Warpgate proves its identity may all have
/// changed. Readers take a fresh reference per use; each keeps working until it
/// is dropped, so a session already in flight is never cut short by a reload.
#[derive(Clone)]
pub struct VaultCell {
    receiver: watch::Receiver<Option<Arc<VaultClient>>>,
    sender: watch::Sender<Option<Arc<VaultClient>>>,
}

impl VaultCell {
    pub fn new(client: Option<Arc<VaultClient>>) -> Self {
        let (sender, receiver) = watch::channel(client);
        Self { receiver, sender }
    }

    /// The client as of right now, or `None` when no Vault server is configured.
    pub fn get(&self) -> Option<Arc<VaultClient>> {
        self.receiver.borrow().clone()
    }

    pub fn replace(&self, client: Option<Arc<VaultClient>>) {
        let _ = self.sender.send(client);
    }
}

use std::{sync::Arc, time::Duration};

use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::Mutex;

use crate::ServerClient;

#[derive(Clone, Debug)]
pub enum RCEvent {
    Connected,
    Disconnected,
}

#[derive(Clone, Debug)]
pub enum RCCommand {
    Connect,
}

#[derive(Clone, Debug, PartialEq)]
pub enum RCState {
    NotInitialized,
    Connecting,
    Connected,
    Disconnected,
}

pub struct RemoteClient {
    client: Arc<Mutex<ServerClient>>,
    rx: UnboundedReceiver<RCCommand>,
    tx: UnboundedSender<RCEvent>,
}

impl RemoteClient {
    pub fn new (
        client: Arc<Mutex<ServerClient>>,
        rx: UnboundedReceiver<RCCommand>,
        tx: UnboundedSender<RCEvent>,
    ) -> Self {
        Self {
            client,
            rx,
            tx,
        }
    }

    pub fn start(mut self) {
        tokio::spawn(async move {
            loop {
                let cmd = self.rx.recv().await;
                match cmd {
                    Some(RCCommand::Connect) => {
                        println!("[rc] connecting");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        println!("[rc] connected");
                        self.tx.send(RCEvent::Connected).unwrap();
                    }
                    None => {
                        break;
                    }
                }
            }
            println!("[rc] no more commmands");
        });
    }
}

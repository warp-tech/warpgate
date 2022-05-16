use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use russh::client::Channel;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tracing::*;
use uuid::Uuid;
use warpgate_common::SessionId;

use crate::{ChannelOperation, RCEvent};

pub struct DirectTCPIPChannel {
    client_channel: Channel,
    channel_id: Uuid,
    ops_rx: UnboundedReceiver<ChannelOperation>,
    events_tx: UnboundedSender<RCEvent>,
    session_id: SessionId,
}

impl DirectTCPIPChannel {
    pub fn new(
        client_channel: Channel,
        channel_id: Uuid,
        ops_rx: UnboundedReceiver<ChannelOperation>,
        events_tx: UnboundedSender<RCEvent>,
        session_id: SessionId,
    ) -> Self {
        DirectTCPIPChannel {
            client_channel,
            channel_id,
            ops_rx,
            events_tx,
            session_id,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        loop {
            tokio::select! {
                incoming_data = self.ops_rx.recv() => {
                    match incoming_data {
                        Some(ChannelOperation::Data(data)) => {
                            self.client_channel.data(&*data).await.context("data")?;
                        }
                        Some(ChannelOperation::Eof) => {
                            self.client_channel.eof().await.context("eof")?;
                        },
                        Some(ChannelOperation::Close) => break,
                        None => break,
                        Some(operation) => {
                            warn!(client_channel=%self.channel_id, ?operation, session=%self.session_id, "unexpected client_channel operation");
                        }
                    }
                }
                channel_event = self.client_channel.wait() => {
                    match channel_event {
                        Some(russh::ChannelMsg::Data { data }) => {
                            let bytes: &[u8] = &data;
                            self.events_tx.send(RCEvent::Output(
                                self.channel_id,
                                Bytes::from(BytesMut::from(bytes)),
                            ))?;
                        }
                        Some(russh::ChannelMsg::Close) => {
                            self.events_tx.send(RCEvent::Close(self.channel_id))?;
                        },
                        Some(russh::ChannelMsg::Success) => {
                            self.events_tx.send(RCEvent::Success(self.channel_id))?;
                        },
                        Some(russh::ChannelMsg::Eof) => {
                            self.events_tx.send(RCEvent::Eof(self.channel_id))?;
                        }
                        None => {
                            self.events_tx.send(RCEvent::Close(self.channel_id))?;
                            break
                        },
                        Some(operation) => {
                            warn!(client_channel=%self.channel_id, ?operation, session=%self.session_id, "unexpected client_channel operation");
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

impl Drop for DirectTCPIPChannel {
    fn drop(&mut self) {
        info!(client_channel=%self.channel_id, session=%self.session_id, "Closed");
    }
}

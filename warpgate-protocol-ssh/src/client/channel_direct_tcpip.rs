use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use russh::client::Channel;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tracing::*;

use crate::{ChannelOperation, RCEvent, ServerChannelId};

pub struct DirectTCPIPChannel {
    channel: Channel,
    server_channel_id: ServerChannelId,
    ops_rx: UnboundedReceiver<ChannelOperation>,
    events_tx: UnboundedSender<RCEvent>,
    session_tag: String,
}

impl DirectTCPIPChannel {
    pub fn new(
        channel: Channel,
        server_channel_id: ServerChannelId,
        ops_rx: UnboundedReceiver<ChannelOperation>,
        events_tx: UnboundedSender<RCEvent>,
        session_tag: String,
    ) -> Self {
        DirectTCPIPChannel {
            channel,
            server_channel_id,
            ops_rx,
            events_tx,
            session_tag,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        loop {
            tokio::select! {
                incoming_data = self.ops_rx.recv() => {
                    match incoming_data {
                        Some(ChannelOperation::Data(data)) => {
                            self.channel.data(&*data).await.context("data")?;
                        }
                        Some(ChannelOperation::Eof) => {
                            self.channel.eof().await.context("eof")?;
                        },
                        Some(ChannelOperation::Close) => break,
                        None => break,
                        Some(operation) => {
                            warn!(channel=%self.server_channel_id, ?operation, session=%self.session_tag, "unexpected channel operation");
                        }
                    }
                }
                channel_event = self.channel.wait() => {
                    match channel_event {
                        Some(russh::ChannelMsg::Data { data }) => {
                            let bytes: &[u8] = &data;
                            self.events_tx.send(RCEvent::Output(
                                self.server_channel_id,
                                Bytes::from(BytesMut::from(bytes)),
                            ))?;
                        }
                        Some(russh::ChannelMsg::Close) => {
                            self.events_tx.send(RCEvent::Close(self.server_channel_id))?;
                        },
                        Some(russh::ChannelMsg::Success) => {
                            self.events_tx.send(RCEvent::Success(self.server_channel_id))?;
                        },
                        Some(russh::ChannelMsg::Eof) => {
                            self.events_tx.send(RCEvent::Eof(self.server_channel_id))?;
                        }
                        None => {
                            self.events_tx.send(RCEvent::Close(self.server_channel_id))?;
                            break
                        },
                        Some(operation) => {
                            warn!(channel=%self.server_channel_id, ?operation, session=%self.session_tag, "unexpected channel operation");
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
        info!(channel=%self.server_channel_id, session=%self.session_tag, "Closed");
    }
}

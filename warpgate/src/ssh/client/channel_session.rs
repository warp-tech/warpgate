use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use thrussh::client::Channel;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tracing::*;

use crate::ssh::{ChannelOperation, RCEvent, ServerChannelId};

pub struct SessionChannel {
    channel: Channel,
    server_channel_id: ServerChannelId,
    ops_rx: UnboundedReceiver<ChannelOperation>,
    events_tx: UnboundedSender<RCEvent>,
    session_tag: String,
}

impl SessionChannel {
    pub fn new(
        channel: Channel,
        server_channel_id: ServerChannelId,
        ops_rx: UnboundedReceiver<ChannelOperation>,
        events_tx: UnboundedSender<RCEvent>,
        session_tag: String,
    ) -> Self {
        SessionChannel {
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
                        Some(ChannelOperation::ExtendedData { ext, data }) => {
                            self.channel.extended_data(ext, &*data).await.context("extended data")?;
                        }
                        Some(ChannelOperation::RequestPty(request)) => {
                            self.channel.request_pty(
                                true,
                                &request.term,
                                request.col_width,
                                request.row_height,
                                request.pix_width,
                                request.pix_height,
                                &request.modes,
                            ).await.context("request_pty")?;
                        }
                        Some(ChannelOperation::ResizePty(request)) => {
                            self.channel.window_change(
                                request.col_width,
                                request.row_height,
                                request.pix_width,
                                request.pix_height,
                            ).await.context("resize_pty")?;
                        },
                        Some(ChannelOperation::RequestShell) => {
                            self.channel.request_shell(true).await.context("request_shell")?;
                        },
                        Some(ChannelOperation::RequestEnv(name, value)) => {
                            self.channel.set_env(true, name, value).await.context("request_env")?;
                        },
                        Some(ChannelOperation::RequestExec(command)) => {
                            self.channel.exec(true, command).await.context("request_exec")?;
                        },
                        Some(ChannelOperation::RequestSubsystem(name)) => {
                            self.channel.request_subsystem(true, &name).await.context("request_subsystem")?;
                        },
                        Some(ChannelOperation::Eof) => {
                            self.channel.eof().await.context("eof")?;
                        },
                        Some(ChannelOperation::Signal(signal)) => {
                            self.channel.signal(signal).await.context("signal")?;
                        },
                        Some(ChannelOperation::OpenShell) => unreachable!(),
                        Some(ChannelOperation::OpenDirectTCPIP { .. }) => unreachable!(),
                        Some(ChannelOperation::Close) => break,
                        None => break,
                    }
                }
                channel_event = self.channel.wait() => {
                    match channel_event {
                        Some(thrussh::ChannelMsg::Data { data }) => {
                            let bytes: &[u8] = &data;
                            self.events_tx.send(RCEvent::Output(
                                self.server_channel_id,
                                Bytes::from(BytesMut::from(bytes)),
                            ))?;
                        }
                        Some(thrussh::ChannelMsg::Close) => {
                            self.events_tx.send(RCEvent::Close(self.server_channel_id))?;
                        },
                        Some(thrussh::ChannelMsg::Success) => {
                            self.events_tx.send(RCEvent::Success(self.server_channel_id))?;
                        },
                        Some(thrussh::ChannelMsg::Eof) => {
                            self.events_tx.send(RCEvent::Eof(self.server_channel_id))?;
                        }
                        Some(thrussh::ChannelMsg::ExitStatus { exit_status }) => {
                            self.events_tx.send(RCEvent::ExitStatus(self.server_channel_id, exit_status))?;
                        }
                        Some(thrussh::ChannelMsg::WindowAdjusted { .. }) => { },
                        Some(thrussh::ChannelMsg::ExitSignal {
                            core_dumped, error_message, lang_tag, signal_name
                        }) => {
                            self.events_tx.send(RCEvent::ExitSignal {
                                channel: self.server_channel_id, core_dumped, error_message, lang_tag, signal_name
                            })?;
                        },
                        Some(thrussh::ChannelMsg::XonXoff { client_can_do: _ }) => {
                        }
                        Some(thrussh::ChannelMsg::ExtendedData { data, ext }) => {
                            let data: &[u8] = &data;
                            self.events_tx.send(RCEvent::ExtendedData {
                                channel: self.server_channel_id,
                                data: Bytes::from(BytesMut::from(data)),
                                ext,
                            })?;
                        }
                        None => {
                            self.events_tx.send(RCEvent::Close(self.server_channel_id))?;
                            break
                        },
                    }
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    }
}

impl Drop for SessionChannel {
    fn drop(&mut self) {
        info!(channel=%self.server_channel_id, session=%self.session_tag, "Closed");
    }
}

use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use russh::client::Channel;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tracing::*;
use uuid::Uuid;
use warpgate_common::SessionId;

use crate::{ChannelOperation, RCEvent};

pub struct SessionChannel {
    client_channel: Channel,
    channel_id: Uuid,
    ops_rx: UnboundedReceiver<ChannelOperation>,
    events_tx: UnboundedSender<RCEvent>,
    session_id: SessionId,
}

impl SessionChannel {
    pub fn new(
        client_channel: Channel,
        channel_id: Uuid,
        ops_rx: UnboundedReceiver<ChannelOperation>,
        events_tx: UnboundedSender<RCEvent>,
        session_id: SessionId,
    ) -> Self {
        SessionChannel {
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
                        Some(ChannelOperation::ExtendedData { ext, data }) => {
                            self.client_channel.extended_data(ext, &*data).await.context("extended data")?;
                        }
                        Some(ChannelOperation::RequestPty(request)) => {
                            self.client_channel.request_pty(
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
                            self.client_channel.window_change(
                                request.col_width,
                                request.row_height,
                                request.pix_width,
                                request.pix_height,
                            ).await.context("resize_pty")?;
                        },
                        Some(ChannelOperation::RequestShell) => {
                            self.client_channel.request_shell(true).await.context("request_shell")?;
                        },
                        Some(ChannelOperation::RequestEnv(name, value)) => {
                            self.client_channel.set_env(true, name, value).await.context("request_env")?;
                        },
                        Some(ChannelOperation::RequestExec(command)) => {
                            self.client_channel.exec(true, command).await.context("request_exec")?;
                        },
                        Some(ChannelOperation::RequestSubsystem(name)) => {
                            self.client_channel.request_subsystem(true, &name).await.context("request_subsystem")?;
                        },
                        Some(ChannelOperation::Eof) => {
                            self.client_channel.eof().await.context("eof")?;
                        },
                        Some(ChannelOperation::Signal(signal)) => {
                            self.client_channel.signal(signal).await.context("signal")?;
                        },
                        Some(ChannelOperation::OpenShell) => unreachable!(),
                        Some(ChannelOperation::OpenDirectTCPIP { .. }) => unreachable!(),
                        Some(ChannelOperation::OpenX11 { .. }) => unreachable!(),
                        Some(ChannelOperation::RequestX11(request)) => {
                            self.client_channel.request_x11(
                                true,
                                request.single_conection,
                                request.x11_auth_protocol,
                                request.x11_auth_cookie,
                                request.x11_screen_number,
                            ).await.context("data")?;
                        }
                        Some(ChannelOperation::Close) => break,
                        None => break,
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
                        Some(russh::ChannelMsg::ExitStatus { exit_status }) => {
                            self.events_tx.send(RCEvent::ExitStatus(self.channel_id, exit_status))?;
                        }
                        Some(russh::ChannelMsg::WindowAdjusted { .. }) => { },
                        Some(russh::ChannelMsg::ExitSignal {
                            core_dumped, error_message, lang_tag, signal_name
                        }) => {
                            self.events_tx.send(RCEvent::ExitSignal {
                                channel: self.channel_id, core_dumped, error_message, lang_tag, signal_name
                            })?;
                        },
                        Some(russh::ChannelMsg::XonXoff { client_can_do: _ }) => {
                        }
                        Some(russh::ChannelMsg::ExtendedData { data, ext }) => {
                            let data: &[u8] = &data;
                            self.events_tx.send(RCEvent::ExtendedData {
                                channel: self.channel_id,
                                data: Bytes::from(BytesMut::from(data)),
                                ext,
                            })?;
                        }
                        None => {
                            self.events_tx.send(RCEvent::Close(self.channel_id))?;
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
        info!(channel=%self.channel_id, session=%self.session_id, "Closed");
    }
}

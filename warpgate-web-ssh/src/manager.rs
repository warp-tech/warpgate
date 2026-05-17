use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, anyhow};
use russh::keys::PublicKeyBase64;
use tokio::sync::mpsc::Receiver;
use tokio::sync::{Mutex, mpsc};
use tracing::{Instrument, debug, error, info_span, warn};
use uuid::Uuid;
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{
    SshHostKeyVerificationMode, Target, TargetOptions, TargetSSHOptions, WarpgateError,
};
use warpgate_core::recordings::TerminalRecordingStreamId;
use warpgate_core::{ConfigProvider, Services, SessionStateInit, State};
use warpgate_db_entities::Target::TargetKind;
use warpgate_protocol_ssh::known_hosts::KnownHosts;
use warpgate_protocol_ssh::{RCCommand, RCEvent, RCState, RemoteClient};

use crate::protocol::ServerMessage;
use crate::session::{WebSshSession, WebSshSessionHandle};

const MAX_SESSIONS_PER_USER: usize = 100;

#[derive(Default)]
pub struct WebSshClientManager {
    sessions: Arc<Mutex<HashMap<Uuid, Arc<WebSshSession>>>>,
}

impl WebSshClientManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn create_session(
        &self,
        services: &Services,
        user_id: Uuid,
        username: &str,
        target_name: &str,
        remote_address: Option<SocketAddr>,
    ) -> Result<Uuid, WarpgateError> {
        {
            let sessions = self.sessions.lock().await;
            let user_session_count = sessions.values().filter(|s| s.user_id() == user_id).count();
            if user_session_count >= MAX_SESSIONS_PER_USER {
                return Err(WarpgateError::SessionLimitReached);
            }
        }

        let target: Target = {
            let mut cp = services.config_provider.lock().await;
            cp.list_targets()
                .await?
                .into_iter()
                .find(|t| t.name == target_name)
                .ok_or_else(|| anyhow!("SSH target {target_name:?} not found"))?
        };

        let TargetOptions::Ssh(mut ssh_options) = target.options.clone() else {
            return Err(WarpgateError::InvalidTarget);
        };

        if ssh_options.username.is_empty() {
            ssh_options.username = username.to_owned();
        }

        let (abort_tx, mut abort_rx) = mpsc::unbounded_channel::<()>();
        let session_handle = WebSshSessionHandle::new(abort_tx);

        let server_handle = State::register_session(
            &services.state,
            &warpgate_protocol_ssh::PROTOCOL_NAME,
            SessionStateInit {
                remote_address,
                handle: Box::new(session_handle),
            },
        )
        .await
        .context("registering webSSH session")?;

        {
            let server_handle = server_handle.lock().await;

            server_handle
                .set_user_info(AuthStateUserInfo {
                    id: user_id,
                    username: username.to_owned(),
                })
                .await
                .context("setting user info on server handle")?;

            server_handle
                .set_target(&target)
                .await
                .context("setting target on server handle")?;
        }

        let session_id = server_handle.lock().await.id();
        let rc_handles = RemoteClient::create(session_id, services.clone())
            .context("creating SSH remote client")?;

        let session = Arc::new(WebSshSession::new(
            session_id,
            user_id,
            target_name.to_owned(),
            TargetKind::from(&target.options),
            rc_handles.command_tx.clone(),
            rc_handles.abort_tx.clone(),
            services.recordings.clone(),
        ));

        tokio::spawn({
            let session = session.clone();
            async move {
                if abort_rx.recv().await.is_some() {
                    session.close();
                }
            }
        });

        self.sessions
            .lock()
            .await
            .insert(session_id, session.clone());

        rc_handles
            .command_tx
            .send((RCCommand::Connect(ssh_options.clone()), None))
            .ok();

        spawn_event_loop(
            session.clone(),
            rc_handles.event_rx,
            self.sessions.clone(),
            services.clone(),
            ssh_options,
        );

        debug!(session=%session_id, user=%username, target=%target_name, "Web-SSH session created");

        Ok(session_id)
    }

    pub async fn get_session(&self, id: Uuid) -> Option<Arc<WebSshSession>> {
        self.sessions.lock().await.get(&id).cloned()
    }

    pub async fn remove_session(&self, id: Uuid) {
        if let Some(session) = self.sessions.lock().await.remove(&id) {
            session.abort();
        }
    }
}

fn spawn_event_loop(
    session: Arc<WebSshSession>,
    mut event_rx: Receiver<RCEvent>,
    sessions: Arc<Mutex<HashMap<Uuid, Arc<WebSshSession>>>>,
    services: Services,
    ssh_options: TargetSSHOptions,
) {
    let session_id = session.id();
    let span = info_span!("WebSSH", session=%session_id);
    tokio::task::Builder::new()
        .spawn(
            async move {
                while let Some(event) = event_rx.recv().await {
                    match event {
                        RCEvent::State(state) => {
                            session
                                .push_event(ServerMessage::ConnectionState { state })
                                .await;
                        }
                        RCEvent::Output(channel_id, data) => {
                            {
                                session.with_recorder(channel_id, async |r| {
                                    if let Err(e) = r
                                        .write(TerminalRecordingStreamId::Output, &data)
                                        .await
                                    {
                                        error!(%channel_id, ?e, "Failed to record terminal data");
                                    }
                                }).await;
                            }
                            session
                                .push_event(ServerMessage::Output {
                                    channel_id,
                                    data: crate::protocol::Base64Bytes(data),
                                })
                                .await;
                        }
                        RCEvent::Eof(channel_id) => {
                            session.push_event(ServerMessage::Eof { channel_id }).await;
                        }
                        RCEvent::Close(channel_id) => {
                            session.stop_recording(channel_id).await;
                            session
                                .push_event(ServerMessage::ChannelClosed { channel_id })
                                .await;
                        }
                        RCEvent::ExitStatus(channel_id, code) => {
                            session
                                .push_event(ServerMessage::ExitStatus { channel_id, code })
                                .await;
                        }
                        RCEvent::ChannelFailure(channel_id) => {
                            session.stop_recording(channel_id).await;
                            session
                                .push_event(ServerMessage::ChannelClosed { channel_id })
                                .await;
                        }
                        RCEvent::Error(e) => {
                            session
                                .push_event(ServerMessage::Error {
                                    message: e.to_string(),
                                })
                                .await;
                        }
                        RCEvent::ConnectionError(e) => {
                            session
                                .push_event(ServerMessage::Error {
                                    message: e.to_string(),
                                })
                                .await;
                            session
                                .push_event(ServerMessage::ConnectionState {
                                    state: RCState::Disconnected,
                                })
                                .await;
                        }
                        RCEvent::HostKeyReceived(key) => {
                            debug!(%session_id, "Host key received: {}", key.algorithm());
                        }
                        RCEvent::HostKeyUnknown(key, reply) => {
                            let mode = services
                                .config
                                .lock()
                                .await
                                .store
                                .ssh
                                .host_key_verification;
                            match mode {
                                SshHostKeyVerificationMode::AutoAccept => {
                                    let known_hosts = KnownHosts::new(&services.db);
                                    if let Err(e) = known_hosts
                                        .trust(
                                            &ssh_options.host,
                                            ssh_options.port,
                                            &key,
                                        )
                                        .await
                                    {
                                        error!(%session_id, ?e, "Failed to save host key");
                                    }
                                    let _ = reply.send(true);
                                }
                                SshHostKeyVerificationMode::Prompt => {
                                    session
                                        .push_event(ServerMessage::HostKeyUnknown {
                                            host: ssh_options.host.clone(),
                                            port: ssh_options.port,
                                            key_type: key.algorithm().to_string(),
                                            key_base64: key.public_key_base64(),
                                        })
                                        .await;
                                    session
                                        .set_pending_host_key(crate::session::PendingHostKey {
                                            reply,
                                            key,
                                            host: ssh_options.host.clone(),
                                            port: ssh_options.port,
                                        })
                                        .await;
                                }
                                SshHostKeyVerificationMode::AutoReject => {
                                    warn!(%session_id, "Unknown host key rejected (auto-reject mode)");
                                    let _ = reply.send(false);
                                }
                            }
                        }
                        RCEvent::Done => {
                            session.close();
                            sessions.lock().await.remove(&session.id());
                            break;
                        }
                        _ => {}
                    }
                }
                anyhow::Ok(())
            }
            .instrument(span),
        )
        .ok();
}

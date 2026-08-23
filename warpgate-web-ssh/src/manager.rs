use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use russh::keys::PublicKeyBase64;
use tokio::sync::mpsc::Receiver;
use tokio::sync::{Mutex, mpsc};
use tracing::{Instrument, debug, error, info_span, warn};
use uuid::Uuid;
use warpgate_common::{TargetSSHOptions, WarpgateError};
use warpgate_core::{
    Services, State, TargetAuthorization, TargetSessionStart, UserSessionStateInit,
};
use warpgate_db_entities::Parameters;
use warpgate_db_entities::Parameters::SshHostKeyVerificationMode;
use warpgate_db_entities::Target::TargetKind;
use warpgate_protocol_ssh::{
    RCCommand, RCEvent, RCState, RemoteClient, resolve_approved_ssh_chain,
};
use warpgate_web_clients_common::{ClientManager, SessionRemover, WebSessionHandle};

use crate::protocol::ServerMessage;
use crate::session::WebSshSession;

const MAX_SESSIONS_PER_USER: usize = 100;

#[derive(Default)]
pub struct WebSshClientManager(ClientManager<WebSshSession>);

impl std::ops::Deref for WebSshClientManager {
    type Target = ClientManager<WebSshSession>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl SessionRemover for WebSshClientManager {
    async fn remove_session(&self, id: Uuid) {
        self.0.remove_session(id).await;
    }
}

impl WebSshClientManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn create_session(
        &self,
        services: &Services,
        authorization: TargetAuthorization,
        remote_address: Option<SocketAddr>,
    ) -> Result<Uuid, WarpgateError> {
        let user_id = authorization.user_info().id;
        if self.count_for_user(user_id).await >= MAX_SESSIONS_PER_USER {
            return Err(WarpgateError::SessionLimitReached);
        }

        let authorization = authorization.narrow::<TargetSSHOptions>()?;
        let username = authorization.user_info().username.clone();
        let target_name = authorization.target().name.clone();
        let target_kind = TargetKind::from(&authorization.target().options);

        let (abort_tx, mut abort_rx) = mpsc::unbounded_channel::<()>();
        let session_handle = WebSessionHandle::new(abort_tx);

        let server_handle = State::register_user_session(
            &services.state,
            warpgate_protocol_ssh::PROTOCOL_NAME,
            UserSessionStateInit {
                remote_address,
                handle: Box::new(session_handle),
            },
        )
        .await
        .context("registering webSSH session")?;

        let (_, approved, _) = *{
            let mut server_handle = server_handle.lock().await;

            server_handle
                .set_user_info(authorization.user_info().clone())
                .await
                .context("setting user info on server handle")?;

            server_handle
                .start_target_session(authorization)
                .await
                .and_then(TargetSessionStart::admitted)
                .context("starting target session")?
        };

        let session_id = server_handle.lock().await.id();
        let rc_handles = RemoteClient::create(session_id, services.clone())
            .context("creating SSH remote client")?;

        let session = Arc::new(WebSshSession::new(
            session_id.0,
            user_id,
            target_name.clone(),
            target_kind,
            server_handle,
            rc_handles.command_tx.clone(),
            rc_handles.abort_tx.clone(),
            services.recordings.clone(),
        ));

        // weak ref to avoid the ref cycle
        // https://github.com/warp-tech/warpgate/issues/2049
        tokio::spawn({
            let session = Arc::downgrade(&session);
            async move {
                if abort_rx.recv().await.is_some()
                    && let Some(session) = session.upgrade()
                {
                    session.close();
                }
            }
        });

        self.insert(session.clone()).await;

        let ssh_chain = resolve_approved_ssh_chain(services, approved)
            .await?
            .into_iter()
            .map(|x| x.ssh_options)
            .collect::<Vec<_>>();
        rc_handles
            .command_tx
            .send((RCCommand::Connect(ssh_chain), None))
            .ok();

        spawn_event_loop(
            session.clone(),
            rc_handles.event_rx,
            self.sessions(),
            services.clone(),
        );

        debug!(session=%session_id, user=%username, target=%target_name, "Web-SSH session created");

        Ok(session_id.0)
    }
}

fn spawn_event_loop(
    session: Arc<WebSshSession>,
    mut event_rx: Receiver<RCEvent>,
    sessions: Arc<Mutex<HashMap<Uuid, Arc<WebSshSession>>>>,
    services: Services,
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
                                .push(ServerMessage::ConnectionState { state })
                                .await;
                        }
                        RCEvent::Output(channel_id, data) => {
                            session.on_output(channel_id, &data).await;
                            session
                                .push(ServerMessage::Output {
                                    channel_id,
                                    data,
                                })
                                .await;
                        }
                        RCEvent::Eof(channel_id) => {
                            session.push(ServerMessage::Eof { channel_id }).await;
                        }

                        RCEvent::ExitStatus(channel_id, code) => {
                            session
                                .push(ServerMessage::ExitStatus { channel_id, code })
                                .await;
                        }
                        RCEvent::Close(channel_id) |
                        RCEvent::ChannelFailure(channel_id) => {
                            session.end_channel(channel_id).await;
                            session
                                .push(ServerMessage::ChannelClosed { channel_id })
                                .await;
                        }
                        RCEvent::Error(e) => {
                            session
                                .push(ServerMessage::Error {
                                    message: e.to_string(),
                                })
                                .await;
                        }
                        RCEvent::ConnectionError(e) => {
                            session
                                .push(ServerMessage::Error {
                                    message: e.to_string(),
                                })
                                .await;
                            session
                                .push(ServerMessage::ConnectionState {
                                    state: RCState::Disconnected,
                                })
                                .await;
                        }
                        RCEvent::HostKeyReceived(key, host, port) => {
                            debug!(%session_id, "Host key received for {host}:{port}: {}", key.algorithm());
                        }
                        RCEvent::HostKeyUnknown(key, host, port, reply) => {
                            let mode = match Parameters::Entity::get(&services.db).await {
                                Ok(p) => p.ssh_host_key_verification,
                                Err(e) => {
                                    error!(%session_id, ?e, "Failed to read the host key verification mode");
                                    let _ = reply.send(false);
                                    continue;
                                }
                            };
                            match mode {
                                SshHostKeyVerificationMode::Ignore
                                | SshHostKeyVerificationMode::AutoAccept => {
                                    let _ = reply.send(true);
                                }
                                SshHostKeyVerificationMode::Prompt => {
                                    session
                                        .push(ServerMessage::HostKeyUnknown {
                                            host,
                                            port,
                                            key_type: key.algorithm().to_string(),
                                            key_base64: key.public_key_base64(),
                                        })
                                        .await;
                                    session
                                        .set_pending_host_key(crate::session::PendingHostKey {
                                            reply,
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
                            break;
                        }
                        _ => {}
                    }
                }

                // remote client is gone now
                session.close();
                sessions.lock().await.remove(&session.id());
                anyhow::Ok(())
            }
            .instrument(span),
        )
        .ok();
}

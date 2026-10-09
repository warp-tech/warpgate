use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use russh::keys::PublicKeyBase64;
use tokio::sync::mpsc::Receiver;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, error, info_span, warn};
use warpgate_common::{TargetSSHOptions, UserSessionId, WarpgateError};
use warpgate_core::{Services, TargetAuthorization};
use warpgate_db_entities::Parameters;
use warpgate_db_entities::Parameters::SshHostKeyVerificationMode;
use warpgate_db_entities::Target::TargetKind;
use warpgate_protocol_ssh::{
    RCEvent, RCState, RemoteClient, RemoteClientHandles, resolve_approved_ssh_chain,
};
use warpgate_web_clients_common::{
    ClientManager, LiveSessionPhase, register_provisional_web_client_session,
    run_web_client_lifecycle,
};

use crate::protocol::ServerMessage;
use crate::session::{PendingHostKey, WebSshSession};

const MAX_SESSIONS_PER_USER: usize = 100;

#[derive(Default)]
pub struct WebSshClientManager(ClientManager<WebSshSession>);

impl std::ops::Deref for WebSshClientManager {
    type Target = ClientManager<WebSshSession>;
    fn deref(&self) -> &Self::Target {
        &self.0
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
    ) -> Result<UserSessionId, WarpgateError> {
        let authorization = authorization.narrow::<TargetSSHOptions>()?;
        let user_id = authorization.user_info().id;
        let username = authorization.user_info().username.clone();
        let target_name = authorization.target().name.clone();
        let target_kind = TargetKind::from(&authorization.target().options);

        let cancel = CancellationToken::new();
        let server_handle = register_provisional_web_client_session(
            services,
            warpgate_protocol_ssh::PROTOCOL_NAME,
            remote_address,
            &cancel,
        )
        .await?;
        let session_id = server_handle.lock().await.user_session_id();

        let RemoteClientHandles {
            event_rx,
            command_tx,
            abort_tx,
        } = RemoteClient::create(session_id, services.clone())
            .context("creating SSH remote client")?;

        let session = Arc::new(WebSshSession::new(
            session_id,
            user_id,
            target_name.clone(),
            target_kind,
            server_handle,
            cancel,
            command_tx,
            services.recordings.clone(),
        ));
        session.forward_cancellation(abort_tx);

        if let Err(error) = self
            .try_insert(session.clone(), MAX_SESSIONS_PER_USER)
            .await
        {
            session.abort();
            return Err(error);
        }
        // Reaped unless a client attaches; attaching cancels the timer.
        session.start_disconnect_timer(self.0.clone()).await;

        tokio::spawn(
            run_session(
                session,
                authorization,
                remote_address,
                event_rx,
                self.0.clone(),
                services.clone(),
            )
            .instrument(info_span!("WebSSH", session=%session_id)),
        );

        debug!(session=%session_id, user=%username, target=%target_name, "Web-SSH session created");

        Ok(session_id)
    }
}

async fn run_session(
    session: Arc<WebSshSession>,
    authorization: TargetAuthorization<TargetSSHOptions>,
    remote_address: Option<SocketAddr>,
    mut event_rx: Receiver<RCEvent>,
    registry: ClientManager<WebSshSession>,
    services: Services,
) {
    run_web_client_lifecycle(
        &session,
        registry,
        &services,
        authorization,
        remote_address,
        |admitted| async {
            session.bind_target_session(admitted.id());
            let last_error = match resolve_approved_ssh_chain(&services, admitted).await {
                Ok(chain) => {
                    session.connect(chain.into_iter().map(|x| x.ssh_options).collect());
                    relay_events(&session, &mut event_rx, &services).await
                }
                Err(error) => Err(error),
            };
            if let Some(pending) = session.take_pending_host_key().await {
                let _ = pending.reply.send(false);
            }
            last_error
        },
    )
    .await;
}

async fn relay_events(
    session: &WebSshSession,
    event_rx: &mut Receiver<RCEvent>,
    services: &Services,
) -> Result<(), WarpgateError> {
    let session_id = session.id();
    let mut final_result: Result<(), WarpgateError> = Ok(());
    while let Some(event) = event_rx.recv().await {
        match event {
            RCEvent::State(RCState::Connecting) => {
                session.set_phase(LiveSessionPhase::Connecting).await;
            }
            RCEvent::State(RCState::Connected) => {
                session.set_phase(LiveSessionPhase::Connected).await;
            }
            RCEvent::Output(channel_id, data) => {
                session.on_output(channel_id, &data).await;
                session
                    .push(ServerMessage::Output { channel_id, data })
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
            RCEvent::Close(channel_id) | RCEvent::ChannelFailure(channel_id) => {
                session.end_channel(channel_id).await;
                session
                    .push(ServerMessage::ChannelClosed { channel_id })
                    .await;
            }
            RCEvent::Error(e) => {
                final_result = Err(notice(session, e).await.into());
            }
            RCEvent::ConnectionError(e) => {
                final_result = Err(notice(session, e.into()).await.into());
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
                    SshHostKeyVerificationMode::Ignore | SshHostKeyVerificationMode::AutoAccept => {
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
                        session.set_pending_host_key(PendingHostKey { reply }).await;
                    }
                    SshHostKeyVerificationMode::AutoReject => {
                        warn!(%session_id, "Unknown host key rejected (auto-reject mode)");
                        let _ = reply.send(false);
                    }
                }
            }
            RCEvent::Done => break,
            // Includes the `Disconnected` state: the end is reported once, with
            // its reason, when the client is done.
            _ => {}
        }
    }
    final_result
}

async fn notice(session: &WebSshSession, error: anyhow::Error) -> anyhow::Error {
    session
        .push(ServerMessage::Error {
            message: error.to_string(),
        })
        .await;
    error
}

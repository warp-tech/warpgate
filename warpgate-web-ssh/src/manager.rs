use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use russh::keys::PublicKeyBase64;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Receiver;
use tracing::{Instrument, debug, error, info_span, warn};
use warpgate_common::{TargetSSHOptions, UserSessionId, WarpgateError};
use warpgate_core::{Services, State, TargetAuthorization, UserSessionStateInit};
use warpgate_db_entities::Parameters;
use warpgate_db_entities::Parameters::SshHostKeyVerificationMode;
use warpgate_db_entities::Target::TargetKind;
use warpgate_protocol_ssh::{
    ConnectionError, RCCommand, RCEvent, RCState, RemoteClient, client_error_message,
    resolve_approved_ssh_chain,
};

/// What a browser session is told when the connection fails.
///
/// A named function rather than a method call inside the event loop, because
/// the guard here is the *choice* — `client_message()` and not `Display`. The
/// raw form carries the issuer's own words, mounts, policies and hostnames,
/// which the SSH path keeps from users and this entry point renders alike.
///
/// A call inside an async loop cannot be reached by a test without driving a
/// browser session. Named here, the boundary has somewhere a test can stand.
#[must_use]
pub fn shown_to_the_browser(error: &ConnectionError) -> String {
    error.client_message()
}
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
    async fn remove_session(&self, id: UserSessionId) {
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
    ) -> Result<UserSessionId, WarpgateError> {
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

        let server_handle = State::register_node_local_user_session(
            &services.state,
            warpgate_protocol_ssh::PROTOCOL_NAME,
            UserSessionStateInit {
                remote_address,
                handle: Box::new(session_handle),
            },
        )
        .await
        .context("registering webSSH session")?;

        let (target_session_id, approved) = server_handle
            .lock()
            .await
            .start_target_session(authorization)
            .await
            .context("starting target session")?
            .admitted()?;

        let session_id = server_handle.lock().await.user_session_id();
        let rc_handles = RemoteClient::create(session_id, services.clone())
            .context("creating SSH remote client")?;

        let session = Arc::new(WebSshSession::new(
            session_id,
            user_id,
            target_name.clone(),
            target_kind,
            target_session_id,
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

        // Not reduced to plain SSH options: `Connect` carries the identity of
        // each hop, so `connect_chain` can decide which target was asked about
        // rather than assuming it is the last one.
        let ssh_chain = resolve_approved_ssh_chain(services, approved).await?;
        rc_handles
            .command_tx
            .send((RCCommand::Connect(ssh_chain), None))
            .ok();

        spawn_event_loop(
            session.clone(),
            rc_handles.event_rx,
            self.0.clone(),
            services.clone(),
        );

        debug!(session=%session_id, user=%username, target=%target_name, "Web-SSH session created");

        Ok(session_id)
    }
}

fn spawn_event_loop(
    session: Arc<WebSshSession>,
    mut event_rx: Receiver<RCEvent>,
    manager: ClientManager<WebSshSession>,
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
                            // Same boundary as the SSH path, for the same
                            // reason. Disclosure only here rather than terminal
                            // injection — this lands in a Svelte alert, which
                            // escapes — but the text is the one `client_message`
                            // exists to keep away from a user.
                            tracing::error!(error=%e, "Client session error");
                            session
                                .push(ServerMessage::Error {
                                    message: client_error_message(&e).to_owned(),
                                })
                                .await;
                        }
                        RCEvent::ConnectionError(e) => {
                            // `Vault`, `Aws` and `Warpgate` arrive here with no
                            // error-level log anywhere upstream — the connect
                            // path logs at debug!, under the default
                            // `warpgate=info` filter — so without this a
                            // certificate failure leaves the server side with
                            // no record at all, only the sanitised text below.
                            tracing::error!(error=%e, "Target connection failed");
                            session
                                .push(ServerMessage::Error {
                                    message: shown_to_the_browser(&e),
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
                manager.remove_session(session.id()).await;
                anyhow::Ok(())
            }
            .instrument(span),
        )
        .ok();
}

#[cfg(test)]
mod tests {
    use warpgate_common::WarpgateError;

    use super::{ConnectionError, shown_to_the_browser};

    /// The browser is told a fixed phrase, never the error's own words.
    ///
    /// `Warpgate` is `#[error(transparent)]`, so its `Display` is whatever the
    /// inner error says — a database failure renders as `database error: …`
    /// carrying SQL text. That variant is the one this boundary exists for, and
    /// asserting on it specifically is what makes this test fail if the call
    /// reverts to `to_string()`.
    #[test]
    fn a_browser_never_sees_the_error_s_own_words() {
        let leaky = ConnectionError::Warpgate(WarpgateError::Other(
            "database error: SELECT secret FROM credentials".into(),
        ));

        let shown = shown_to_the_browser(&leaky);
        assert!(!shown.contains("SELECT"), "the raw error reached the browser: {shown}");
        assert!(!shown.contains("database error"), "the raw error reached the browser: {shown}");
        assert_eq!(shown, leaky.client_message());
    }
}

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use russh::keys::PublicKeyBase64;
use tokio::sync::mpsc::Receiver;
use tokio::sync::{Mutex, mpsc};
use tracing::{Instrument, debug, error, info_span, warn};
use uuid::Uuid;
use warpgate_common::{TargetOptions, WarpgateError};
use warpgate_core::{Services, SessionStateInit, State, TargetAuthorization};
use warpgate_db_entities::Parameters;
use warpgate_db_entities::Parameters::SshHostKeyVerificationMode;
use warpgate_db_entities::Target::TargetKind;
use warpgate_protocol_ssh::{
    ConnectionError, RCCommand, RCEvent, RCState, RemoteClient, client_error_message,
    resolve_ssh_chain,
};

/// What a browser session is told when the connection fails.
///
/// A named function rather than a method call inside the event loop, because
/// the guard here is the *choice* — `client_message()` and not `Display`. The
/// raw form carries the issuer's own words, mounts, policies and hostnames,
/// which the SSH path has kept from users since it was first reported; this
/// entry point renders the same errors and was missed.
///
/// A call inside an async loop cannot be reached by a test without driving a
/// browser session, and the integration test that was credited with covering
/// this one turned out to exercise the SSH path instead — measured, not
/// suspected. Named here, the boundary has somewhere a test can stand.
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

        let (user_info, target) = authorization.into_parts();
        let username = user_info.username.clone();

        let TargetOptions::Ssh(_) = &target.options else {
            return Err(WarpgateError::InvalidTarget);
        };

        let (abort_tx, mut abort_rx) = mpsc::unbounded_channel::<()>();
        let session_handle = WebSessionHandle::new(abort_tx);

        let server_handle = State::register_session(
            &services.state,
            warpgate_protocol_ssh::PROTOCOL_NAME,
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
                .set_user_info(user_info)
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
            target.name.clone(),
            TargetKind::from(&target.options),
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

        let ssh_chain = resolve_ssh_chain(services, target.id, Some(&username)).await?;
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

        debug!(session=%session_id, user=%username, target=%target.name, "Web-SSH session created");

        Ok(session_id)
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
                sessions.lock().await.remove(&session.id());
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

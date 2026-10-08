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
    ConnectionError, RCEvent, RCState, RemoteClient, RemoteClientHandles, client_error_message,
    resolve_approved_ssh_chain,
};
use warpgate_web_clients_common::{
    ClientManager, LiveSessionPhase, register_provisional_web_client_session,
    run_web_client_lifecycle,
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
                    session.connect(chain);
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
                // Same boundary as the SSH path, for the same reason. Disclosure
                // only here rather than terminal injection — this lands in a
                // Svelte alert, which escapes — but the text is the one
                // `client_message` exists to keep away from a user.
                error!(%session_id, error=%e, "Client session error");
                let message = client_error_message(&e).to_owned();
                final_result = Err(notice(session, message, e).await.into());
            }
            RCEvent::ConnectionError(e) => {
                // `Vault`, `Aws` and `Warpgate` arrive here with no error-level
                // log anywhere upstream — the connect path logs at debug!, under
                // the default `warpgate=info` filter — so without this a
                // certificate failure leaves the server side with no record at
                // all, only the sanitised text below.
                error!(%session_id, error=%e, "Target connection failed");
                let message = shown_to_the_browser(&e);
                final_result = Err(notice(session, message, e.into()).await.into());
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

/// Tells the browser `message` and hands `error` on to close the session.
///
/// The two are separate on purpose: the error's own `Display` is what this
/// boundary keeps from the browser, and the close reason it becomes is rendered
/// through `user_facing_reason`, which reduces it to a status phrase.
async fn notice(session: &WebSshSession, message: String, error: anyhow::Error) -> anyhow::Error {
    session.push(ServerMessage::Error { message }).await;
    error
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
        assert!(
            !shown.contains("SELECT"),
            "the raw error reached the browser: {shown}"
        );
        assert!(
            !shown.contains("database error"),
            "the raw error reached the browser: {shown}"
        );
        assert_eq!(shown, leaky.client_message());
    }
}

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

use crate::protocol::ServerMessage;
use crate::session::{PendingHostKey, WebSshSession};

/// A failure the browser is about to be told of, as `notice` takes it.
///
/// A type rather than a `String` parameter, because the guard here is the
/// *choice* — `client_message()` and not `Display` — and a `String` can be
/// built from either. There is no constructor from text, so a `notice` call
/// that passes `e.to_string()` does not compile. A direct
/// `ServerMessage::Error` push would still bypass it; `notice` is the only one
/// today.
///
/// The server-side record lives here too, for the opposite reason: the log is
/// where the full error belongs, escaped so that remote text cannot forge a
/// record.
enum BrowserNotice<'a> {
    Client(&'a anyhow::Error),
    Connection(&'a ConnectionError),
}

impl BrowserNotice<'_> {
    fn message(&self) -> String {
        match self {
            Self::Client(error) => client_error_message(error).to_owned(),
            Self::Connection(error) => error.client_message(),
        }
    }

    /// `{:?}` and not `{}`: `ConnectionError::Io` is transparent, so a newline
    /// in remote text would otherwise forge a second record in the default
    /// text format. An `anyhow::Error`'s own `Debug` is multi-line and
    /// unescaped, so that variant is rendered first and the string escaped.
    fn log(&self, session_id: UserSessionId) {
        match self {
            Self::Client(error) => {
                error!(session=%session_id, error = ?format!("{error:#}"), "Client session error");
            }
            // The connect path logs it as well, but this is the record on the
            // side that knows which browser session was told what.
            Self::Connection(error) => {
                error!(session=%session_id, ?error, "Target connection failed");
            }
        }
    }
}

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
                notice(session, &BrowserNotice::Client(&e)).await;
                final_result = Err(e.into());
            }
            RCEvent::ConnectionError(e) => {
                notice(session, &BrowserNotice::Connection(&e)).await;
                final_result = Err(anyhow::Error::from(e).into());
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

/// Records the failure and tells the browser the sanitised form of it.
///
/// The browser text is derived while the concrete error type is still known:
/// once it is an `anyhow::Error`, a `ConnectionError` no longer downcasts to
/// anything `client_error_message` recognises. The error itself goes on to
/// close the session.
async fn notice(session: &WebSshSession, failure: &BrowserNotice<'_>) {
    failure.log(session.id());
    session
        .push(ServerMessage::Error {
            message: failure.message(),
        })
        .await;
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::fmt::MakeWriter;
    use warpgate_common::{UserSessionId, WarpgateError};

    use super::{BrowserNotice, ConnectionError};

    const SENTINEL: &str = "SELECT secret FROM credentials";

    /// The browser is told a fixed phrase, never the error's own words.
    ///
    /// Asserting on the `Warpgate` variant specifically is what makes this
    /// fail if the message reverts to `to_string()`.
    #[test]
    fn a_browser_never_sees_the_error_s_own_words() {
        let leaky = ConnectionError::Warpgate(WarpgateError::Other(
            format!("database error: {SENTINEL}").into(),
        ));
        assert!(
            leaky.to_string().contains(SENTINEL),
            "the fixture does not carry the sentinel, so nothing below is evidence"
        );

        let shown = BrowserNotice::Connection(&leaky).message();
        assert!(
            !shown.contains(SENTINEL),
            "the raw error reached the browser: {shown}"
        );
        assert!(
            !shown.contains("database error"),
            "the raw error reached the browser: {shown}"
        );
        assert_eq!(shown, leaky.client_message());
    }

    /// The other event the browser is told of. `RCEvent::Error` carries an
    /// `anyhow::Error`; this one interpolates the inner error's text, so its
    /// top-level `Display` carries the SQL.
    #[test]
    fn a_browser_never_sees_a_client_session_error_s_own_words() {
        let inner = WarpgateError::Other(format!("database error: {SENTINEL}").into());
        let leaky = anyhow::anyhow!("Error in command loop: {inner}");
        assert!(
            leaky.to_string().contains(SENTINEL),
            "the fixture does not carry the sentinel, so nothing below is evidence"
        );

        let shown = BrowserNotice::Client(&leaky).message();
        assert!(
            !shown.contains(SENTINEL),
            "the raw error reached the browser: {shown}"
        );
    }

    /// `tracing-subscriber` ships no `MakeWriter` for a buffer the test can
    /// still read afterwards: its `Arc<W>` impl wants `&W: Write`, which a
    /// `Mutex` is not.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl MakeWriter<'_> for Captured {
        type Writer = Self;

        fn make_writer(&self) -> Self::Writer {
            self.clone()
        }
    }

    /// One record out of the sink, with the formatter's trailing break removed.
    fn captured_record(failure: &BrowserNotice<'_>) -> String {
        let captured = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_writer(captured.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || failure.log(UserSessionId(uuid::Uuid::nil())));

        let logged = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        logged.strip_suffix('\n').unwrap_or(&logged).to_owned()
    }

    const FORGED: &str = "permission denied\n  ERROR warpgate::ssh: Authenticated with publickey";

    fn assert_one_escaped_record(record: &str) {
        assert!(
            !record.contains('\n'),
            "the error forged a second record: {record:?}"
        );
        assert!(
            record.contains("\\n"),
            "the error never reached the log: {record:?}"
        );
    }

    #[test]
    fn a_newline_in_a_connection_error_cannot_forge_a_web_ssh_log_record() {
        let error = ConnectionError::Io(std::io::Error::other(FORGED));
        assert!(
            error.to_string().contains('\n'),
            "the fixture carries no newline, so nothing below is evidence"
        );
        assert_one_escaped_record(&captured_record(&BrowserNotice::Connection(&error)));
    }

    #[test]
    fn a_newline_in_a_client_session_error_cannot_forge_a_web_ssh_log_record() {
        let error = anyhow::anyhow!(FORGED);
        assert!(
            format!("{error:?}").contains('\n'),
            "the fixture's Debug carries no raw newline, so nothing below is evidence"
        );
        assert_one_escaped_record(&captured_record(&BrowserNotice::Client(&error)));
    }
}

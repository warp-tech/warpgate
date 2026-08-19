use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use redis_protocol::codec::Resp3;
use redis_protocol::resp3::types::{BytesFrame, RespVersion};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tokio::time;
use tokio_util::codec::Framed;
use tracing::{debug, error, info, info_span, warn};
use url::Url;
use warpgate_common::auth::AuthSelector;
use warpgate_common::{Protocol, Secret, TargetRedisOptions, UserSessionId};
use warpgate_common_http::ext::construct_external_url;
use warpgate_core::{
    AdmittedTarget, ApprovedTarget, AuthOkPermit, DbAuthTransport, Services, WarpgateServerHandle,
    run_db_authorization,
};

use crate::client::RedisClient;
use crate::error::RedisError;

pub struct RedisSession<S: AsyncRead + AsyncWrite + Send + Unpin> {
    framed: Framed<S, Resp3>,
    username: Option<String>,
    /// Redis carries the password inline with `AUTH`/`HELLO`, so the shared
    /// auth flow can only be handed it once - never prompted for it again.
    pending_password: Option<Secret<String>>,
    /// Set when the client authenticated via `HELLO` rather than plain `AUTH`,
    /// so the success reply can echo the RESP3 handshake it expects.
    hello_version: Option<RespVersion>,
    server_handle: Arc<Mutex<WarpgateServerHandle>>,
    id: UserSessionId,
    services: Services,
    remote_address: SocketAddr,
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin> DbAuthTransport for RedisSession<S> {
    type Error = RedisError;

    const PROTOCOL: Protocol = crate::common::PROTOCOL_NAME;
    const SUPPORTS_WEB_APPROVAL: bool = false;

    /// The password arrived with `AUTH`/`HELLO`. There is no second prompt in
    /// the RESP protocol, so a repeat request denies the login.
    async fn prompt_password(&mut self) -> Result<Option<Secret<String>>, RedisError> {
        Ok(self.pending_password.take())
    }

    async fn send_auth_ok(&mut self, _permit: AuthOkPermit) -> Result<(), RedisError> {
        let reply = match self.hello_version.clone() {
            Some(version) => hello_reply_frame(version),
            None => BytesFrame::SimpleString {
                data: Bytes::from_static(b"OK"),
                attributes: None,
            },
        };
        self.framed.send(reply).await?;
        Ok(())
    }

    async fn external_url(&mut self) -> Result<Url, RedisError> {
        Ok(construct_external_url(None, &*self.services.config.lock().await, None).await?)
    }

    /// RESP has no side-channel message a client displays mid-authentication,
    /// so a policy requiring web approval can't be satisfied over Redis.
    async fn send_web_approval_prompt(
        &mut self,
        _url: &Url,
        _identification_string: &str,
    ) -> Result<bool, RedisError> {
        warn!("Web user approval is not supported over the Redis protocol");
        Ok(false)
    }

    async fn send_denied(&mut self) -> Result<(), RedisError> {
        self.send_error("WRONGPASS invalid username-password pair or user is disabled.")
            .await
    }
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin> RedisSession<S> {
    pub async fn new(
        server_handle: Arc<Mutex<WarpgateServerHandle>>,
        services: Services,
        stream: S,
        remote_address: SocketAddr,
    ) -> Self {
        let id = server_handle.lock().await.user_session_id();
        Self {
            framed: Framed::new(stream, Resp3::default()),
            username: None,
            pending_password: None,
            hello_version: None,
            server_handle,
            id,
            services,
            remote_address,
        }
    }

    pub fn make_logging_span(&self) -> tracing::Span {
        let client_ip = self.remote_address.ip().to_string();
        if let Some(ref username) = self.username {
            info_span!("Redis", session=%self.id, session_username=%username, %client_ip)
        } else {
            info_span!("Redis", session=%self.id, %client_ip)
        }
    }

    async fn send_error(&mut self, message: &str) -> Result<(), RedisError> {
        self.framed
            .send(BytesFrame::SimpleError {
                data: message.to_string().into(),
                attributes: None,
            })
            .await?;
        Ok(())
    }

    async fn send_noauth(&mut self) -> Result<(), RedisError> {
        self.send_error("NOAUTH Authentication required.").await
    }

    /// RESP has no dedicated handshake: authentication is driven by whatever
    /// the client sends first. Anything other than a recognized `AUTH`/`HELLO`
    /// gets the same `NOAUTH` error a `requirepass`-enabled Redis would send,
    /// so ordinary clients retry with credentials without special-casing.
    pub async fn run(mut self) -> Result<(), RedisError> {
        loop {
            let Some(frame) = self.framed.next().await.transpose()? else {
                return Ok(());
            };

            if let BytesFrame::Hello { version, auth, .. } = &frame {
                match auth {
                    Some((username, password)) => {
                        self.hello_version = Some(version.clone());
                        let selector = username.to_string();
                        let password = Secret::from(password.to_string());
                        return self.authenticate(selector, password).await;
                    }
                    None => {
                        self.send_error(NOAUTH_HELLO_MESSAGE).await?;
                        continue;
                    }
                }
            }

            let Some(args) = frame_as_command(&frame) else {
                self.send_error("ERR Protocol error: expected a command array")
                    .await?;
                return Ok(());
            };

            let Some(command) = args.first() else {
                self.send_noauth().await?;
                continue;
            };

            if command.eq_ignore_ascii_case(b"HELLO") {
                match parse_hello(&args) {
                    Ok(Some((username, password, version))) => {
                        self.hello_version = Some(version);
                        return self.authenticate(username, password).await;
                    }
                    Ok(None) => {
                        self.send_error(NOAUTH_HELLO_MESSAGE).await?;
                    }
                    Err(message) => {
                        self.send_error(&message).await?;
                    }
                }
            } else if command.eq_ignore_ascii_case(b"AUTH") {
                match args.len() {
                    2 => {
                        self.send_error(
                            "ERR Warpgate requires a username: send AUTH <warpgate-user>#<target> <password>",
                        )
                        .await?;
                    }
                    3 => {
                        let username = String::from_utf8_lossy(&args[1]).into_owned();
                        let password = Secret::from(String::from_utf8_lossy(&args[2]).into_owned());
                        return self.authenticate(username, password).await;
                    }
                    _ => {
                        self.send_error("ERR wrong number of arguments for 'auth' command")
                            .await?;
                    }
                }
            } else {
                self.send_noauth().await?;
            }
        }
    }

    async fn authenticate(
        mut self,
        raw_selector: String,
        password: Secret<String>,
    ) -> Result<(), RedisError> {
        self.username = Some(raw_selector.clone());
        self.pending_password = Some(password);

        let selector: AuthSelector = raw_selector.into();
        let remote_ip = self.remote_address.ip();
        let session_id = self.id;
        let services = self.services.clone();

        let Some(approved) =
            run_db_authorization(&mut self, &services, session_id, selector, remote_ip).await?
        else {
            return Ok(());
        };

        self.run_authorized(approved).await
    }

    async fn run_authorized(mut self, approved: ApprovedTarget) -> Result<(), RedisError> {
        let Ok(approved) = approved.narrow::<TargetRedisOptions>() else {
            warn!("Selected target is not a Redis target");
            self.send_error("ERR Warpgate target not found").await?;
            return Ok(());
        };

        let admitted = self
            .server_handle
            .lock()
            .await
            .register_approved_target_session(approved)
            .await?;

        self.run_authorized_inner(admitted).await
    }

    async fn run_authorized_inner(
        mut self,
        admitted: AdmittedTarget<TargetRedisOptions>,
    ) -> Result<(), RedisError> {
        let options = admitted.specific_target().options().clone();
        let mut client = match RedisClient::connect(&options).await {
            Err(error) => {
                self.send_error("ERR Warpgate target connection failed")
                    .await?;
                Err(error)
            }
            x => x,
        }?;

        let idle_timeout = match parse_idle_timeout(options.idle_timeout.as_deref()) {
            IdlePolicy::Disabled => None,
            IdlePolicy::Timeout(timeout) => {
                info!(
                    idle_timeout_seconds = timeout.as_secs(),
                    "Using configured idle timeout for session"
                );
                Some(timeout)
            }
        };

        let mut last_activity = std::time::Instant::now();
        let check_interval = Duration::from_secs(5);

        loop {
            let select_timeout = match idle_timeout {
                Some(timeout) => {
                    let elapsed = last_activity.elapsed();
                    if elapsed > timeout {
                        info!(
                            idle_seconds = elapsed.as_secs(),
                            timeout_seconds = timeout.as_secs(),
                            "Session idle timeout exceeded, closing connection"
                        );
                        self.send_error(&format!(
                            "ERR Session idle for {} exceeded configured timeout of {}. Please reconnect.",
                            humantime::format_duration(elapsed),
                            humantime::format_duration(timeout)
                        ))
                        .await?;
                        break;
                    }
                    timeout.saturating_sub(elapsed).min(check_interval)
                }
                None => check_interval,
            };

            tokio::select! {
                c_to_s = time::timeout(select_timeout, self.framed.next()) => {
                    match c_to_s {
                        Ok(Some(Ok(frame))) => {
                            last_activity = std::time::Instant::now();
                            maybe_log_client_frame(&frame);
                            client.send(frame).await?;
                        }
                        Ok(Some(Err(error))) => {
                            error!(%error, "Error receiving message");
                            break;
                        }
                        Ok(None) => break,
                        Err(_) => {
                            // Timeout tick - loop back around to re-check idle timeout.
                        }
                    }
                },
                s_to_c = client.recv() => {
                    match s_to_c {
                        Ok(Some(frame)) => {
                            last_activity = std::time::Instant::now();
                            maybe_log_server_frame(&frame);
                            self.framed.send(frame).await?;
                        }
                        Ok(None) => break,
                        Err(error) => {
                            error!(%error, "Error receiving message");
                            break;
                        }
                    }
                }
            };
        }

        Ok(())
    }
}

const NOAUTH_HELLO_MESSAGE: &str = "NOAUTH HELLO must be called with the client already authenticated, otherwise the HELLO <proto> AUTH <user> <pass> option can be used to authenticate the client and select the RESP protocol version at the same time";

/// Extracts a command name and its arguments from a decoded frame, if it's a
/// plain array of strings - the shape every real RESP client sends commands
/// as. Anything else (a bare `HELLO` sent as an inline command is handled
/// separately) isn't a command Warpgate can gate on.
fn frame_as_command(frame: &BytesFrame) -> Option<Vec<Bytes>> {
    let BytesFrame::Array { data, .. } = frame else {
        return None;
    };
    data.iter()
        .map(|f| match f {
            BytesFrame::BlobString { data, .. } => Some(data.clone()),
            BytesFrame::SimpleString { data, .. } => Some(data.clone()),
            _ => None,
        })
        .collect()
}

/// Parses `HELLO [protover [AUTH username password] [SETNAME name]]` sent as
/// a normal command array. `Ok(None)` means no inline `AUTH` clause was
/// given - the caller should ask the client to retry with one.
fn parse_hello(args: &[Bytes]) -> Result<Option<(String, Secret<String>, RespVersion)>, String> {
    let version = match args.get(1).map(Bytes::as_ref) {
        None => return Ok(None),
        Some(b"2") => RespVersion::RESP2,
        Some(b"3") => RespVersion::RESP3,
        Some(_) => return Err("NOPROTO unsupported protocol version".to_string()),
    };

    let mut auth = None;
    let mut i = 2;
    while i < args.len() {
        if args[i].eq_ignore_ascii_case(b"AUTH") {
            if i + 2 >= args.len() {
                return Err("ERR syntax error in HELLO".to_string());
            }
            let username = String::from_utf8_lossy(&args[i + 1]).into_owned();
            let password = Secret::from(String::from_utf8_lossy(&args[i + 2]).into_owned());
            auth = Some((username, password));
            i += 3;
        } else if args[i].eq_ignore_ascii_case(b"SETNAME") {
            if i + 1 >= args.len() {
                return Err("ERR syntax error in HELLO".to_string());
            }
            i += 2;
        } else {
            return Err("ERR syntax error in HELLO".to_string());
        }
    }

    Ok(auth.map(|(username, password)| (username, password, version)))
}

fn str_frame(s: &str) -> BytesFrame {
    BytesFrame::SimpleString {
        data: Bytes::copy_from_slice(s.as_bytes()),
        attributes: None,
    }
}

fn hello_reply_frame(version: RespVersion) -> BytesFrame {
    let proto: i64 = match version {
        RespVersion::RESP2 => 2,
        RespVersion::RESP3 => 3,
    };
    let entries: Vec<(BytesFrame, BytesFrame)> = vec![
        (str_frame("server"), str_frame("redis")),
        (
            str_frame("proto"),
            BytesFrame::Number {
                data: proto,
                attributes: None,
            },
        ),
        (str_frame("mode"), str_frame("standalone")),
        (str_frame("role"), str_frame("master")),
        (
            str_frame("modules"),
            BytesFrame::Array {
                data: vec![],
                attributes: None,
            },
        ),
    ];

    match version {
        RespVersion::RESP3 => BytesFrame::Map {
            data: entries.into_iter().collect(),
            attributes: None,
        },
        RespVersion::RESP2 => BytesFrame::Array {
            data: entries.into_iter().flat_map(|(k, v)| [k, v]).collect(),
            attributes: None,
        },
    }
}

fn maybe_log_client_frame(frame: &BytesFrame) {
    if let Some(args) = frame_as_command(frame)
        && let Some(command) = args.first()
    {
        let name = String::from_utf8_lossy(command).to_ascii_uppercase();
        debug!(%name, "C->S command");
        return;
    }
    debug!(?frame, "C->S message");
}

fn maybe_log_server_frame(frame: &BytesFrame) {
    if let BytesFrame::SimpleError { data, .. } = frame {
        info!(error = %data, "Redis error");
    } else {
        debug!(?frame, "S->C message");
    }
}

const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_mins(10);

enum IdlePolicy {
    /// No idle timeout: the proxy never closes an idle session.
    Disabled,
    Timeout(Duration),
}

/// Map a configured `idle_timeout` string to an effective policy. An explicit
/// zero duration (`"0"`, `"0s"`) disables the timeout; an unset or unparseable
/// value falls back to [`DEFAULT_IDLE_TIMEOUT`].
fn parse_idle_timeout(value: Option<&str>) -> IdlePolicy {
    let Some(trimmed) = value.map(str::trim).filter(|s| !s.is_empty()) else {
        return IdlePolicy::Timeout(DEFAULT_IDLE_TIMEOUT);
    };
    match humantime::parse_duration(trimmed) {
        Ok(duration) if duration.is_zero() => IdlePolicy::Disabled,
        Ok(duration) => IdlePolicy::Timeout(duration),
        Err(error) => {
            warn!(
                timeout_string = %trimmed,
                error = %error,
                "Invalid idle_timeout value, falling back to default"
            );
            IdlePolicy::Timeout(DEFAULT_IDLE_TIMEOUT)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{DEFAULT_IDLE_TIMEOUT, IdlePolicy, parse_idle_timeout};

    #[test]
    fn explicit_zero_disables() {
        assert!(matches!(
            parse_idle_timeout(Some("0")),
            IdlePolicy::Disabled
        ));
        assert!(matches!(
            parse_idle_timeout(Some("0s")),
            IdlePolicy::Disabled
        ));
    }

    #[test]
    fn valid_duration_is_used() {
        assert!(matches!(
            parse_idle_timeout(Some("30m")),
            IdlePolicy::Timeout(d) if d == Duration::from_secs(30 * 60)
        ));
    }

    #[test]
    fn unset_or_unparseable_uses_default() {
        assert!(matches!(
            parse_idle_timeout(None),
            IdlePolicy::Timeout(d) if d == DEFAULT_IDLE_TIMEOUT
        ));
        assert!(matches!(
            parse_idle_timeout(Some("garbage")),
            IdlePolicy::Timeout(d) if d == DEFAULT_IDLE_TIMEOUT
        ));
    }
}

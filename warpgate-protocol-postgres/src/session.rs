use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use pgwire::error::ErrorInfo;
use pgwire::messages::startup::SecretKey;
use pgwire::messages::{
    DecodeContext, PgWireBackendMessage, PgWireFrontendMessage, ProtocolVersion,
};
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tokio::time;
use tracing::{debug, error, info, info_span, warn};
use url::Url;
use warpgate_common::auth::AuthSelector;
use warpgate_common::{
    PostgresProtocolVersion, Protocol, Secret, TargetPostgresOptions, UserSessionId,
};
use warpgate_common_http::ext::construct_external_url;
use warpgate_core::{
    ApprovedTarget, AuthOkPermit, DbAuthTransport, Services, TargetAuthorization,
    WarpgateServerHandle, run_db_authorization,
};
use warpgate_tls::ServerTlsStream;

use crate::client::{ConnectionOptions, PostgresClient};
use crate::error::PostgresError;
use crate::stream::{
    PgWireGenericBackendMessage, PgWireGenericFrontendMessage, PgWireStartupOrSslRequest,
    PostgresStream,
};

pub struct PostgresSession<S: AsyncRead + AsyncWrite + Send + Unpin> {
    stream: PostgresStream<S, ServerTlsStream<S>>,
    tls_config: Arc<ServerConfig>,
    username: Option<String>,
    database: Option<String>,
    server_handle: Arc<Mutex<WarpgateServerHandle>>,
    id: UserSessionId,
    services: Services,
    remote_address: SocketAddr,
    decode_context: DecodeContext,
    /// Used to remap cancel keys when the target uses protocol 3.2
    /// but the client only supports 3.0
    cancel_key_downgrade_map: HashMap<SecretKey, SecretKey>,
    /// Used to remap cancel keys when the target uses protocol 3.0
    /// but the client already supports 3.2
    cancel_key_upgrade_map: HashMap<SecretKey, SecretKey>,
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin> DbAuthTransport for PostgresSession<S> {
    type Error = PostgresError;

    const PROTOCOL: Protocol = crate::common::PROTOCOL_NAME;
    const SUPPORTS_WEB_APPROVAL: bool = true;

    async fn prompt_password(&mut self) -> Result<Option<Secret<String>>, PostgresError> {
        self.stream
            .push(pgwire::messages::startup::Authentication::CleartextPassword)?;
        self.stream.flush().await?;

        let Some(PgWireGenericFrontendMessage(PgWireFrontendMessage::PasswordMessageFamily(
            message,
        ))) = self
            .stream
            .recv::<PgWireGenericFrontendMessage>(&self.decode_context)
            .await?
        else {
            return Err(PostgresError::Eof);
        };

        Ok(Some(Secret::from(
            message
                .into_password()
                .map_err(PostgresError::from)?
                .password,
        )))
    }

    async fn send_auth_ok(&mut self, _permit: AuthOkPermit) -> Result<(), PostgresError> {
        self.stream
            .push(pgwire::messages::startup::Authentication::Ok)?;
        Ok(())
    }

    async fn external_url(&mut self) -> Result<Url, PostgresError> {
        Ok(construct_external_url(None, &*self.services.config.lock().await, None).await?)
    }

    async fn send_web_approval_prompt(
        &mut self,
        url: &Url,
        identification_string: &str,
    ) -> Result<bool, PostgresError> {
        self.stream
            .push(pgwire::messages::response::NoticeResponse::new(vec![
                (b'S', "WARNING".into()),
                (b'V', "WARNING".into()),
                (b'C', "WG001".into()),
                (
                    b'M',
                    "Warpgate authentication: please open the following URL in your browser:"
                        .into(),
                ),
                (b'D', url.to_string()),
                (
                    b'H',
                    format!(
                        "Make sure you're seeing this security key: {}\n",
                        identification_string
                            .chars()
                            .map(|x| x.to_string())
                            .collect::<Vec<_>>()
                            .join(" ")
                    ),
                ),
            ]))?;
        self.stream.flush().await?;
        Ok(true)
    }

    async fn send_denied(&mut self) -> Result<(), PostgresError> {
        let error_info = ErrorInfo::new(
            "FATAL".to_owned(),
            "28P01".to_owned(),
            "Authentication failed".to_owned(),
        );
        self.stream
            .push(pgwire::messages::response::ErrorResponse::from(error_info))?;
        self.stream.flush().await?;
        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin> PostgresSession<S> {
    pub async fn new(
        server_handle: Arc<Mutex<WarpgateServerHandle>>,
        services: Services,
        stream: S,
        tls_config: ServerConfig,
        remote_address: SocketAddr,
    ) -> Self {
        let id = server_handle.lock().await.user_session_id();

        Self {
            services,
            tls_config: Arc::new(tls_config),
            stream: PostgresStream::new(stream),
            username: None,
            database: None,
            server_handle,
            id,
            remote_address,
            decode_context: DecodeContext::new(pgwire::messages::ProtocolVersion::PROTOCOL3_2),
            cancel_key_downgrade_map: HashMap::new(),
            cancel_key_upgrade_map: HashMap::new(),
        }
    }

    pub fn make_logging_span(&self) -> tracing::Span {
        let client_ip = self.remote_address.ip().to_string();
        if let Some(ref username) = self.username {
            info_span!("PostgreSQL", session=%self.id, session_username=%username, %client_ip)
        } else {
            info_span!("PostgreSQL", session=%self.id, %client_ip)
        }
    }

    pub async fn run(mut self) -> Result<(), PostgresError> {
        let mut tls_established = false;

        // libpq negotiates in up to three steps: an optional GSSAPI encryption
        // request, an optional SSL request, then the StartupMessage.
        let startup = loop {
            let Some(message) = self
                .stream
                .recv::<PgWireStartupOrSslRequest>(&self.decode_context)
                .await?
            else {
                return Err(PostgresError::Eof);
            };

            match message {
                PgWireStartupOrSslRequest::GssEncRequest(_) => {
                    debug!("Received GssEncRequest, refusing");
                    self.stream
                        .push(pgwire::messages::response::GssEncResponse::Refuse)?;
                    self.stream.flush().await?;
                }
                PgWireStartupOrSslRequest::SslRequest(_) => {
                    if tls_established {
                        return Err(PostgresError::ProtocolError(
                            "unexpected SslRequest inside a TLS session".into(),
                        ));
                    }
                    debug!("Received SslRequest");
                    self.stream
                        .push(pgwire::messages::response::SslResponse::Accept)?;
                    self.stream.flush().await?;
                    self.stream = self.stream.upgrade(self.tls_config.clone()).await?;
                    self.decode_context.awaiting_frontend_ssl = false;
                    tls_established = true;
                    debug!("TLS setup complete");
                }
                PgWireStartupOrSslRequest::Startup(startup) => {
                    if !tls_established {
                        self.send_error_response(
                            "08P01".into(),
                            "SSL connection required - please enable SSL in your client (e.g., add `sslmode=require` to your connection string)".into(),
                        )
                        .await?;
                        return Ok(());
                    }
                    break startup;
                }
            }
        };

        self.decode_context.awaiting_frontend_startup = false;

        let Some(protocol_version) = ProtocolVersion::from_version_number(
            startup.protocol_number_major,
            startup.protocol_number_minor,
        ) else {
            error!(
                major = startup.protocol_number_major,
                minor = startup.protocol_number_minor,
                "Client requested unsupported protocol version"
            );
            self.send_error_response(
                "0W002".into(),
                format!(
                    "Unsupported protocol version: {}.{}",
                    startup.protocol_number_major, startup.protocol_number_minor
                ),
            )
            .await?;
            return Ok(());
        };

        let username = startup.parameters.get("user").cloned();
        self.decode_context.protocol_version = protocol_version;
        self.username = username.clone();
        self.database = startup.parameters.get("database").cloned();

        self.run_authorization(startup, &username.unwrap_or_else(|| "".into()))
            .await
    }

    pub async fn run_authorization(
        mut self,
        startup: pgwire::messages::startup::Startup,
        username: &String,
    ) -> Result<(), PostgresError> {
        let selector: AuthSelector = username.into();
        let remote_ip = self.remote_address.ip();
        let session_id = self.server_handle.lock().await.user_session_id();

        let services = self.services.clone();
        let Some(authorization) =
            run_db_authorization(&mut self, &services, session_id, selector, remote_ip).await?
        else {
            return Ok(());
        };

        self.run_authorized(startup, authorization).await
    }

    async fn run_authorized(
        mut self,
        startup: pgwire::messages::startup::Startup,
        authorization: TargetAuthorization,
    ) -> Result<(), PostgresError> {
        if let Some(banner) = warpgate_db_entities::Parameters::Entity::get(&self.services.db)
            .await
            .map_err(PostgresError::other)?
            .banner_text()
        {
            self.stream
                .push(pgwire::messages::response::NoticeResponse::new(vec![
                    (b'S', "NOTICE".into()),
                    (b'V', "NOTICE".into()),
                    (b'C', "WG002".into()),
                    (b'M', banner.into()),
                ]))?;
        }

        self.stream.flush().await?;

        let target_name = authorization.target().name.clone();
        let authorization = match authorization.narrow::<TargetPostgresOptions>() {
            Ok(authorization) => authorization,
            Err(_) => {
                warn!("Selected target is not a PostgreSQL target");
                self.send_error_response(
                    "0W001".into(),
                    format!("Warpgate target {target_name} not found"),
                )
                .await?;
                return Ok(());
            }
        };

        let (_, approved) = self
            .server_handle
            .lock()
            .await
            .start_target_session(authorization)
            .await?
            .admitted()?;

        self.run_authorized_inner(startup, approved).await
    }

    async fn send_error_response(
        &mut self,
        code: String,
        message: String,
    ) -> Result<(), PostgresError> {
        let error_info = ErrorInfo::new("FATAL".to_owned(), code, message);
        self.stream
            .push(pgwire::messages::response::ErrorResponse::from(error_info))?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn run_authorized_inner(
        mut self,
        startup: pgwire::messages::startup::Startup,
        approved: ApprovedTarget<TargetPostgresOptions>,
    ) -> Result<(), PostgresError> {
        let options = approved.options().clone();
        let target_protocol_version = match options.protocol_version.unwrap_or_default() {
            PostgresProtocolVersion::V3_0 => ProtocolVersion::PROTOCOL3_0,
            PostgresProtocolVersion::V3_2 => ProtocolVersion::PROTOCOL3_2,
        };

        let mut client = match PostgresClient::connect(
            approved,
            ConnectionOptions {
                protocol_version: target_protocol_version,
                parameters: startup.parameters,
            },
        )
        .await
        {
            Err(error) => {
                self.send_error_response(
                    "0W002".into(),
                    "Warpgate target connection failed".into(),
                )
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
        let check_interval = Duration::from_secs(5); // Check idle timeout every 5 seconds

        loop {
            // With the idle timeout disabled we still wake up on check_interval
            // to re-poll the sockets, but never close the connection ourselves.
            let select_timeout = match idle_timeout {
                Some(timeout) => {
                    let elapsed = last_activity.elapsed();
                    if elapsed > timeout {
                        info!(
                            idle_seconds = elapsed.as_secs(),
                            timeout_seconds = timeout.as_secs(),
                            "Session idle timeout exceeded, closing connection"
                        );
                        self.send_error_response(
                            "57P01".into(),
                            format!(
                                "Session idle for {} exceeded configured timeout of {}. Please reconnect.",
                                humantime::format_duration(elapsed),
                                humantime::format_duration(timeout)
                            ),
                        )
                        .await?;
                        break;
                    }
                    timeout.saturating_sub(elapsed).min(check_interval)
                }
                None => check_interval,
            };

            tokio::select! {
                c_to_s = time::timeout(select_timeout, self.stream.recv::<PgWireGenericFrontendMessage>(&self.decode_context)) => {
                    match c_to_s {
                        Ok(Ok(Some(mut msg))) => {
                            last_activity = std::time::Instant::now(); // Update activity on client message
                            Self::maybe_log_client_msg(&msg.0);
                            msg = self.maybe_transform_client_msg(msg, &client);
                            client.send(msg).await?;
                        }
                        Ok(Ok(None)) => {
                            break
                        }
                        Ok(Err(err)) => {
                            error!(error=%err, "Error receiving message");
                            break
                        }
                        Err(_) => {
                            // Timeout - check if we've exceeded idle timeout
                        }
                    }
                },
                s_to_c = client.recv() => {
                    match s_to_c {
                        Ok(Some(mut msg)) => {
                            last_activity = std::time::Instant::now(); // Update activity on server message
                            Self::maybe_log_server_msg(&msg.0);
                            msg = self.maybe_transform_server_msg(msg);
                            self.stream.push(msg)?;
                            self.stream.flush().await?;
                        }
                        Ok(None) => {
                            break
                        }
                        Err(err) => {
                            error!(error=%err, "Error receiving message");
                            break
                        }
                    }
                }
            };
        }

        Ok(())
    }

    /// Needed to downgrade cancel key handling from 3.2 to 3.0 protocol
    fn maybe_transform_client_msg(
        &mut self,
        mut msg: PgWireGenericFrontendMessage,
        client: &PostgresClient,
    ) -> PgWireGenericFrontendMessage {
        if let PgWireFrontendMessage::CancelRequest(cancel_request) = &mut msg.0 {
            // Transform cancel keys back to 3.2 format if needed
            if let SecretKey::I32(_) = cancel_request.secret_key
                && let Some(upgraded_key) = self
                    .cancel_key_downgrade_map
                    .remove(&cancel_request.secret_key)
            {
                cancel_request.secret_key = upgraded_key;
            }
            if client.protocol_version() == ProtocolVersion::PROTOCOL3_0 {
                // Transform cancel keys to 3.0 format if needed
                if let SecretKey::Bytes(_) = cancel_request.secret_key
                    && let Some(downgraded_key) = self
                        .cancel_key_upgrade_map
                        .remove(&cancel_request.secret_key)
                {
                    cancel_request.secret_key = downgraded_key;
                }
            }
        }
        msg
    }

    fn maybe_transform_server_msg(
        &mut self,
        mut msg: PgWireGenericBackendMessage,
    ) -> PgWireGenericBackendMessage {
        if let PgWireBackendMessage::BackendKeyData(key_data) = &mut msg.0 {
            // Locally issue a 3.0 protocol key in older format and store mapping
            if self.decode_context.protocol_version == ProtocolVersion::PROTOCOL3_0 {
                // Locally issue a random key in older format and store mapping
                if let SecretKey::Bytes(bytes) = &key_data.secret_key {
                    let downgraded_key = SecretKey::I32(rand::random::<i32>());
                    self.cancel_key_downgrade_map
                        .insert(downgraded_key.clone(), SecretKey::Bytes(bytes.clone()));
                    key_data.secret_key = downgraded_key;
                }
            }
            if self.decode_context.protocol_version == ProtocolVersion::PROTOCOL3_2 {
                // Locally issue a 3.2 protocol key in newer format and store mapping
                if let SecretKey::I32(_) = key_data.secret_key {
                    let value = rand::random::<[u8; 32]>();
                    let upgraded_key = SecretKey::Bytes(Bytes::from_owner(value));
                    self.cancel_key_upgrade_map
                        .insert(upgraded_key.clone(), key_data.secret_key.clone());
                    key_data.secret_key = upgraded_key;
                }
            }
        }
        msg
    }

    fn maybe_log_client_msg(msg: &PgWireFrontendMessage) {
        debug!(?msg, "C->S message");
        match msg {
            PgWireFrontendMessage::Parse(query) => {
                info!(query_name=?query.name, query=query.query, "Preparing query");
            }
            PgWireFrontendMessage::Execute(query) => {
                info!(query_name=?query.name, "Executing prepared query");
            }
            PgWireFrontendMessage::Query(query) => {
                info!(query=%query.query, "Query");
            }
            _ => (),
        }
    }

    fn maybe_log_server_msg(msg: &PgWireBackendMessage) {
        debug!(?msg, "S->C message");
        if let PgWireBackendMessage::ErrorResponse(error) = msg {
            info!(?error, "PostgreSQL error");
        }
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

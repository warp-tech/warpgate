use std::net::SocketAddr;
use std::sync::Arc;

use pgwire::error::ErrorInfo;
use pgwire::messages::response::TransactionStatus;
use pgwire::messages::PgWireFrontendMessage;
use rustls::ServerConfig;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::server::TlsStream;
use tracing::*;
use uuid::Uuid;
use warpgate_common::auth::{AuthCredential, AuthResult, AuthSelector, CredentialKind};
use warpgate_common::Secret;
use warpgate_core::{authorize_ticket, consume_ticket, Services, WarpgateServerHandle};

use crate::error::PostgresError;
use crate::stream::{PgWireGenericFrontendMessage, PgWireStartupOrSslRequest, PostgresStream};

pub struct PostgresSession {
    stream: PostgresStream<TlsStream<TcpStream>>,
    tls_config: Arc<ServerConfig>,
    // capabilities: Capabilities,
    // challenge: [u8; 20],
    username: Option<String>,
    database: Option<String>,
    server_handle: Arc<Mutex<WarpgateServerHandle>>,
    id: Uuid,
    services: Services,
    remote_address: SocketAddr,
}

impl PostgresSession {
    pub async fn new(
        server_handle: Arc<Mutex<WarpgateServerHandle>>,
        services: Services,
        stream: TcpStream,
        tls_config: ServerConfig,
        remote_address: SocketAddr,
    ) -> Self {
        let id = server_handle.lock().await.id();

        Self {
            services,
            tls_config: Arc::new(tls_config),
            stream: PostgresStream::new(stream),
            username: None,
            database: None,
            server_handle,
            id,
            remote_address,
        }
    }

    pub fn make_logging_span(&self) -> tracing::Span {
        let client_ip = self.remote_address.ip().to_string();
        match self.username {
            Some(ref username) => {
                info_span!("PostgreSQL", session=%self.id, session_username=%username, %client_ip)
            }
            None => info_span!("PostgreSQL", session=%self.id, %client_ip),
        }
    }

    pub async fn run(mut self) -> Result<(), PostgresError> {
        let Some(mut initial_message) = self.stream.recv::<PgWireStartupOrSslRequest>().await?
        else {
            return Err(PostgresError::Eof);
        };

        if let PgWireStartupOrSslRequest::SslRequest(_) = &initial_message {
            debug!("Received SslRequest");
            self.stream
                .push(pgwire::messages::response::SslResponse::Accept)?;
            self.stream.flush().await?;
            self.stream = self.stream.upgrade(self.tls_config.clone()).await?;
            debug!("TLS setup complete");

            let Some(next_message) = self.stream.recv::<PgWireStartupOrSslRequest>().await? else {
                return Err(PostgresError::Eof);
            };

            initial_message = next_message;
        }

        let PgWireStartupOrSslRequest::Startup(startup) = initial_message else {
            return Err(PostgresError::ProtocolError("expected Startup".into()));
        };

        self.stream
            .push(pgwire::messages::startup::Authentication::CleartextPassword)?;
        self.stream.flush().await?;

        let Some(PgWireGenericFrontendMessage(PgWireFrontendMessage::PasswordMessageFamily(
            message,
        ))) = self.stream.recv::<PgWireGenericFrontendMessage>().await?
        else {
            return Err(PostgresError::Eof);
        };

        let username = startup.parameters.get("user").cloned();
        self.username = username.clone();
        self.database = startup.parameters.get("database").cloned();

        let password = Secret::from(
            message
                .into_password()
                .map_err(PostgresError::from)?
                .password,
        );

        self.run_authorization(&username.unwrap_or("".into()), password)
            .await
    }

    pub async fn run_authorization(
        mut self,
        username: &String,
        password: Secret<String>,
    ) -> Result<(), PostgresError> {
        let selector: AuthSelector = username.into();

        async fn fail(this: &mut PostgresSession) -> Result<(), PostgresError> {
            let error_info = ErrorInfo::new(
                "FATAL".to_owned(),
                "28P01".to_owned(),
                "Authentication failed".to_owned(),
            );

            this.stream
                .push(pgwire::messages::response::ErrorResponse::from(error_info))?;
            this.stream.flush().await?;
            Ok(())
        }

        match selector {
            AuthSelector::User {
                username,
                target_name,
            } => {
                let state_arc = self
                    .services
                    .auth_state_store
                    .lock()
                    .await
                    .create(
                        Some(&self.server_handle.lock().await.id()),
                        &username,
                        crate::common::PROTOCOL_NAME,
                        &[CredentialKind::Password],
                    )
                    .await?
                    .1;
                let mut state = state_arc.lock().await;

                let user_auth_result = {
                    let credential = AuthCredential::Password(password);

                    let mut cp = self.services.config_provider.lock().await;
                    if cp.validate_credential(&username, &credential).await? {
                        state.add_valid_credential(credential);
                    }

                    state.verify()
                };

                match user_auth_result {
                    AuthResult::Accepted { username } => {
                        self.services
                            .auth_state_store
                            .lock()
                            .await
                            .complete(state.id())
                            .await;
                        let target_auth_result = {
                            self.services
                                .config_provider
                                .lock()
                                .await
                                .authorize_target(&username, &target_name)
                                .await
                                .map_err(PostgresError::other)?
                        };
                        if !target_auth_result {
                            warn!(
                                "Target {} not authorized for user {}",
                                target_name, username
                            );
                            return fail(&mut self).await;
                        }
                        self.run_authorized(username, target_name).await
                    }
                    AuthResult::Rejected | AuthResult::Need(_) => fail(&mut self).await,
                }
            }
            AuthSelector::Ticket { secret } => {
                match authorize_ticket(&self.services.db, &secret)
                    .await
                    .map_err(PostgresError::other)?
                {
                    Some(ticket) => {
                        info!("Authorized for {} with a ticket", ticket.target);
                        consume_ticket(&self.services.db, &ticket.id)
                            .await
                            .map_err(PostgresError::other)?;

                        self.run_authorized(ticket.username, ticket.target).await
                    }
                    _ => fail(&mut self).await,
                }
            }
        }
    }

    async fn run_authorized(
        mut self,
        username: String,
        target_name: String,
    ) -> Result<(), PostgresError> {
        debug!(?username, ?target_name, "Running authorized session");

        self.stream
            .push(pgwire::messages::startup::Authentication::Ok)?;
        self.stream
            .push(pgwire::messages::response::ReadyForQuery::new(
                TransactionStatus::Idle,
            ))?;
        self.stream.flush().await?;

        loop {
            let Some(payload) = self.stream.recv::<PgWireGenericFrontendMessage>().await? else {
                return Err(PostgresError::Eof);
            };

            info!(?payload, "Received message");
        };
    }
}

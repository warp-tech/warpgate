use std::net::SocketAddr;
use std::sync::Arc;

use pgwire::error::ErrorInfo;
use pgwire::messages::{PgWireBackendMessage, PgWireFrontendMessage};
use rustls::ServerConfig;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::server::TlsStream;
use tracing::*;
use uuid::Uuid;
use warpgate_common::auth::{AuthCredential, AuthResult, AuthSelector, CredentialKind};
use warpgate_common::{Secret, TargetOptions, TargetPostgresOptions};
use warpgate_core::{
    authorize_ticket, consume_ticket, ConfigProvider, Services, WarpgateServerHandle,
};

use crate::client::{ConnectionOptions, PostgresClient};
use crate::error::PostgresError;
use crate::stream::{PgWireGenericFrontendMessage, PgWireStartupOrSslRequest, PostgresStream};

pub struct PostgresSession {
    stream: PostgresStream<TlsStream<TcpStream>>,
    tls_config: Arc<ServerConfig>,
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

        let username = startup.parameters.get("user").cloned();
        self.username = username.clone();
        self.database = startup.parameters.get("database").cloned();

        self.run_authorization(startup, &username.unwrap_or("".into()))
            .await
    }

    pub async fn run_authorization(
        mut self,
        startup: pgwire::messages::startup::Startup,
        username: &String,
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

                let mut auth_ok_sent = false;

                loop {
                    let user_auth_result = state_arc.lock().await.verify();

                    match user_auth_result {
                        AuthResult::Accepted { username } => {
                            self.services
                                .auth_state_store
                                .lock()
                                .await
                                .complete(state_arc.lock().await.id())
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
                                warn!("Target {target_name} not authorized for user {username}",);
                                return fail(&mut self).await;
                            }

                            if !auth_ok_sent {
                                self.stream
                                    .push(pgwire::messages::startup::Authentication::Ok)?;
                            }
                            return self.run_authorized(startup, username, target_name).await;
                        }
                        AuthResult::Need(kinds) => {
                            if kinds.contains(&CredentialKind::Password) {
                                self.stream.push(
                                    pgwire::messages::startup::Authentication::CleartextPassword,
                                )?;
                                self.stream.flush().await?;

                                let Some(PgWireGenericFrontendMessage(
                                    PgWireFrontendMessage::PasswordMessageFamily(message),
                                )) = self.stream.recv::<PgWireGenericFrontendMessage>().await?
                                else {
                                    return Err(PostgresError::Eof);
                                };

                                let password = Secret::from(
                                    message
                                        .into_password()
                                        .map_err(PostgresError::from)?
                                        .password,
                                );

                                let mut state = state_arc.lock().await;

                                let credential = AuthCredential::Password(password);

                                if {
                                    self.services
                                        .config_provider
                                        .lock()
                                        .await
                                        .validate_credential(&username, &credential)
                                        .await?
                                } {
                                    state.add_valid_credential(credential);
                                } else {
                                    // Postgres CLI will just send the same password in a loop without prompting the user again
                                    return fail(&mut self).await;
                                }
                            } else if kinds.contains(&CredentialKind::WebUserApproval) {
                                // Only WebUserApproval is needed, i.e. the password was either correct or not required, otherwise just fail early

                                let identification_string =
                                    state_arc.lock().await.identification_string().to_owned();
                                let auth_state_id = *state_arc.lock().await.id();
                                let mut event = self
                                    .services
                                    .auth_state_store
                                    .lock()
                                    .await
                                    .subscribe(auth_state_id);

                                let login_url_result =
                                    state_arc.lock().await.construct_web_approval_url(
                                        &*self.services.config.lock().await,
                                    );
                                let login_url = match login_url_result {
                                    Ok(login_url) => login_url,
                                    Err(error) => {
                                        error!(?error, "Failed to construct external URL");
                                        return fail(&mut self).await;
                                    }
                                };

                                if !auth_ok_sent {
                                    self.stream
                                        .push(pgwire::messages::startup::Authentication::Ok)?;
                                    auth_ok_sent = true;
                                }

                                self.stream
                                    .push(pgwire::messages::response::NoticeResponse::new(vec![
                                        (b'S', "WARNING".into()),
                                        (b'V', "WARNING".into()),
                                        (b'C', "WG001".into()),
                                        (b'M', "Warpgate authentication: please open the following URL in your browser:".into()),
                                        (b'D', login_url.into()),
                                        (b'H', format!(
                                            "Make sure you're seeing this security key: {}\n",
                                            identification_string
                                                .chars()
                                                .map(|x| x.to_string())
                                                .collect::<Vec<_>>()
                                                .join(" ")
                                        )),
                                    ]))?;
                                self.stream.flush().await?;

                                if !matches!(event.recv().await, Ok(AuthResult::Accepted { .. })) {
                                    warn!("Web user approval failed");
                                    return fail(&mut self).await;
                                }
                            } else {
                                return fail(&mut self).await;
                            }
                        }
                        AuthResult::Rejected => return fail(&mut self).await,
                    }
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

                        self.stream
                            .push(pgwire::messages::startup::Authentication::Ok)?;
                        self.run_authorized(startup, ticket.username, ticket.target)
                            .await
                    }
                    _ => fail(&mut self).await,
                }
            }
        }
    }

    async fn run_authorized(
        mut self,
        startup: pgwire::messages::startup::Startup,
        username: String,
        target_name: String,
    ) -> Result<(), PostgresError> {
        self.stream.flush().await?;

        let target = {
            self.services
                .config_provider
                .lock()
                .await
                .list_targets()
                .await?
                .iter()
                .filter_map(|t| match t.options {
                    TargetOptions::Postgres(ref options) => Some((t, options)),
                    _ => None,
                })
                .find(|(t, _)| t.name == target_name)
                .map(|(t, opt)| (t.clone(), opt.clone()))
        };

        let Some((target, postgres_options)) = target else {
            warn!("Selected target not found");
            self.send_error_response(
                "0W001".into(),
                format!("Warpgate target {target_name} not found"),
            )
            .await?;
            return Ok(());
        };

        {
            let handle = self.server_handle.lock().await;
            handle.set_username(username).await?;
            handle.set_target(&target).await?;
        }

        self.run_authorized_inner(startup, postgres_options).await
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
        options: TargetPostgresOptions,
    ) -> Result<(), PostgresError> {
        let mut client = match PostgresClient::connect(
            &options,
            ConnectionOptions {
                protocol_number_major: startup.protocol_number_major,
                protocol_number_minor: startup.protocol_number_minor,
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

        loop {
            tokio::select! {
                c_to_s = self.stream.recv::<PgWireGenericFrontendMessage>() => {
                    match c_to_s {
                        Ok(Some(msg)) => {
                            self.maybe_log_client_msg(&msg.0);
                            client.send(msg).await?;
                        }
                        Ok(None) => {
                            break
                        }
                        Err(err) => {
                            error!(error=%err, "Error receiving message");
                            break
                        }
                    };
                },
                s_to_c = client.recv() => {
                    match s_to_c {
                        Ok(Some(msg)) => {
                            self.maybe_log_server_msg(&msg.0);
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
                    };
                }
            };
        }

        Ok(())
    }

    fn maybe_log_client_msg(&self, msg: &PgWireFrontendMessage) {
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

    fn maybe_log_server_msg(&self, msg: &PgWireBackendMessage) {
        debug!(?msg, "S->C message");
        if let PgWireBackendMessage::ErrorResponse(error) = msg {
            info!(?error, "PostgreSQL error");
        }
    }
}

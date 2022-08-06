use std::sync::Arc;

use bytes::{Buf, Bytes, BytesMut};
use rand::Rng;
use rustls::ServerConfig;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::*;
use uuid::Uuid;
use warpgate_common::auth::{AuthCredential, AuthSelector, AuthState};
use warpgate_common::helpers::rng::get_crypto_rng;
use warpgate_common::{
    authorize_ticket, AuthResult, Secret, Services, TargetMySqlOptions, TargetOptions,
    WarpgateServerHandle,
};
use warpgate_database_protocols::io::{BufExt, Decode};
use warpgate_database_protocols::mysql::protocol::auth::AuthPlugin;
use warpgate_database_protocols::mysql::protocol::connect::{
    AuthSwitchRequest, Handshake, HandshakeResponse,
};
use warpgate_database_protocols::mysql::protocol::response::{ErrPacket, OkPacket, Status};
use warpgate_database_protocols::mysql::protocol::text::Query;
use warpgate_database_protocols::mysql::protocol::Capabilities;

use crate::client::{ConnectionOptions, MySqlClient};
use crate::error::MySqlError;
use crate::stream::MySqlStream;

pub struct MySqlSession {
    stream: MySqlStream<tokio_rustls::server::TlsStream<TcpStream>>,
    capabilities: Capabilities,
    challenge: [u8; 20],
    username: Option<String>,
    database: Option<String>,
    tls_config: Arc<ServerConfig>,
    server_handle: Arc<Mutex<WarpgateServerHandle>>,
    id: Uuid,
    services: Services,
}

impl MySqlSession {
    pub async fn new(
        server_handle: Arc<Mutex<WarpgateServerHandle>>,
        services: Services,
        stream: TcpStream,
        tls_config: ServerConfig,
    ) -> Self {
        let id = server_handle.lock().await.id();
        Self {
            services,
            stream: MySqlStream::new(stream),
            capabilities: Capabilities::PROTOCOL_41
                | Capabilities::PLUGIN_AUTH
                | Capabilities::FOUND_ROWS
                | Capabilities::LONG_FLAG
                | Capabilities::NO_SCHEMA
                | Capabilities::PLUGIN_AUTH_LENENC_DATA
                | Capabilities::CONNECT_WITH_DB
                | Capabilities::SESSION_TRACK
                | Capabilities::IGNORE_SPACE
                | Capabilities::INTERACTIVE
                | Capabilities::TRANSACTIONS
                | Capabilities::DEPRECATE_EOF
                | Capabilities::SECURE_CONNECTION
                | Capabilities::SSL,
            challenge: get_crypto_rng().gen(),
            tls_config: Arc::new(tls_config),
            username: None,
            database: None,
            server_handle,
            id,
        }
    }

    pub fn make_logging_span(&self) -> tracing::Span {
        match self.username {
            Some(ref username) => info_span!("MySQL", session=%self.id, session_username=%username),
            None => info_span!("MySQL", session=%self.id),
        }
    }

    pub async fn run(mut self) -> Result<(), MySqlError> {
        let mut challenge_1 = BytesMut::from(&self.challenge[..]);
        let challenge_2 = challenge_1.split_off(8);
        let challenge_chain = challenge_1.freeze().chain(challenge_2.freeze());

        let handshake = Handshake {
            protocol_version: 10,
            server_version: "8.0.0-Warpgate".to_owned(),
            connection_id: 1,
            auth_plugin_data: challenge_chain,
            server_capabilities: self.capabilities,
            server_default_collation: 45,
            status: Status::empty(),
            auth_plugin: Some(AuthPlugin::MySqlNativePassword),
        };
        self.stream.push(&handshake, ())?;
        self.stream.flush().await?;

        let resp = loop {
            let Some(payload) = self.stream.recv().await? else {
                return Err(MySqlError::Eof);
            };
            let resp = HandshakeResponse::decode_with(payload, &mut self.capabilities)
                .map_err(MySqlError::decode)?;

            trace!(?resp, "Handshake response");
            info!(capabilities=?self.capabilities, username=%resp.username, "User handshake");

            if self.capabilities.contains(Capabilities::SSL) {
                if self.stream.is_tls() {
                    break resp;
                }
                self.stream = self.stream.upgrade(self.tls_config.clone()).await?;
                continue;
            } else {
                self.send_error(1002, "Warpgate requires TLS - please enable it in your client: add `--ssl` on the CLI or add `?sslMode=PREFERRED` to your database URI").await?;
                return Err(MySqlError::TlsNotSupportedByClient);
            }
        };

        if resp.auth_plugin == Some(AuthPlugin::MySqlClearPassword) {
            if let Some(mut response) = resp.auth_response.clone() {
                let password = Secret::new(response.get_str_nul()?);
                return self.run_authorization(resp, password).await;
            }
        }

        let req = AuthSwitchRequest {
            plugin: AuthPlugin::MySqlClearPassword,
            data: Bytes::new(),
        };
        self.stream.push(&req, ())?;

        // self.push(&RawBytes::<
        self.stream.flush().await?;

        let Some(response) = &self.stream.recv().await? else {
            return Err(MySqlError::Eof);
        };
        let password = Secret::new(response.clone().get_str_nul()?);
        self.run_authorization(resp, password).await
    }

    async fn send_error(&mut self, code: u16, message: &str) -> Result<(), MySqlError> {
        self.stream.push(
            &ErrPacket {
                error_code: code,
                error_message: message.to_owned(),
                sql_state: None,
            },
            (),
        )?;
        self.stream.flush().await?;
        Ok(())
    }

    pub async fn run_authorization(
        mut self,
        handshake: HandshakeResponse,
        password: Secret<String>,
    ) -> Result<(), MySqlError> {
        let selector: AuthSelector = (&handshake.username).into();

        async fn fail(this: &mut MySqlSession) -> Result<(), MySqlError> {
            this.stream.push(
                &ErrPacket {
                    error_code: 1,
                    error_message: "Warpgate access denied".to_owned(),
                    sql_state: None,
                },
                (),
            )?;
            this.stream.flush().await?;
            Ok(())
        }

        match selector {
            AuthSelector::User {
                username,
                target_name,
            } => {
                let state_arc = self.services.auth_state_store.lock().await.create(&username, crate::common::PROTOCOL_NAME).await?.1;
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
                        self.services.auth_state_store.lock().await.complete(state.id()).await;
                        let target_auth_result = {
                            self.services
                                .config_provider
                                .lock()
                                .await
                                .authorize_target(&username, &target_name)
                                .await
                                .map_err(MySqlError::other)?
                        };
                        if !target_auth_result {
                            warn!(
                                "Target {} not authorized for user {}",
                                target_name, username
                            );
                            return fail(&mut self).await;
                        }
                        self.run_authorized(handshake, username, target_name).await
                    }
                    AuthResult::Rejected
                    | AuthResult::Need(_)
                    | AuthResult::NeedMoreCredentials => fail(&mut self).await, // TODO SSO
                }
            }
            AuthSelector::Ticket { secret } => {
                match authorize_ticket(&self.services.db, &secret)
                    .await
                    .map_err(MySqlError::other)?
                {
                    Some(ticket) => {
                        info!("Authorized for {} with a ticket", ticket.target);
                        self.services
                            .config_provider
                            .lock()
                            .await
                            .consume_ticket(&ticket.id)
                            .await
                            .map_err(MySqlError::other)?;

                        self.run_authorized(handshake, ticket.username, ticket.target)
                            .await
                    }
                    _ => fail(&mut self).await,
                }
            }
        }
    }

    async fn run_authorized(
        mut self,
        handshake: HandshakeResponse,
        username: String,
        target_name: String,
    ) -> Result<(), MySqlError> {
        self.stream.push(
            &OkPacket {
                affected_rows: 0,
                last_insert_id: 0,
                status: Status::empty(),
                warnings: 0,
            },
            (),
        )?;
        self.stream.flush().await?;

        info!(%username, "Authenticated");

        let target = {
            self.services
                .config
                .lock()
                .await
                .store
                .targets
                .iter()
                .filter_map(|t| match t.options {
                    TargetOptions::MySql(ref options) => Some((t, options)),
                    _ => None,
                })
                .find(|(t, _)| t.name == target_name)
                .map(|(t, opt)| (t.clone(), opt.clone()))
        };

        let Some((target, mysql_options)) = target else {
            warn!("Selected target not found");
            self.stream.push(
                &ErrPacket {
                    error_code: 1,
                    error_message: "Warpgate access denied".to_owned(),
                    sql_state: None,
                },
                (),
            )?;
            self.stream.flush().await?;
            return Ok(());
        };

        {
            let handle = self.server_handle.lock().await;
            handle.set_username(username).await?;
            handle.set_target(&target).await?;
        }

        let span = self.make_logging_span();
        self.run_authorized_inner(handshake, mysql_options)
            .instrument(span)
            .await
    }

    async fn run_authorized_inner(
        mut self,
        handshake: HandshakeResponse,
        options: TargetMySqlOptions,
    ) -> Result<(), MySqlError> {
        self.database = handshake.database.clone();
        self.username = Some(handshake.username);
        if let Some(ref database) = handshake.database {
            info!("Selected database: {database}");
        }

        let mut client = match MySqlClient::connect(
            &options,
            ConnectionOptions {
                collation: handshake.collation,
                database: handshake.database,
                max_packet_size: handshake.max_packet_size,
                capabilities: self.capabilities,
            },
        )
        .await
        {
            Err(error) => {
                error!(%error, "Target connection failed");
                self.send_error(1045, "Access denied").await?;
                Err(error)
            }
            x => x,
        }?;

        loop {
            self.stream.reset_sequence_id();
            client.stream.reset_sequence_id();
            let Some(payload) = self.stream.recv().await? else {
                break;
            };
            trace!(?payload, "server got packet");

            let com = payload.first();

            // COM_QUERY
            if com == Some(&0x03) {
                let query = Query::decode(payload)?;
                info!(query=%query.0, "SQL");

                client.stream.push(&query, ())?;
                client.stream.flush().await?;

                let mut eof_ctr = 0;
                loop {
                    let Some(response) = client.stream.recv().await? else {
                        return Err(MySqlError::Eof);
                    };
                    trace!(?response, "client got packet");
                    self.stream.push(&&response[..], ())?;
                    self.stream.flush().await?;
                    if let Some(com) = response.first() {
                        if com == &0xfe {
                            if self.capabilities.contains(Capabilities::DEPRECATE_EOF) {
                                break;
                            }
                            eof_ctr += 1;
                            if eof_ctr == 2 {
                                // todo check multiple results
                                break;
                            }
                        }
                        if com == &0 || com == &0xff {
                            break;
                        }
                    }
                }
            // COM_QUIT
            } else if com == Some(&0x01) {
                break;
            // COM_INIT_DB
            } else if com == Some(&0x02) {
                let mut buf = payload.clone();
                buf.advance(1);
                let db = buf.get_str(buf.len())?;
                self.database = Some(db.clone());
                info!("Selected database: {db}");
                client.stream.push(&&payload[..], ())?;
                client.stream.flush().await?;
                self.passthrough_until_result(&mut client).await?;
            // COM_FIELD_LIST, COM_PING, COM_RESET_CONNECTION
            } else if com == Some(&0x04) || com == Some(&0x0e) || com == Some(&0x1f) {
                client.stream.push(&&payload[..], ())?;
                client.stream.flush().await?;
                self.passthrough_until_result(&mut client).await?;
            } else if let Some(com) = com {
                warn!("Unknown packet type {com}");
                self.send_error(1047, "Not implemented").await?;
            } else {
                break;
            }
        }

        Ok(())
    }

    async fn passthrough_until_result(
        &mut self,
        client: &mut MySqlClient,
    ) -> Result<(), MySqlError> {
        loop {
            let Some(response) = client.stream.recv().await? else{
                return Err(MySqlError::Eof);
            };
            trace!(?response, "client got packet");
            self.stream.push(&&response[..], ())?;
            self.stream.flush().await?;
            if let Some(com) = response.first() {
                if com == &0 || com == &0xff || com == &0xfe {
                    break;
                }
            }
        }
        Ok(())
    }
}

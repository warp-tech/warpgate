use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::Arc;

use bytes::{Buf, Bytes, BytesMut};
use rand::RngExt;
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tracing::{error, info, info_span, trace, warn};
use url::Url;
use uuid::Uuid;
use warpgate_common::auth::AuthSelector;
use warpgate_common::helpers::rng::get_crypto_rng;
use warpgate_common::{Protocol, Secret, TargetMySqlOptions, TargetOptions};
use warpgate_common_http::ext::construct_external_url;
use warpgate_core::{
    AuthOkPermit, DbAuthTransport, Services, TargetAuthorization, WarpgateServerHandle,
    run_db_authorization,
};
use warpgate_database_protocols::io::{BufExt, Decode};
use warpgate_database_protocols::mysql::protocol::Capabilities;
use warpgate_database_protocols::mysql::protocol::auth::AuthPlugin;
use warpgate_database_protocols::mysql::protocol::connect::{
    AuthSwitchRequest, Handshake, HandshakeResponse,
};
use warpgate_database_protocols::mysql::protocol::response::{ErrPacket, OkPacket, Status};
use warpgate_database_protocols::mysql::protocol::text::Query;
use warpgate_tls::ServerTlsStream;

use crate::client::{ConnectionOptions, MySqlClient};
use crate::error::MySqlError;
use crate::stream::MySqlStream;

pub struct MySqlSession<S: AsyncRead + AsyncWrite + Send + Unpin> {
    stream: MySqlStream<S, ServerTlsStream<S>>,
    capabilities: Capabilities,
    challenge: [u8; 20],
    username: Option<String>,
    database: Option<String>,
    tls_config: Arc<ServerConfig>,
    server_handle: Arc<Mutex<WarpgateServerHandle>>,
    id: Uuid,
    services: Services,
    remote_address: SocketAddr,
    /// MySQL carries the password in the handshake, so the shared auth flow can
    /// only be handed it — never prompted for it a second time.
    handshake_password: Option<Secret<String>>,
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin> DbAuthTransport for MySqlSession<S> {
    type Error = MySqlError;

    const PROTOCOL: Protocol = crate::common::PROTOCOL_NAME;
    const SUPPORTS_WEB_APPROVAL: bool = false;

    /// The password arrived in the handshake. There is no second prompt in the
    /// MySQL protocol, so a repeat request denies the login.
    async fn prompt_password(&mut self) -> Result<Option<Secret<String>>, MySqlError> {
        Ok(self.handshake_password.take())
    }

    async fn send_auth_ok(&mut self, _permit: AuthOkPermit) -> Result<(), MySqlError> {
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
        Ok(())
    }

    async fn external_url(&mut self) -> Result<Url, MySqlError> {
        Ok(construct_external_url(None, &*self.services.config.lock().await, None).await?)
    }

    /// The MySQL connection phase has no packet for showing the user a link, so
    /// a policy requiring web approval can't be satisfied over MySQL.
    async fn send_web_approval_prompt(
        &mut self,
        _url: &Url,
        _identification_string: &str,
    ) -> Result<bool, MySqlError> {
        warn!("Web user approval is not supported over MySQL");
        Ok(false)
    }

    async fn send_denied(&mut self) -> Result<(), MySqlError> {
        self.send_access_denied().await
    }
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin> MySqlSession<S> {
    pub async fn new(
        server_handle: Arc<Mutex<WarpgateServerHandle>>,
        services: Services,
        stream: S,
        tls_config: ServerConfig,
        remote_address: SocketAddr,
    ) -> Self {
        let id = server_handle.lock().await.id();
        Self {
            services,
            stream: MySqlStream::new(stream),
            // Target packets are relayed to the client verbatim, but the target
            // is only picked (and its capabilities learned) after this handshake
            // is already on the wire. So the client must not be offered any
            // capability that changes packet framing - DEPRECATE_EOF turns the
            // result set terminator from an EOF into an OK packet, SESSION_TRACK
            // changes the OK packet's trailing `info` string to length-encoded -
            // or a target lacking it desyncs the client mid-result-set.
            capabilities: Capabilities::PROTOCOL_41
                | Capabilities::PLUGIN_AUTH
                | Capabilities::FOUND_ROWS
                | Capabilities::LONG_FLAG
                | Capabilities::NO_SCHEMA
                | Capabilities::PLUGIN_AUTH_LENENC_DATA
                | Capabilities::CONNECT_WITH_DB
                | Capabilities::IGNORE_SPACE
                | Capabilities::INTERACTIVE
                | Capabilities::TRANSACTIONS
                | Capabilities::SECURE_CONNECTION
                | Capabilities::SSL,
            challenge: get_crypto_rng().random(),
            tls_config: Arc::new(tls_config),
            username: None,
            database: None,
            server_handle,
            id,
            remote_address,
            handshake_password: None,
        }
    }

    pub fn make_logging_span(&self) -> tracing::Span {
        let client_ip = self.remote_address.ip().to_string();
        if let Some(ref username) = self.username {
            info_span!("MySQL", session=%self.id, session_username=%username, %client_ip)
        } else {
            info_span!("MySQL", session=%self.id, %client_ip)
        }
    }

    pub async fn run(mut self) -> Result<(), MySqlError> {
        let mut challenge_1 = BytesMut::from(&self.challenge[..]);
        let challenge_2 = challenge_1.split_off(8);
        let challenge_chain = challenge_1.freeze().chain(challenge_2.freeze());

        let advertised_version = {
            let config = self.services.config.lock().await;
            config.store.mysql.advertised_version.clone()
        };

        let handshake = Handshake {
            protocol_version: 10,
            server_version: advertised_version,
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
            }
            self.send_error(1002, "Warpgate requires TLS - please enable it in your client: add `--ssl` on the CLI or add `?sslMode=PREFERRED` to your database URI").await?;
            return Err(MySqlError::TlsNotSupportedByClient);
        };

        if resp.auth_plugin == Some(AuthPlugin::MySqlClearPassword)
            && let Some(mut response) = resp.auth_response.clone()
        {
            let password = Secret::new(response.get_str_nul()?);
            return self.run_authorization(resp, password).await;
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

    async fn send_access_denied(&mut self) -> Result<(), MySqlError> {
        self.send_error(1, "Warpgate access denied").await
    }

    pub async fn run_authorization(
        mut self,
        handshake: HandshakeResponse,
        password: Secret<String>,
    ) -> Result<(), MySqlError> {
        let selector: AuthSelector = handshake.username.deref().into();
        let remote_ip = self.remote_address.ip();
        let session_id = self.server_handle.lock().await.id();

        self.handshake_password = Some(password);

        let services = self.services.clone();
        let Some(authorization) =
            run_db_authorization(&mut self, &services, session_id, selector, remote_ip).await?
        else {
            return Ok(());
        };

        self.run_authorized(handshake, authorization).await
    }

    async fn run_authorized(
        mut self,
        handshake: HandshakeResponse,
        authorization: TargetAuthorization,
    ) -> Result<(), MySqlError> {
        let (user_info, target) = authorization.into_parts();

        let TargetOptions::MySql(ref mysql_options) = target.options else {
            warn!("Selected target is not a MySQL target");
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

        let mysql_options = mysql_options.clone();

        {
            let handle = self.server_handle.lock().await;
            handle.set_user_info(user_info).await?;
            handle.set_target(&target).await?;
        }

        self.run_authorized_inner(handshake, mysql_options).await
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

        // The handshake's max_packet_size is forwarded to the target; the
        // proxy's own codecs must honor it too, in both directions, or a
        // >4 MiB row/statement/BLOB would abort the session.
        self.stream.set_max_packet_size(handshake.max_packet_size);
        client.stream.set_max_packet_size(handshake.max_packet_size);

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
                let mut first_packet = true;
                loop {
                    let Some(response) = client.stream.recv().await? else {
                        return Err(MySqlError::Eof);
                    };
                    trace!(?response, "client got packet");
                    self.stream.push(&&response[..], ())?;
                    self.stream.flush().await?;

                    let com = response.first();
                    if first_packet {
                        first_packet = false;
                        // OK or ERR as the first packet means there is no
                        // result set; later packets starting with 0x00 are
                        // rows with an empty first column
                        if com == Some(&0) || com == Some(&0xff) {
                            break;
                        }
                        continue;
                    }
                    // 0xff is not a valid length-encoded value prefix, so
                    // no row or column definition can start with it
                    if com == Some(&0xff) {
                        break;
                    }
                    // Rows can also start with 0xfe (a length-encoded value
                    // >= 2^24); a real EOF packet is shorter than that
                    // prefix. The column definitions and the rows are each
                    // terminated by one.
                    if com == Some(&0xfe) && response.len() < 9 {
                        eof_ctr += 1;
                        if eof_ctr == 2 {
                            // todo check multiple results
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
            let Some(response) = client.stream.recv().await? else {
                return Err(MySqlError::Eof);
            };
            trace!(?response, "client got packet");
            self.stream.push(&&response[..], ())?;
            self.stream.flush().await?;
            if let Some(com) = response.first()
                && (com == &0 || com == &0xff || com == &0xfe)
            {
                break;
            }
        }
        Ok(())
    }
}

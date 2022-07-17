use std::sync::Arc;

use bytes::{Buf, BytesMut};
use rand::Rng;
use rustls::ServerConfig;
use sqlx_core_guts::io::{BufExt, Decode};
use sqlx_core_guts::mysql::protocol::auth::AuthPlugin;
use sqlx_core_guts::mysql::protocol::connect::{AuthSwitchRequest, Handshake, HandshakeResponse};
use sqlx_core_guts::mysql::protocol::response::{ErrPacket, OkPacket, Status};
use sqlx_core_guts::mysql::protocol::text::Query;
use sqlx_core_guts::mysql::protocol::Capabilities;
use tokio::net::TcpStream;
use tracing::*;
use warpgate_common::helpers::rng::get_crypto_rng;

use crate::client::{ConnectionOptions, MySqlClient};
use crate::common::compute_auth_challenge_response;
use crate::error::MySqlError;
use crate::stream::MySqlStream;

pub struct MySqlSession {
    stream: MySqlStream<tokio_rustls::server::TlsStream<TcpStream>>,
    capabilities: Capabilities,
    challenge: [u8; 20],
    tls_config: Arc<ServerConfig>,
}

impl MySqlSession {
    pub fn new(stream: TcpStream, tls_config: ServerConfig) -> Self {
        Self {
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
        }
    }

    async fn check_auth_response(&mut self, response: &[u8]) -> Result<bool, MySqlError> {
        let expected_response = compute_auth_challenge_response(self.challenge, "123").map_err(MySqlError::other)?;

        let client_response = password_hash::Output::new(response).map_err(MySqlError::other)?;
        if client_response == expected_response {
            self.stream.push(
                &OkPacket {
                    affected_rows: 0,
                    last_insert_id: 0,
                    status: Status::empty(),
                    warnings: 0,
                },
                (),
            )?;
        } else {
            self.stream.push(
                &ErrPacket {
                    error_code: 1,
                    error_message: "Access denied".to_owned(),
                    sql_state: None,
                },
                (),
            )?;
        }
        self.stream.flush().await?;

        Ok(client_response == expected_response)
    }

    pub async fn run(mut self) -> Result<(), MySqlError> {
        let mut challenge_1 = BytesMut::from(&self.challenge[..]);
        let challenge_2 = challenge_1.split_off(8);
        let challenge_chain = challenge_1.freeze().chain(challenge_2.freeze());

        let handshake = Handshake {
            protocol_version: 10,
            server_version: "Warpgate".to_owned(),
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
            let resp = HandshakeResponse::decode_with(payload, &mut self.capabilities).map_err(MySqlError::decode)?;

            trace!(?resp, "Handshake response");
            info!(capabilities=?self.capabilities, username=%resp.username, "User handshake");

            if self.capabilities.contains(Capabilities::SSL) {
                if self.stream.is_tls() {
                    break resp;
                }
                self.stream = self.stream.upgrade(self.tls_config.clone()).await?;
                info!("User connection upgraded to TLS");
                continue;
            } else {
                break resp;
            }
        };

        if resp.auth_plugin == Some(AuthPlugin::MySqlNativePassword) {
            if let Some(response) = resp.auth_response.as_ref() {
                if self.check_auth_response(response).await? {
                    return self.run_authorized(resp).await;
                }
            }
        }

        let challenge = self.challenge;
        let req = AuthSwitchRequest {
            plugin: AuthPlugin::MySqlNativePassword,
            data: BytesMut::from(&challenge[..]).freeze(),
        };
        self.stream.push(&req, ())?;

        // self.push(&RawBytes::<
        self.stream.flush().await?;

        let Some(response) = &self.stream.recv().await? else {
            return Err(MySqlError::Eof);
        };
        if self.check_auth_response(response).await? {
            return self.run_authorized(resp).await;
        }

        Ok(())
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

    pub async fn run_authorized(mut self, handshake: HandshakeResponse) -> Result<(), MySqlError> {
        let mut client = match MySqlClient::connect(
            "mysql://dev:123@localhost:3306/elements_web?sslMode=REQUIRED",
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

            let com = payload.get(0);

            // COM_QUERY
            if com == Some(&0x03) {
                let query = Query::decode(payload)?;
                trace!(?query, "server got query");

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
                    if let Some(com) = response.get(0) {
                        if com == &0xfe {
                            eof_ctr += 1;
                            if eof_ctr == 2
                                && !self.capabilities.contains(Capabilities::DEPRECATE_EOF)
                            {
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
                info!("Changing database to {db}");
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

    async fn passthrough_until_result(&mut self, client: &mut MySqlClient) -> Result<(), MySqlError> {
        loop {
            let Some(response) = client.stream.recv().await? else{
                return Err(MySqlError::Eof);
            };
            trace!(?response, "client got packet");
            self.stream.push(&&response[..], ())?;
            self.stream.flush().await?;
            if let Some(com) = response.get(0) {
                if com == &0 || com == &0xff || com == &0xfe {
                    break;
                }
            }
        }
        Ok(())
    }
}

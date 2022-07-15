#![feature(type_alias_impl_trait, let_else, try_blocks)]
mod client;
mod common;
mod stream;
mod tls;
use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::{Buf, BytesMut};
use common::compute_auth_challenge_response;
use rand::Rng;
use rustls::ServerConfig;
use sqlx_core_guts::io::Decode;
use sqlx_core_guts::mysql::protocol::auth::AuthPlugin;
use sqlx_core_guts::mysql::protocol::connect::{AuthSwitchRequest, Handshake, HandshakeResponse};
use sqlx_core_guts::mysql::protocol::response::{ErrPacket, OkPacket, Status};
use sqlx_core_guts::mysql::protocol::text::Query;
use sqlx_core_guts::mysql::protocol::Capabilities;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;
use stream::MySQLStream;
use tokio::net::{TcpListener, TcpStream};
use tracing::*;
use warpgate_common::helpers::rng::get_crypto_rng;
use warpgate_common::{ProtocolServer, Services, Target, TargetTestError};

use crate::client::{ConnectionOptions, MySQLClient};
use crate::tls::FromCertificateAndKey;

pub struct MySQLProtocolServer {
    services: Services,
}

impl MySQLProtocolServer {
    pub async fn new(services: &Services) -> Result<Self> {
        Ok(MySQLProtocolServer {
            services: services.clone(),
        })
    }
}

#[async_trait]
impl ProtocolServer for MySQLProtocolServer {
    async fn run(self, address: SocketAddr) -> Result<()> {
        let (certificate, key) = {
            let config = self.services.config.lock().await;
            let certificate_path = config
                .paths_relative_to
                .join(&config.store.mysql.certificate);
            let key_path = config.paths_relative_to.join(&config.store.mysql.key);

            (
                std::fs::read(&certificate_path).with_context(|| {
                    format!(
                        "reading SSL certificate from '{}'",
                        certificate_path.display()
                    )
                })?,
                std::fs::read(&key_path).with_context(|| {
                    format!("reading SSL private key from '{}'", key_path.display())
                })?,
            )
        };

        let tls_config = ServerConfig::try_from_certificate_and_key(certificate, key)?;

        info!(?address, "Listening");
        let listener = TcpListener::bind(address).await?;
        loop {
            let (stream, addr) = listener.accept().await?;
            let tls_config = tls_config.clone();
            tokio::spawn(async move {
                match Session::new(stream, tls_config).run().await {
                    Ok(_) => info!(?addr, "Session finished"),
                    Err(e) => error!(?addr, ?e, "Session failed"),
                }
            });
        }
    }

    async fn test_target(self, _target: Target) -> Result<(), TargetTestError> {
        Ok(())
    }
}

impl Debug for MySQLProtocolServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MySQLProtocolServer")
    }
}

struct Session {
    stream: MySQLStream<tokio_rustls::server::TlsStream<TcpStream>>,
    capabilities: Capabilities,
    challenge: [u8; 20],
    tls_config: Arc<ServerConfig>,
}

impl Session {
    pub fn new(stream: TcpStream, tls_config: ServerConfig) -> Self {
        Self {
            stream: MySQLStream::new(stream),
            capabilities: Capabilities::PROTOCOL_41
                | Capabilities::PLUGIN_AUTH
                | Capabilities::FOUND_ROWS
                | Capabilities::LONG_FLAG
                | Capabilities::NO_SCHEMA
                // | Capabilities::MULTI_RESULTS
                | Capabilities::MULTI_STATEMENTS
                // | Capabilities::PS_MULTI_RESULTS
                | Capabilities::PLUGIN_AUTH_LENENC_DATA
                | Capabilities::CONNECT_WITH_DB
                | Capabilities::CAN_HANDLE_EXPIRED_PASSWORDS
                | Capabilities::SESSION_TRACK
                | Capabilities::IGNORE_SPACE
                | Capabilities::INTERACTIVE
                | Capabilities::TRANSACTIONS
                // | Capabilities::MULTI_FACTOR_AUTHENTICATION
                | Capabilities::DEPRECATE_EOF
                | Capabilities::SECURE_CONNECTION
                | Capabilities::SSL,
            challenge: get_crypto_rng().gen(),
            tls_config: Arc::new(tls_config),
        }
    }

    async fn check_auth_response(&mut self, response: &[u8]) -> Result<bool> {
        let expected_response = compute_auth_challenge_response(self.challenge, "123")?;

        let client_response = password_hash::Output::new(response)?;
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

    pub async fn run(mut self) -> Result<()> {
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
            let payload = self.stream.recv().await?;
            let resp = HandshakeResponse::decode_with(payload, &mut self.capabilities)
                .context("Failed to parse packet")?;

            trace!(?resp, "Handshake response");
            info!(capabilities=?self.capabilities, username=%resp.username, "handshake complete");

            if self.capabilities.contains(Capabilities::SSL) {
                if self.stream.is_tls() {
                    break resp;
                }
                self.stream = self.stream.upgrade(self.tls_config.clone()).await?;
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

        let response = &self.stream.recv().await?;
        if self.check_auth_response(response).await? {
            return self.run_authorized(resp).await;
        }

        Ok(())
    }

    async fn send_error(&mut self, code: u16, message: &str) -> Result<()> {
        self.stream.push(
            &ErrPacket {
                error_code: code,
                error_message: message.to_owned(),
                sql_state: None,
            },
            (),
        )?;
        self.stream.flush().await
    }

    pub async fn run_authorized(mut self, handshake: HandshakeResponse) -> Result<()> {
        let mut client = match MySQLClient::connect(
            "mysql://dev:123@localhost:3306/elements_web",
            ConnectionOptions {
                collation: handshake.collation,
                database: handshake.database,
                max_packet_size: handshake.max_packet_size,
                capabilities: self.capabilities,
            },
        )
        .await
        {
            Ok(c) => c,
            Err(error) => {
                error!(?error, "Target connection failed");
                self.send_error(1045, "Access denied").await?;
                return Err(error);
            }
        };

        loop {
            self.stream.reset_sequence_id();
            client.stream.reset_sequence_id();
            let payload = self.stream.recv().await?;
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
                    let response = client.stream.recv().await?;
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
            // COM_FIELD_LIST
            } else if com == Some(&0x04) {
                client.stream.push(&&payload[..], ())?;
                client.stream.flush().await?;
                loop {
                    let response = client.stream.recv().await?;
                    trace!(?response, "client got packet");
                    self.stream.push(&&response[..], ())?;
                    self.stream.flush().await?;
                    if let Some(com) = response.get(0) {
                        if com == &0 || com == &0xff || com == &0xfe {
                            break;
                        }
                    }
                }
            } else {
                warn!("Unknown packet type {:?}", payload.get(0));
                self.send_error(1047, "Not implemented").await?;
            }
        }

        Ok(())
    }
}

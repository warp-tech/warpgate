#![feature(type_alias_impl_trait, let_else, try_blocks)]
mod client;
mod common;
mod stream;
use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::{Buf, BytesMut};
use common::compute_auth_challenge_response;
use rand::Rng;
use sqlx_core_guts::io::Decode;
use sqlx_core_guts::mysql::protocol::auth::AuthPlugin;
use sqlx_core_guts::mysql::protocol::connect::{AuthSwitchRequest, Handshake, HandshakeResponse};
use sqlx_core_guts::mysql::protocol::response::{ErrPacket, OkPacket, Status};
use sqlx_core_guts::mysql::protocol::text::Query;
use sqlx_core_guts::mysql::protocol::Capabilities;
use std::fmt::Debug;
use std::net::SocketAddr;
use stream::MySQLStream;
use tokio::net::{TcpListener, TcpStream};
use tracing::*;
use warpgate_common::helpers::rng::get_crypto_rng;
use warpgate_common::{ProtocolServer, Services, Target, TargetTestError};

use crate::client::{ConnectionOptions, MySQLClient};

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
        info!(?address, "Listening");
        let listener = TcpListener::bind(address).await?;
        loop {
            let (stream, addr) = listener.accept().await?;
            tokio::spawn(async move {
                match Session::new(stream).run().await {
                    Ok(_) => info!(?addr, "Session finished"),
                    Err(e) => error!(?addr, ?e, "Session failed"),
                }
            });
        }
        Ok(())
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
    stream: MySQLStream,
    capabilities: Capabilities,
    challenge: [u8; 20],
}

impl Session {
    pub fn new(stream: TcpStream) -> Self {
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
                | Capabilities::SECURE_CONNECTION,
            challenge: get_crypto_rng().gen(),
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

        let payload = self.stream.recv().await?;
        let resp = HandshakeResponse::decode_with(payload, &mut self.capabilities)
            .context("Failed to parse packet")?;

        trace!(?resp, "Handshake response");
        info!(capabilities=?self.capabilities, username=%resp.username, "handshake complete");

        if resp.auth_plugin == Some(AuthPlugin::MySqlNativePassword) {
            if let Some(response) = resp.auth_response.as_ref() {
                if self.check_auth_response(response).await? {
                    return self.run_authorized(resp).await;
                }
            }
        }

        let challenge = self.challenge.clone();
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
                capabilities: self.capabilities.clone(),
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

            // COM_QUERY
            if payload.get(0) == Some(&0x03) {
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
                    if let Some(b) = response.get(0) {
                        if b == &0xfe {
                            eof_ctr += 1;
                            if eof_ctr == 2 && !self.capabilities.contains(Capabilities::DEPRECATE_EOF) {
                                // tood check multiple results
                                break;
                            }
                        }
                        if b == &0 || b == &0xff {
                            break;
                        }
                    }
                }

            } else {
                warn!("Unknown packet type {:?}", payload.get(0));
                self.send_error(999, "Not implemented").await?;
            }
        }

        Ok(())
    }
}

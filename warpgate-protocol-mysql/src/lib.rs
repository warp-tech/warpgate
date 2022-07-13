#![feature(type_alias_impl_trait, let_else, try_blocks)]
mod common;
use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::{Buf, Bytes, BytesMut};
use mysql_common::proto::codec::PacketCodec;
use rand::Rng;
use sha1::Digest;
use sqlx_core_guts::io::{BufStream, Decode, Encode};
use sqlx_core_guts::mysql::protocol::auth::AuthPlugin;
use sqlx_core_guts::mysql::protocol::connect::{AuthSwitchRequest, Handshake, HandshakeResponse};
use sqlx_core_guts::mysql::protocol::response::{ErrPacket, OkPacket, Status};
use sqlx_core_guts::mysql::protocol::text::Query;
use sqlx_core_guts::mysql::protocol::Capabilities;
use std::fmt::Debug;

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::*;
use warpgate_common::helpers::rng::get_crypto_rng;
use warpgate_common::{ProtocolServer, Services, Target, TargetTestError};

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
    stream: BufStream<TcpStream>,
    codec: PacketCodec,
    capabilities: Capabilities,
    inbound_buffer: BytesMut,
    outbound_buffer: BytesMut,
    challenge: [u8; 20],
}


impl Session {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream: BufStream::new(stream),
            capabilities: Capabilities::PROTOCOL_41
                | Capabilities::PLUGIN_AUTH
                | Capabilities::FOUND_ROWS
                | Capabilities::LONG_FLAG
                | Capabilities::NO_SCHEMA
                | Capabilities::MULTI_RESULTS
                | Capabilities::MULTI_STATEMENTS
                | Capabilities::PS_MULTI_RESULTS
                | Capabilities::CONNECT_ATTRS
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
            codec: PacketCodec::default(),
            inbound_buffer: BytesMut::new(),
            outbound_buffer: BytesMut::new(),
            challenge: get_crypto_rng().gen(),
        }
    }

    fn push<'a, C, P: Encode<'a, C>>(&mut self, packet: &'a P, context: C) -> Result<()> {
        let mut buf = vec![];
        packet.encode_with(&mut buf, context);
        self.codec
            .encode(&mut &*buf, &mut self.outbound_buffer)
            .context("Failed to encode packet")?;
        Ok(())
    }

    async fn flush(&mut self) -> Result<()> {
        trace!(outbound_buffer=?self.outbound_buffer, "flushing");
        self.stream.write(&self.outbound_buffer[..]);
        self.outbound_buffer = BytesMut::new();
        self.stream
            .flush()
            .await
            .context("Failed to flush stream")?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<Bytes> {
        let mut payload = BytesMut::new();
        loop {
            let read_bytes = self.stream.read_buf(&mut self.inbound_buffer).await?;
            if read_bytes == 0 {
                anyhow::bail!("Unexpected EOF");
            }
            trace!(inbound_buffer=?self.inbound_buffer, "chunk");
            {
                let got_full_packet = self.codec.decode(&mut self.inbound_buffer, &mut payload)?;
                if got_full_packet {
                    break;
                }
            }
        }
        trace!(inbound_buffer=?self.inbound_buffer, "after packet");
        Ok(payload.freeze())
        // let result = P::deserialize(ctx, &mut pb);
        // drop(pb);
        // return result.context("Failed to deserialize");
    }

    async fn check_auth_response(&mut self, response: &[u8]) -> Result<bool> {
        let expected_response = password_hash::Output::new(
            &{
                let true_password = b"123";
                let password_sha: [u8; 20] = sha1::Sha1::digest(true_password).into();
                let password_sha_sha: [u8; 20] = sha1::Sha1::digest(password_sha).into();
                let password_seed_2sha_sha: [u8; 20] =
                    sha1::Sha1::digest([self.challenge, password_sha_sha].concat()).into();

                let mut result = password_sha;
                result
                    .iter_mut()
                    .zip(password_seed_2sha_sha.iter())
                    .for_each(|(x1, x2)| *x1 ^= *x2);
                result
            }[..],
        );

        let client_response = password_hash::Output::new(response);
        info!(?client_response, "client_response");
        info!(?expected_response, "exp response");

        info!("correct {}", client_response == expected_response);

        if client_response == expected_response {
            self.push(&OkPacket {
                affected_rows: 0,
                last_insert_id: 0,
                status: Status::empty(),
                warnings: 0,
            }, ())?;
        } else {
            self.push(&ErrPacket {
                error_code: 1,
                error_message: "Access denied".to_owned(),
                sql_state: None,
            }, ())?;
        }
        self.flush().await?;

        Ok(client_response == expected_response)
    }

    pub async fn run(mut self) -> Result<()> {
        let mut challenge_1 = BytesMut::from(&self.challenge[..]);
        let mut challenge_2 = challenge_1.split_off(8);
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
        self.push(&handshake, ())?;
        self.flush().await?;

        let mut payload = self.recv().await?;
        let resp = HandshakeResponse::decode_with(payload, &mut self.capabilities)
            .context("Failed to parse packet")?;
        info!(?resp, "got response");

        if resp.auth_plugin == Some(AuthPlugin::MySqlNativePassword) {
            if let Some(response) = resp.auth_response.as_ref() {
            if self.check_auth_response(response).await? {
                return self.run_authorized().await;
            }}
        }

        let challenge = self.challenge.clone();
        let req = AuthSwitchRequest {
            plugin: AuthPlugin::MySqlNativePassword,
            data: BytesMut::from(&challenge[..]).freeze(),
        };
        self.push(&req, ())?;

        // self.push(&RawBytes::<
        self.flush().await?;

        let response = &self.recv().await?;
        if self.check_auth_response(response).await? {
            return self.run_authorized().await;
        }

        Ok(())
    }

    pub async fn run_authorized(mut self) -> Result<()> {
        loop {
            self.codec.reset_seq_id();
            let payload = self.recv().await?;
            trace!(?payload, "got packet");

            // COM_QUERY
            if payload.get(0) == Some(&0x03) {
                let query = Query::decode(payload)?;
                trace!(?query, "got query");
                self.push(&ErrPacket {
                    error_code: 1,
                    error_message: "Whoops".to_owned(),
                    sql_state: None,
                }, ())?;
                self.flush().await?;
            }
        }

        Ok(())
    }
}

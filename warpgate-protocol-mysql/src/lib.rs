#![feature(type_alias_impl_trait, let_else, try_blocks)]
mod common;
use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::buf::Chain;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use mysql_common::constants::StatusFlags;
use mysql_common::io::ParseBuf;
use mysql_common::misc::raw::bytes::BareBytes;
use mysql_common::misc::raw::{Const, RawBytes, RawInt, Skip};
use mysql_common::packets::{AuthSwitchRequest, HandshakePacket, HandshakeResponse};
use mysql_common::proto::codec::PacketCodec;
use mysql_common::proto::{MyDeserialize, MySerialize};
use rand::Rng;
use sha1::Digest;
use sqlx_core_guts::io::{BufMutExt, BufStream};
use sqlx_core_guts::mysql::io::MySqlBufMutExt;
use sqlx_core_guts::mysql::protocol::auth::AuthPlugin;
use sqlx_core_guts::mysql::protocol::connect::Handshake;
use sqlx_core_guts::mysql::protocol::response::{ErrPacket, OkPacket, Status};
use sqlx_core_guts::mysql::protocol::Capabilities;
use std::borrow::Cow;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::tcp::ReadHalf;
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

pub trait SerializePacket {
    fn serialize(&self, buf: &mut Vec<u8>);
}

impl SerializePacket for OkPacket {
    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.put_u8(0);
        buf.put_uint_lenenc(self.affected_rows);
        buf.put_uint_lenenc(self.last_insert_id);
        buf.put_u16_le(self.status.bits());
        buf.put_u16_le(self.warnings);
    }
}

impl SerializePacket for ErrPacket {
    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.put_u8(0xff);
        buf.put_u16_le(self.error_code);
        buf.extend_from_slice(self.error_message.as_bytes())
        //TODO: sql_state
    }
}

impl SerializePacket for Handshake {
    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.put_u8(self.protocol_version);
        buf.put_str_nul(&self.server_version);
        buf.put_u32_le(self.connection_id);
        buf.put_slice(self.auth_plugin_data.first_ref());
        buf.put_u8(0x00);
        buf.put_u16_le((self.server_capabilities.bits() & 0x0000_FFFF) as u16);
        buf.put_u8(self.server_default_collation);
        buf.put_u16_le(self.status.bits());
        buf.put_u16_le(((self.server_capabilities.bits() & 0xFFFF_0000) >> 16) as u16);

        if self.server_capabilities.contains(Capabilities::PLUGIN_AUTH) {
            buf.put_u8((self.auth_plugin_data.last_ref().len() + 8 + 1) as u8);
        } else {
            buf.put_u8(0);
        }

        buf.put_slice(&[0_u8; 10][..]);

        if self
            .server_capabilities
            .contains(Capabilities::SECURE_CONNECTION)
        {
            buf.put_slice(self.auth_plugin_data.last_ref());
            buf.put_u8(0);
        }

        if self.server_capabilities.contains(Capabilities::PLUGIN_AUTH) {
            if let Some(auth_plugin) = self.auth_plugin {
                buf.put_str_nul(match auth_plugin {
                    AuthPlugin::MySqlNativePassword => "mysql_native_password",
                    AuthPlugin::CachingSha2Password => "caching_sha2_password",
                    AuthPlugin::Sha256Password => "sha256_password",
                });
            }
        }
    }
}

impl SerializePacket for AuthSwitchRequest<'_> {
    fn serialize(&self, buf: &mut Vec<u8>) {
        MySerialize::serialize(self, buf);
    }
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

    fn push<P: SerializePacket>(&mut self, packet: &P) -> Result<()> {
        let mut buf = vec![];
        packet.serialize(&mut buf);
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

    // async fn recv<'a, P>(
    //     &'a mut self,
    //     ctx: P::Ctx,
    // ) -> Result<P> where P: MyDeserialize<'a> {    }

    async fn recv(&mut self) -> Result<Vec<u8>> {
        let mut payload = vec![];
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
        Ok(payload)
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
            })?;
        } else {
            self.push(&ErrPacket {
                error_code: 1,
                error_message: "Access denied".to_owned(),
                sql_state: None,
            })?;
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
        self.push(&handshake)?;
        self.flush().await?;

        let payload = self.recv().await?;
        let resp = ParseBuf(&payload)
            .parse::<HandshakeResponse>(())
            .context("Failed to parse packet")?;
        info!(?resp, "got response");

        if resp.auth_plugin() == Some(&mysql_common::packets::AuthPlugin::MysqlNativePassword) {
            if self.check_auth_response(resp.scramble_buf()).await? {
                return Ok(());
            }
        }

        let challenge = self.challenge.clone();
        let req = AuthSwitchRequest::new(
            &b"mysql_native_password"[..],
            &challenge[..],
        );
        self.push(&req)?;

        // self.push(&RawBytes::<
        self.flush().await?;

        let response = &self.recv().await?;
        self.check_auth_response(response).await?;

        Ok(())
    }
}

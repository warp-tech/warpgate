#![feature(type_alias_impl_trait, let_else, try_blocks)]
mod common;
use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::buf::Chain;
use bytes::{Buf, Bytes, BytesMut};
use mysql_common::constants::{CapabilityFlags, StatusFlags};
use mysql_common::io::ParseBuf;
use mysql_common::misc::raw::{Const, RawBytes, RawInt, Skip};
use mysql_common::packets::{HandshakePacket, HandshakeResponse, OkPacket};
use mysql_common::proto::codec::PacketCodec;
use mysql_common::proto::{MyDeserialize, MySerialize};
use sqlx_core_guts::io::{BufStream, Encode};
use sqlx_core_guts::mysql::connection::stream::MySqlStream;
use sqlx_core_guts::mysql::protocol::connect::Handshake;
use sqlx_core_guts::mysql::protocol::response::Status;
use sqlx_core_guts::mysql::protocol::{Capabilities, Packet};
use std::borrow::Cow;
use std::fmt::Debug;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::tcp::ReadHalf;
use tokio::net::{TcpListener, TcpStream};
use tracing::*;
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
    sequence_id: u8,
    capabilities: Capabilities,
}

impl Session {
    pub fn new(stream: TcpStream) -> Self {
        let mut capabilities = Capabilities::PROTOCOL_41
            | Capabilities::IGNORE_SPACE
            | Capabilities::DEPRECATE_EOF
            | Capabilities::FOUND_ROWS
            | Capabilities::TRANSACTIONS
            | Capabilities::SECURE_CONNECTION
            | Capabilities::PLUGIN_AUTH_LENENC_DATA
            | Capabilities::MULTI_STATEMENTS
            | Capabilities::MULTI_RESULTS
            | Capabilities::PLUGIN_AUTH
            | Capabilities::PS_MULTI_RESULTS
            | Capabilities::SSL;

        Self {
            stream: BufStream::new(stream),
            capabilities,
            sequence_id: 0,
        }
    }

    async fn recv_packet(&mut self) -> Result<Packet<Bytes>> {
        // https://dev.mysql.com/doc/dev/mysql-server/8.0.12/page_protocol_basic_packets.html
        // https://mariadb.com/kb/en/library/0-packet/#standard-packet

        let mut header: Bytes = self.stream.read(4).await?;

        let packet_size = header.get_uint_le(3) as usize;
        let sequence_id = header.get_u8();

        self.sequence_id = sequence_id.wrapping_add(1);

        let payload: Bytes = self.stream.read(packet_size).await?;

        // TODO: packet compression
        // TODO: packet joining

        if payload
            .get(0)
            .ok_or(anyhow::anyhow!("Packet empty"))?
            .eq(&0xff)
        {
            // self.waiting.pop_front();

            // instead of letting this packet be looked at everywhere, we check here
            // and emit a proper Error
            anyhow::bail!("Protocol error");
            // return Err(MySqlDatabaseError(ErrPacket::decode_with(
            //     payload,
            //     self.capabilities,
            // )?)
            // .into());
        }

        Ok(Packet(payload))
    }

    pub(crate) async fn send_packet<'en, T>(&mut self, payload: T) -> Result<()>
    where
        T: Encode<'en, Capabilities>,
    {
        self.sequence_id = 0;
        self.write_packet(payload);
        self.stream.flush().await.context("Failed to flush stream")
    }

    pub(crate) fn write_packet<'en, T>(&mut self, payload: T)
    where
        T: Encode<'en, Capabilities>,
    {
        self.stream
            .write_with(Packet(payload), (self.capabilities, &mut self.sequence_id));
    }

    pub async fn run(mut self) -> Result<()> {
        let mut inner = vec![];
        HandshakePacket::new(
            10,
            Cow::Borrowed(&b"10.0.0-Warpgate"[..]),
            1,
            b"abcdefgh".to_owned(),
            None::<&[u8]>,
            CapabilityFlags::CLIENT_PROTOCOL_41
                | CapabilityFlags::CLIENT_PLUGIN_AUTH
                | CapabilityFlags::CLIENT_LONG_PASSWORD
                | CapabilityFlags::CLIENT_FOUND_ROWS
                | CapabilityFlags::CLIENT_LONG_FLAG
                | CapabilityFlags::CLIENT_NO_SCHEMA
                | CapabilityFlags::CLIENT_IGNORE_SIGPIPE
                | CapabilityFlags::CLIENT_MULTI_RESULTS
                | CapabilityFlags::CLIENT_MULTI_STATEMENTS
                | CapabilityFlags::CLIENT_PS_MULTI_RESULTS
                | CapabilityFlags::CLIENT_CONNECT_ATTRS
                | CapabilityFlags::CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
                | CapabilityFlags::CLIENT_CONNECT_WITH_DB
                | CapabilityFlags::CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS
                | CapabilityFlags::CLIENT_SESSION_TRACK
                | CapabilityFlags::CLIENT_IGNORE_SPACE
                | CapabilityFlags::CLIENT_INTERACTIVE
                | CapabilityFlags::CLIENT_TRANSACTIONS
                | CapabilityFlags::MULTI_FACTOR_AUTHENTICATION
                | CapabilityFlags::CLIENT_DEPRECATE_EOF
                | CapabilityFlags::CLIENT_RESERVED
                | CapabilityFlags::CLIENT_SECURE_CONNECTION,
            0,
            StatusFlags::empty(),
            Some(Cow::Borrowed(&b"mysql_native_password"[..])),
        )
        .serialize(&mut inner);

        let mut packet = BytesMut::new();
        let mut codec = PacketCodec::default();
        codec
            .encode(&mut &*inner, &mut packet)
            .context("Failed to encode handshake packet")?;

        self.stream.write(&packet[..]);

        self.stream
            .flush()
            .await
            .context("Failed to flush stream")?;

        let mut inbound_buffer = BytesMut::new();
        loop {
            let read_bytes = self.stream.read_buf(&mut inbound_buffer).await?;
            if read_bytes == 0 {
                break;
            }
            info!(?inbound_buffer, "got packet");
            let mut inner_buf = vec![];
            let result = codec.decode(&mut inbound_buffer, &mut inner_buf)?;
            if result {
                info!(?inner_buf, "got full packet");
                let mut pb = ParseBuf(&inner_buf);
                let pkt = HandshakeResponse::deserialize((), &mut pb)?;
                info!(?pkt, "got response");
            }
            info!(?inbound_buffer, "after got packet");
        }
        Ok(())
    }
}

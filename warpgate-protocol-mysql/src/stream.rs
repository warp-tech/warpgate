use bytes::{Bytes, BytesMut};
use mysql_common::proto::codec::error::PacketCodecError;
use mysql_common::proto::codec::PacketCodec;
use sqlx_core_guts::io::Encode;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::*;

use crate::tls::{MaybeTlsStream, MaybeTlsStreamError, UpgradableStream};

#[derive(thiserror::Error, Debug)]
pub enum MySqlStreamError {
    #[error("packet codec")]
    Codec(#[from] PacketCodecError),
    #[error("I/O")]
    Io(#[from] std::io::Error),
}

pub struct MySqlStream<TS>
where
    TcpStream: UpgradableStream<TS>,
    TS: AsyncRead + AsyncWrite + Unpin,
{
    stream: MaybeTlsStream<TcpStream, TS>,
    codec: PacketCodec,
    inbound_buffer: BytesMut,
    outbound_buffer: BytesMut,
}

impl<TS> MySqlStream<TS>
where
    TcpStream: UpgradableStream<TS>,
    TS: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream: MaybeTlsStream::new(stream),
            codec: PacketCodec::default(),
            inbound_buffer: BytesMut::new(),
            outbound_buffer: BytesMut::new(),
        }
    }

    pub fn push<'a, C, P: Encode<'a, C>>(
        &mut self,
        packet: &'a P,
        context: C,
    ) -> Result<(), MySqlStreamError> {
        let mut buf = vec![];
        packet.encode_with(&mut buf, context);
        self.codec.encode(&mut &*buf, &mut self.outbound_buffer)?;
        Ok(())
    }

    pub async fn flush(&mut self) -> std::io::Result<()> {
        trace!(outbound_buffer=?self.outbound_buffer, "sending");
        self.stream.write_all(&self.outbound_buffer[..]).await?;
        self.outbound_buffer = BytesMut::new();
        self.stream
            .flush()
            .await?;
        Ok(())
    }

    pub async fn recv(&mut self) -> Result<Option<Bytes>, MySqlStreamError> {
        let mut payload = BytesMut::new();
        loop {
            {
                let got_full_packet = self.codec.decode(&mut self.inbound_buffer, &mut payload)?;
                if got_full_packet {
                    trace!(?payload, "received");
                    return Ok(Some(payload.freeze()));
                }
            }
            let read_bytes = self.stream.read_buf(&mut self.inbound_buffer).await?;
            if read_bytes == 0 {
                return Ok(None);
            }
            trace!(inbound_buffer=?self.inbound_buffer, "received chunk");
        }
    }

    pub fn reset_sequence_id(&mut self) {
        self.codec.reset_seq_id();
    }

    pub async fn upgrade(
        mut self,
        config: <TcpStream as UpgradableStream<TS>>::UpgradeConfig,
    ) -> Result<Self, MaybeTlsStreamError> {
        self.stream = self.stream.upgrade(config).await?;
        Ok(self)
    }

    pub fn is_tls(&self) -> bool {
        match self.stream {
            MaybeTlsStream::Raw(_) => false,
            MaybeTlsStream::Tls(_) => true,
            MaybeTlsStream::Upgrading => false,
        }
    }
}

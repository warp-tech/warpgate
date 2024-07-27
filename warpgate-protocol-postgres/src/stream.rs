use std::fmt::Debug;

use bytes::{Bytes, BytesMut};
use pgwire::error::{PgWireError, PgWireResult};
use pgwire::messages::PgWireFrontendMessage;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::*;
use warpgate_common::{MaybeTlsStream, MaybeTlsStreamError, UpgradableStream};

#[derive(thiserror::Error, Debug)]
pub enum PostgresStreamError {
    #[error("decode: {0}")]
    Decode(#[from] PgWireError),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
}

pub(crate) trait PostgresDecode {
    fn decode(buf: &mut BytesMut) -> PgWireResult<Option<Self>>
    where
        Self: Sized;
}

#[derive(Debug)]
pub(crate) enum PgWireStartupOrSslRequest {
    Startup(pgwire::messages::startup::Startup),
    SslRequest(pgwire::messages::startup::SslRequest),
}

impl PostgresDecode for PgWireStartupOrSslRequest {
    fn decode(buf: &mut BytesMut) -> PgWireResult<Option<Self>> {
        if let Ok(Some(result)) = pgwire::messages::startup::SslRequest::decode(buf) {
            return Ok(Some(Self::SslRequest(result)));
        }
        pgwire::messages::startup::Startup::decode(buf).map(|x| x.map(Self::Startup))
    }
}

#[derive(Debug)]
pub(crate) struct PgWireGenericFrontendMessage(pub PgWireFrontendMessage);

impl PostgresDecode for PgWireGenericFrontendMessage {
    fn decode(buf: &mut BytesMut) -> PgWireResult<Option<Self>> {
        PgWireFrontendMessage::decode(buf).map(|x| x.map(PgWireGenericFrontendMessage))
    }
}

impl<T: pgwire::messages::Message> PostgresDecode for T {
    fn decode(buf: &mut BytesMut) -> PgWireResult<Option<Self>> {
        T::decode(buf)
    }
}

pub(crate) struct PostgresStream<TS>
where
    TcpStream: UpgradableStream<TS>,
    TS: AsyncRead + AsyncWrite + Unpin,
{
    stream: MaybeTlsStream<TcpStream, TS>,
    // codec: PacketCodec,
    inbound_buffer: BytesMut,
    outbound_buffer: BytesMut,
}

impl<TS> PostgresStream<TS>
where
    TcpStream: UpgradableStream<TS>,
    TS: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream: MaybeTlsStream::new(stream),
            // codec: PacketCodec::default(),
            inbound_buffer: BytesMut::new(),
            outbound_buffer: BytesMut::new(),
        }
    }

    pub fn push<M: pgwire::messages::Message>(
        &mut self,
        message: M,
    ) -> Result<(), PostgresStreamError> {
        message.encode(&mut self.outbound_buffer)?;
        Ok(())
    }

    pub async fn flush(&mut self) -> std::io::Result<()> {
        trace!(outbound_buffer=?self.outbound_buffer, "sending");
        self.stream.write_all(&self.outbound_buffer[..]).await?;
        self.outbound_buffer = BytesMut::new();
        self.stream.flush().await?;
        Ok(())
    }

    pub(crate) async fn recv<T: PostgresDecode + Debug>(
        &mut self,
    ) -> Result<Option<T>, PostgresStreamError> {
        loop {
            if let Some(message) = T::decode(&mut self.inbound_buffer)? {
                trace!(?message, "received");
                return Ok(Some(message));
            };

            let read_bytes = self.stream.read_buf(&mut self.inbound_buffer).await?;
            if read_bytes == 0 {
                return Ok(None);
            }
            trace!(inbound_buffer=?self.inbound_buffer, "received chunk");
        }
    }

    // pub fn reset_sequence_id(&mut self) {
    //     self.codec.reset_seq_id();
    // }

    pub(crate) async fn upgrade(
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

use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use mysql_common::proto::codec::PacketCodec;
use sqlx_core_guts::io::{BufStream, Encode};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tracing::*;

pub struct MySQLStream {
    stream: BufStream<MaybeTlsStream<TcpStream>>,
    codec: PacketCodec,
    inbound_buffer: BytesMut,
    outbound_buffer: BytesMut,
}

impl MySQLStream {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream: BufStream::new(MaybeTlsStream::Raw(stream)),
            codec: PacketCodec::default(),
            inbound_buffer: BytesMut::new(),
            outbound_buffer: BytesMut::new(),
        }
    }

    pub fn push<'a, C, P: Encode<'a, C>>(&mut self, packet: &'a P, context: C) -> Result<()> {
        let mut buf = vec![];
        packet.encode_with(&mut buf, context);
        self.codec
            .encode(&mut &*buf, &mut self.outbound_buffer)
            .context("Failed to encode packet")?;
        Ok(())
    }

    pub async fn flush(&mut self) -> Result<()> {
        trace!(outbound_buffer=?self.outbound_buffer, "sending");
        self.stream.write(&self.outbound_buffer[..]);
        self.outbound_buffer = BytesMut::new();
        self.stream
            .flush()
            .await
            .context("Failed to flush stream")?;
        Ok(())
    }

    pub async fn recv(&mut self) -> Result<Bytes> {
        let mut payload = BytesMut::new();
        loop {
            {
                let got_full_packet = self.codec.decode(&mut self.inbound_buffer, &mut payload)?;
                if got_full_packet {
                    trace!(?payload, "received");
                    return Ok(payload.freeze());
                }
            }
            let read_bytes = self.stream.read_buf(&mut self.inbound_buffer).await?;
            if read_bytes == 0 {
                anyhow::bail!("Unexpected EOF");
            }
            trace!(inbound_buffer=?self.inbound_buffer, "received chunk");
        }
    }

    pub fn reset_sequence_id(&mut self) {
        self.codec.reset_seq_id();
    }

    pub async fn upgrade(&mut self, tls_config: Arc<rustls::ServerConfig>) -> Result<()> {
        if let MaybeTlsStream::Raw(stream) =
            std::mem::replace(&mut self.stream, BufStream::new(MaybeTlsStream::Upgrading)).take()
        {
            let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);

            let accept = acceptor.accept(stream).await.context("TLS setup failed")?;

            self.stream = BufStream::new(MaybeTlsStream::ServerTls(accept));

            Ok(())
        } else {
            anyhow::bail!("bad state")
        }
    }

    pub fn is_tls(&self) -> bool {
        match *self.stream {
            MaybeTlsStream::Raw(_) => false,
            MaybeTlsStream::ServerTls(_) => true,
            MaybeTlsStream::ClientTls(_) => true,
            MaybeTlsStream::Upgrading => false,
        }
    }
}

enum MaybeTlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    ClientTls(tokio_rustls::client::TlsStream<S>),
    ServerTls(tokio_rustls::server::TlsStream<S>),
    Raw(S),
    Upgrading,
}

impl<S> AsyncRead for MaybeTlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<tokio::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::ClientTls(tls) => Pin::new(tls).poll_read(cx, buf),
            MaybeTlsStream::ServerTls(tls) => Pin::new(tls).poll_read(cx, buf),
            MaybeTlsStream::Raw(stream) => Pin::new(stream).poll_read(cx, buf),
            _ => unreachable!(),
        }
    }
}

impl<S> AsyncWrite for MaybeTlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match self.get_mut() {
            MaybeTlsStream::ClientTls(tls) => Pin::new(tls).poll_write(cx, buf),
            MaybeTlsStream::ServerTls(tls) => Pin::new(tls).poll_write(cx, buf),
            MaybeTlsStream::Raw(stream) => Pin::new(stream).poll_write(cx, buf),
            _ => unreachable!(),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            MaybeTlsStream::ClientTls(tls) => Pin::new(tls).poll_flush(cx),
            MaybeTlsStream::ServerTls(tls) => Pin::new(tls).poll_flush(cx),
            MaybeTlsStream::Raw(stream) => Pin::new(stream).poll_flush(cx),
            _ => unreachable!(),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            MaybeTlsStream::ClientTls(tls) => Pin::new(tls).poll_shutdown(cx),
            MaybeTlsStream::ServerTls(tls) => Pin::new(tls).poll_shutdown(cx),
            MaybeTlsStream::Raw(stream) => Pin::new(stream).poll_shutdown(cx),
            _ => unreachable!(),
        }
    }
}

use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use mysql_common::proto::codec::PacketCodec;
use sqlx_core_guts::io::{BufStream, Encode};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tracing::*;

pub struct MySQLStream {
    stream: BufStream<TcpStream>,
    codec: PacketCodec,
    inbound_buffer: BytesMut,
    outbound_buffer: BytesMut,
}

impl MySQLStream {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream: BufStream::new(stream),
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
                    return Ok(payload.freeze())
                }
            }
            let read_bytes = self.stream.read_buf(&mut self.inbound_buffer).await?;
            if read_bytes == 0 {
                anyhow::bail!("Unexpected EOF");
            }
            trace!(inbound_buffer=?self.inbound_buffer, "received chunk");
        }
    }

    pub fn reset_sequence_id (&mut self) {
        self.codec.reset_seq_id();
    }
}

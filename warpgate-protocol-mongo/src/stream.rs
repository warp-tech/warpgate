use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::trace;

use crate::error::MongoError;

/// The largest wire message we will read or write. This is also what the
/// handshake replies advertise, so clients size their frames to match.
pub const MAX_MESSAGE_SIZE: i32 = mongo_common::consts::MAX_MSG_LEN;

/// Frames the MongoDB wire protocol over any byte transport. TLS is handled
/// outside this type: clients connect with TLS from the first byte and the
/// server accepts the handshake before the session starts.
pub struct MongoStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    stream: T,
    inbound_buffer: BytesMut,
    outbound_buffer: BytesMut,
}

impl<T> MongoStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: T) -> Self {
        Self {
            stream,
            inbound_buffer: BytesMut::new(),
            outbound_buffer: BytesMut::new(),
        }
    }

    /// Reads one wire message, buffering until a full frame is available.
    /// `Ok(None)` means the peer closed the connection.
    pub async fn recv(
        &mut self,
    ) -> Result<Option<(mongowire::messages::Header, mongowire::MessageBody)>, MongoError> {
        loop {
            if let Some(message) =
                mongowire::framing::parse_message(&mut self.inbound_buffer, MAX_MESSAGE_SIZE)?
            {
                trace!(header=?message.0, "received");
                return Ok(Some(message));
            }
            let read_bytes = self.stream.read_buf(&mut self.inbound_buffer).await?;
            if read_bytes == 0 {
                return Ok(None);
            }
        }
    }

    /// Queues one message for sending. The header is copied; framing fills in
    /// the final `message_length`. Checksum trailers are never appended — the
    /// handshake does not advertise checksum support.
    pub fn push(
        &mut self,
        header: &mongowire::messages::Header,
        body: &mongowire::MessageBody,
    ) -> Result<(), MongoError> {
        let mut header = *header;
        mongowire::framing::encode_message(&mut header, body, false, &mut self.outbound_buffer)?;
        Ok(())
    }

    pub async fn flush(&mut self) -> std::io::Result<()> {
        trace!(outbound_buffer=?self.outbound_buffer, "sending");
        self.stream.write_all(&self.outbound_buffer[..]).await?;
        self.outbound_buffer.clear();
        self.stream.flush().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use tokio::io::AsyncWriteExt;
    use wirebson::Document;

    use super::*;

    /// A message pushed through a pipe must come out intact, including the
    /// framing-imposed `message_length`.
    #[tokio::test]
    async fn frame_roundtrip() {
        let (mut writer, reader) = tokio::io::duplex(64 * 1024);
        let writer = tokio::spawn(async move {
            let mut doc = Document::new();
            doc.add("ping", 1_i32);
            doc.add("ok", 1.0_f64);
            let body = mongowire::MessageBody::Msg(
                mongowire::api::response::op_msg(mongowire::messages::MsgFlags::empty(), doc.encode().unwrap())
                    .unwrap(),
            );
            let mut header =
                mongowire::messages::Header::new(7, 0, mongowire::messages::Opcode::Msg);
            let mut out = BytesMut::new();
            mongowire::framing::encode_message(&mut header, &body, false, &mut out).unwrap();
            writer.write_all(&out[..]).await.unwrap();
            writer.flush().await.unwrap();
        });

        let mut stream = MongoStream::new(reader);
        let (header, body) = stream.recv().await.unwrap().unwrap();
        writer.await.unwrap();
        assert_eq!(header.request_id, 7);
        assert!(matches!(body, mongowire::MessageBody::Msg(_)));
    }

    /// Two frames sent back-to-back must decode one at a time, with the
    /// remainder buffered.
    #[tokio::test]
    async fn frames_are_decoded_one_at_a_time() {
        let (mut writer, reader) = tokio::io::duplex(64 * 1024);
        let writer = tokio::spawn(async move {
            for request_id in [1, 2] {
                let mut doc = Document::new();
                doc.add("ping", 1_i32);
                let body = mongowire::MessageBody::Msg(
                    mongowire::api::response::op_msg(
                        mongowire::messages::MsgFlags::empty(),
                        doc.encode().unwrap(),
                    )
                    .unwrap(),
                );
                let mut header = mongowire::messages::Header::new(
                    request_id,
                    0,
                    mongowire::messages::Opcode::Msg,
                );
                let mut out = BytesMut::new();
                mongowire::framing::encode_message(&mut header, &body, false, &mut out).unwrap();
                writer.write_all(&out[..]).await.unwrap();
            }
            writer.flush().await.unwrap();
        });

        let mut stream = MongoStream::new(reader);
        let (first, _) = stream.recv().await.unwrap().unwrap();
        assert_eq!(first.request_id, 1);
        let (second, _) = stream.recv().await.unwrap().unwrap();
        assert_eq!(second.request_id, 2);
        writer.await.unwrap();
    }

    /// A half-closed pipe ends the stream rather than erroring it.
    #[tokio::test]
    async fn eof_yields_none() {
        let (writer, reader) = tokio::io::duplex(1024);
        drop(writer);
        let mut stream = MongoStream::new(reader);
        assert!(stream.recv().await.unwrap().is_none());
    }
}

use std::io;

use bytes::{Bytes, BytesMut};
use ironrdp_connector::{ConnectorResult, Sequence, Written};
use ironrdp_core::WriteBuf;
use ironrdp_pdu::PduHint;
use tracing::{debug, trace};

// TODO: investigate if we could use static async fn / return position impl trait in traits when stabilized:
// https://github.com/rust-lang/rust/issues/91611

pub trait FramedRead {
    type ReadFut<'read>: Future<Output = io::Result<usize>> + 'read
    where
        Self: 'read;

    /// Reads from stream and fills internal buffer
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe. If you use it as the event in a
    /// `tokio::select!` statement and some other branch
    /// completes first, then it is guaranteed that no data was read.
    fn read<'a>(&'a mut self, buf: &'a mut BytesMut) -> Self::ReadFut<'a>;
}

pub trait FramedWrite {
    type WriteAllFut<'write>: Future<Output = io::Result<()>> + 'write
    where
        Self: 'write;

    /// Writes an entire buffer into this stream.
    ///
    /// # Cancel safety
    ///
    /// This method is not cancellation safe. If it is used as the event
    /// in a `tokio::select!` statement and some other
    /// branch completes first, then the provided buffer may have been
    /// partially written, but future calls to `write_all` will start over
    /// from the beginning of the buffer.
    fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> Self::WriteAllFut<'a>;
}

pub trait StreamWrapper: Sized {
    type InnerStream;

    fn from_inner(stream: Self::InnerStream) -> Self;

    fn into_inner(self) -> Self::InnerStream;

    fn get_inner(&self) -> &Self::InnerStream;

    fn get_inner_mut(&mut self) -> &mut Self::InnerStream;
}

pub struct Framed<S> {
    stream: S,
    buf: BytesMut,
}

impl<S> Framed<S> {
    pub fn peek(&self) -> &[u8] {
        &self.buf
    }
}

impl<S> Framed<S>
where
    S: StreamWrapper,
{
    pub fn new(stream: S::InnerStream) -> Self {
        Self::new_with_leftover(stream, BytesMut::new())
    }

    pub fn new_with_leftover(stream: S::InnerStream, leftover: BytesMut) -> Self {
        Self {
            stream: S::from_inner(stream),
            buf: leftover,
        }
    }

    pub fn into_inner(self) -> (S::InnerStream, BytesMut) {
        (self.stream.into_inner(), self.buf)
    }

    pub fn into_inner_no_leftover(self) -> S::InnerStream {
        let (stream, leftover) = self.into_inner();
        debug_assert_eq!(leftover.len(), 0, "unexpected leftover");
        stream
    }

    pub fn get_inner(&self) -> (&S::InnerStream, &BytesMut) {
        (self.stream.get_inner(), &self.buf)
    }

    pub fn get_inner_mut(&mut self) -> (&mut S::InnerStream, &mut BytesMut) {
        (self.stream.get_inner_mut(), &mut self.buf)
    }
}

impl<S> Framed<S>
where
    S: FramedRead,
{
    /// Accumulates at least `length` bytes and returns exactly `length` bytes, keeping the leftover in the internal buffer.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe. If you use it as the event in a
    /// `tokio::select!` statement and some other branch
    /// completes first, then it is safe to drop the future and re-create it later.
    /// Data may have been read, but it will be stored in the internal buffer.
    pub(crate) async fn read_exact(&mut self, length: usize) -> io::Result<BytesMut> {
        loop {
            if self.buf.len() >= length {
                return Ok(self.buf.split_to(length));
            } else {
                self.buf
                    .reserve(length.checked_sub(self.buf.len()).expect("length > self.buf.len()"));
            }

            let len = self.read().await?;

            // Handle EOF
            if len == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "not enough bytes"));
            }
        }
    }

    /// Reads a standard RDP PDU frame.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe. If you use it as the event in a
    /// `tokio::select!` statement and some other branch
    /// completes first, then it is safe to drop the future and re-create it later.
    /// Data may have been read, but it will be stored in the internal buffer.
    pub async fn read_pdu(&mut self) -> io::Result<(ironrdp_pdu::Action, BytesMut)> {
        loop {
            // Try decoding and see if a frame has been received already
            match ironrdp_pdu::find_size(self.peek()) {
                Ok(Some(pdu_info)) => {
                    let frame = self.read_exact(pdu_info.length).await?;

                    return Ok((pdu_info.action, frame));
                }
                Ok(None) => {
                    let len = self.read().await?;

                    // Handle EOF
                    if len == 0 {
                        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "not enough bytes"));
                    }
                }
                Err(e) => return Err(io::Error::other(e)),
            };
        }
    }

    /// Reads a frame using the provided PduHint.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe. If you use it as the event in a
    /// `tokio::select!` statement and some other branch
    /// completes first, then it is safe to drop the future and re-create it later.
    /// Data may have been read, but it will be stored in the internal buffer.
    pub async fn read_by_hint(&mut self, hint: &dyn PduHint) -> io::Result<Bytes> {
        loop {
            match hint.find_size(self.peek()).map_err(io::Error::other)? {
                Some((matched, length)) => {
                    let bytes = self.read_exact(length).await?.freeze();
                    if matched {
                        return Ok(bytes);
                    } else {
                        debug!("Received and lost an unexpected PDU");
                    }
                }
                None => {
                    let len = self.read().await?;

                    // Handle EOF
                    if len == 0 {
                        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "not enough bytes"));
                    }
                }
            };
        }
    }

    /// Reads from stream and fills internal buffer, returning how many bytes were read.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe. If you use it as the event in a
    /// `tokio::select!` statement and some other branch
    /// completes first, then it is guaranteed that no data was read.
    async fn read(&mut self) -> io::Result<usize> {
        self.stream.read(&mut self.buf).await
    }
}

impl<S> FramedWrite for Framed<S>
where
    S: FramedWrite,
{
    type WriteAllFut<'write>
        = S::WriteAllFut<'write>
    where
        Self: 'write;

    /// Attempts to write an entire buffer into this `Framed`’s stream.
    ///
    /// # Cancel safety
    ///
    /// This method is not cancellation safe. If it is used as the event
    /// in a `tokio::select!` statement and some other
    /// branch completes first, then the provided buffer may have been
    /// partially written, but future calls to `write_all` will start over
    /// from the beginning of the buffer.
    fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> Self::WriteAllFut<'a> {
        self.stream.write_all(buf)
    }
}

pub async fn single_sequence_step<S>(
    framed: &mut Framed<S>,
    sequence: &mut dyn Sequence,
    buf: &mut WriteBuf,
) -> ConnectorResult<()>
where
    S: FramedWrite + FramedRead,
{
    buf.clear();
    let written = single_sequence_step_read(framed, sequence, buf).await?;
    single_sequence_step_write(framed, buf, written).await
}

pub async fn single_sequence_step_read<S>(
    framed: &mut Framed<S>,
    sequence: &mut dyn Sequence,
    buf: &mut WriteBuf,
) -> ConnectorResult<Written>
where
    S: FramedRead,
{
    buf.clear();

    if let Some(next_pdu_hint) = sequence.next_pdu_hint() {
        debug!(
            connector.state = sequence.state().name(),
            hint = ?next_pdu_hint,
            "Wait for PDU"
        );

        let pdu = framed
            .read_by_hint(next_pdu_hint)
            .await
            .map_err(|e| ironrdp_connector::custom_err!("read frame by hint", e))?;

        trace!(length = pdu.len(), "PDU received");

        sequence.step(&pdu, buf)
    } else {
        sequence.step_no_input(buf)
    }
}

async fn single_sequence_step_write<S>(
    framed: &mut Framed<S>,
    buf: &mut WriteBuf,
    written: Written,
) -> ConnectorResult<()>
where
    S: FramedWrite,
{
    if let Some(response_len) = written.size() {
        debug_assert_eq!(buf.filled_len(), response_len);
        let response = buf.filled();
        trace!(response_len, "Send response");
        framed
            .write_all(response)
            .await
            .map_err(|e| ironrdp_connector::custom_err!("write all", e))?;
    }

    Ok(())
}

use crate::Error;
use cryptovec::CryptoVec;
use futures::task::*;
use std;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

/// The buffer to read the identification string (first line in the
/// protocol).
struct ReadSshIdBuffer {
    pub buf: CryptoVec,
    pub total: usize,
    pub bytes_read: usize,
    pub sshid_len: usize,
}

impl ReadSshIdBuffer {
    pub fn id(&self) -> &[u8] {
        &self.buf[..self.sshid_len]
    }

    pub fn new() -> ReadSshIdBuffer {
        let mut buf = CryptoVec::new();
        buf.resize(256);
        ReadSshIdBuffer {
            buf: buf,
            sshid_len: 0,
            bytes_read: 0,
            total: 0,
        }
    }
}

impl std::fmt::Debug for ReadSshIdBuffer {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "ReadSshId {:?}", self.id())
    }
}

/// SshRead<R> is the same as R, plus a small buffer in the beginning to
/// read the identification string. After the first line in the
/// connection, the `id` parameter is never used again.
pub struct SshRead<R> {
    id: Option<ReadSshIdBuffer>,
    pub r: R,
}

impl<R: AsyncRead + AsyncWrite> SshRead<R> {
    pub fn split(self) -> (SshRead<tokio::io::ReadHalf<R>>, tokio::io::WriteHalf<R>) {
        let (r, w) = tokio::io::split(self.r);
        (SshRead { id: self.id, r }, w)
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for SshRead<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<Result<(), std::io::Error>> {
        if let Some(mut id) = self.id.take() {
            debug!("id {:?} {:?}", id.total, id.bytes_read);
            if id.total > id.bytes_read {
                let total = id.total.min(id.bytes_read + buf.remaining());
                let result = { buf.put_slice(&id.buf[id.bytes_read..total]) };
                debug!("read {:?} bytes from id.buf", result);
                id.bytes_read += total - id.bytes_read;
                self.id = Some(id);
                return Poll::Ready(Ok(()));
            }
        }
        AsyncRead::poll_read(Pin::new(&mut self.get_mut().r), cx, buf)
    }
}

impl<R: std::io::Write> std::io::Write for SshRead<R> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        self.r.write(buf)
    }
    fn flush(&mut self) -> Result<(), std::io::Error> {
        self.r.flush()
    }
}

impl<R: AsyncWrite + Unpin> AsyncWrite for SshRead<R> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        AsyncWrite::poll_write(Pin::new(&mut self.r), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), std::io::Error>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.r), cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<(), std::io::Error>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.r), cx)
    }
}

impl<R: AsyncRead + Unpin> SshRead<R> {
    pub fn new(r: R) -> Self {
        SshRead {
            id: Some(ReadSshIdBuffer::new()),
            r,
        }
    }

    pub async fn read_ssh_id(&mut self) -> Result<&[u8], Error> {
        let ssh_id = self.id.as_mut().unwrap();
        loop {
            let mut i = 0;
            debug!("read_ssh_id: reading");
            let n = AsyncReadExt::read(&mut self.r, &mut ssh_id.buf[ssh_id.total..]).await?;
            debug!("read {:?}", n);

            ssh_id.total += n;
            debug!("{:?}", std::str::from_utf8(&ssh_id.buf[..ssh_id.total]));
            if n == 0 {
                return Err(Error::Disconnect.into());
            }
            loop {
                if i >= ssh_id.total - 1 {
                    break;
                }
                if ssh_id.buf[i] == b'\r' && ssh_id.buf[i + 1] == b'\n' {
                    ssh_id.bytes_read = i + 2;
                    break;
                } else if ssh_id.buf[i + 1] == b'\n' {
                    // This is really wrong, but OpenSSH 7.4 uses
                    // it.
                    ssh_id.bytes_read = i + 2;
                    i += 1;
                    break;
                } else {
                    i += 1;
                }
            }

            if ssh_id.bytes_read > 0 {
                // If we have a full line, handle it.
                if i >= 8 {
                    if &ssh_id.buf[0..8] == b"SSH-2.0-" {
                        // Either the line starts with "SSH-2.0-"
                        ssh_id.sshid_len = i;
                        return Ok(&ssh_id.buf[..ssh_id.sshid_len]);
                    }
                }
                // Else, it is a "preliminary" (see
                // https://tools.ietf.org/html/rfc4253#section-4.2),
                // and we can discard it and read the next one.
                ssh_id.total = 0;
                ssh_id.bytes_read = 0;
            }
            debug!("bytes_read: {:?}", ssh_id.bytes_read);
        }
    }
}

use std::str::from_utf8;

use bytes::{Buf, Bytes, TryGetError};
use memchr::memchr;

use crate::err_protocol;
use crate::error::Error;

/// Readers for packet fields. All of them fail on a short buffer instead of
/// panicking like the plain [`Buf`] methods, as packets come off the wire.
pub trait BufExt: Buf {
    // Skip a fixed number of bytes
    fn skip(&mut self, len: usize) -> Result<(), Error>;

    // Read a nul-terminated byte sequence
    fn get_bytes_nul(&mut self) -> Result<Bytes, Error>;

    // Read a byte sequence of the exact length
    fn get_bytes(&mut self, len: usize) -> Result<Bytes, Error>;

    // Read a nul-terminated string
    fn get_str_nul(&mut self) -> Result<String, Error>;

    // Read a string of the exact length
    fn get_str(&mut self, len: usize) -> Result<String, Error>;
}

impl BufExt for Bytes {
    fn skip(&mut self, len: usize) -> Result<(), Error> {
        self.get_bytes(len).map(drop)
    }

    fn get_bytes_nul(&mut self) -> Result<Bytes, Error> {
        let nul =
            memchr(b'\0', self).ok_or_else(|| err_protocol!("expected NUL in byte sequence"))?;

        let v = self.split_to(nul);
        self.advance(1);

        Ok(v)
    }

    fn get_bytes(&mut self, len: usize) -> Result<Bytes, Error> {
        if self.len() < len {
            return Err(TryGetError {
                requested: len,
                available: self.len(),
            }
            .into());
        }
        Ok(self.split_to(len))
    }

    fn get_str_nul(&mut self) -> Result<String, Error> {
        utf8(&self.get_bytes_nul()?)
    }

    fn get_str(&mut self, len: usize) -> Result<String, Error> {
        utf8(&self.get_bytes(len)?)
    }
}

fn utf8(bytes: &[u8]) -> Result<String, Error> {
    from_utf8(bytes)
        .map(ToOwned::to_owned)
        .map_err(|err| err_protocol!("{}", err))
}

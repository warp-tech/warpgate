use bytes::{Buf, Bytes};

use crate::error::Error;
use crate::io::BufExt;

pub trait MySqlBufExt: Buf {
    // Read a length-encoded integer.
    // NOTE: 0xfb or NULL is only returned for binary value encoding to indicate NULL.
    // NOTE: 0xff is only returned during a result set to indicate ERR.
    // <https://dev.mysql.com/doc/internals/en/integer.html#packet-Protocol::LengthEncodedInteger>
    fn get_uint_lenenc(&mut self) -> Result<u64, Error>;

    // Read a length-encoded string.
    fn get_str_lenenc(&mut self) -> Result<String, Error>;

    // Read a length-encoded byte sequence.
    fn get_bytes_lenenc(&mut self) -> Result<Bytes, Error>;
}

impl MySqlBufExt for Bytes {
    fn get_uint_lenenc(&mut self) -> Result<u64, Error> {
        Ok(match self.try_get_u8()? {
            0xfc => u64::from(self.try_get_u16_le()?),
            0xfd => self.try_get_uint_le(3)?,
            0xfe => self.try_get_u64_le()?,

            v => u64::from(v),
        })
    }

    fn get_str_lenenc(&mut self) -> Result<String, Error> {
        let size = lenenc_size(self)?;
        self.get_str(size)
    }

    fn get_bytes_lenenc(&mut self) -> Result<Bytes, Error> {
        let size = lenenc_size(self)?;
        self.get_bytes(size)
    }
}

fn lenenc_size(buf: &mut Bytes) -> Result<usize, Error> {
    let size = buf.get_uint_lenenc()?;
    usize::try_from(size).map_err(Error::protocol)
}

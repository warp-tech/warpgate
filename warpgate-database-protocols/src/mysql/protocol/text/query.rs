use bytes::{Buf, Bytes};

use crate::error::Error;
use crate::io::{BufExt, Decode, Encode};
use crate::mysql::protocol::Capabilities;

// https://dev.mysql.com/doc/internals/en/com-query.html

#[derive(Debug)]
pub struct Query(pub String);

impl Encode<'_, ()> for Query {
    fn encode_with(&self, buf: &mut Vec<u8>, _: ()) {
        buf.push(0x03); // COM_QUERY
        buf.extend(self.0.as_bytes())
    }
}

impl Encode<'_, Capabilities> for Query {
    fn encode_with(&self, buf: &mut Vec<u8>, _: Capabilities) {
        buf.push(0x03); // COM_QUERY
        buf.extend(self.0.as_bytes())
    }
}

impl Decode<'_> for Query {
    fn decode_with(mut buf: Bytes, _: ()) -> Result<Self, Error> {
        buf.advance(1);
        let q = buf.get_str(buf.len())?;
        Ok(Query(q))
    }
}

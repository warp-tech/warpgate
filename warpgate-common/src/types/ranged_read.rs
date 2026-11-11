/// A ranged read of a stored object: the bytes from the requested offset, and
/// how big the whole object is, which an HTTP 206 needs for its `Content-Range`.
pub struct RangedRead {
    pub reader: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
    /// Bytes in this response.
    pub len: u64,
    /// Bytes in the whole object.
    pub total: u64,
}

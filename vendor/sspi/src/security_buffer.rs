use std::fmt;
use std::mem::take;

use crate::{BufferType, Error, ErrorKind, Result, SecurityBufferFlags, SecurityBufferType};

/// A security buffer type with a mutable reference to the buffer data.
/// unflagged
/// Basically, it is a security buffer but without buffer flags.
#[non_exhaustive]
enum UnflaggedSecurityBuffer<'data> {
    Data(&'data mut [u8]),
    Token(&'data mut [u8]),
    StreamHeader(&'data mut [u8]),
    StreamTrailer(&'data mut [u8]),
    Stream(&'data mut [u8]),
    Extra(&'data mut [u8]),
    Padding(&'data mut [u8]),
    Missing(usize),
    Empty,
}

/// A special security buffer type is used for the data decryption. Basically, it's almost the same
/// as `SecurityBuffer` but for decryption.
///
/// [DecryptMessage](https://learn.microsoft.com/en-us/windows/win32/secauthn/decryptmessage--general)
/// "The encrypted message is decrypted in place, overwriting the original contents of its buffer."
///
/// So, the already defined `SecurityBuffer` is not suitable for decryption because it uses [Vec] inside.
/// We use reference in the [SecurityBufferRef] structure to avoid data cloning as much as possible.
/// Decryption/encryption input buffers can be very large. Even up to 32 KiB if we are using this crate as a TSSSP(CREDSSP)
/// security package.
pub struct SecurityBufferRef<'data> {
    buffer_type: UnflaggedSecurityBuffer<'data>,
    buffer_flags: SecurityBufferFlags,
}

impl<'data> SecurityBufferRef<'data> {
    /// Creates a [SecurityBufferRef] with a `Data` buffer type and empty buffer flags.
    pub fn data_buf(data: &mut [u8]) -> SecurityBufferRef<'_> {
        SecurityBufferRef {
            buffer_type: UnflaggedSecurityBuffer::Data(data),
            buffer_flags: Default::default(),
        }
    }

    /// Creates a [SecurityBufferRef] with a `Token` buffer type and empty buffer flags.
    pub fn token_buf(data: &mut [u8]) -> SecurityBufferRef<'_> {
        SecurityBufferRef {
            buffer_type: UnflaggedSecurityBuffer::Token(data),
            buffer_flags: Default::default(),
        }
    }

    /// Creates a [SecurityBufferRef] with a `StreamHeader` buffer type and empty buffer flags.
    pub fn stream_header_buf(data: &mut [u8]) -> SecurityBufferRef<'_> {
        SecurityBufferRef {
            buffer_type: UnflaggedSecurityBuffer::StreamHeader(data),
            buffer_flags: Default::default(),
        }
    }

    /// Creates a [SecurityBufferRef] with a `StreamTrailer` buffer type and empty buffer flags.
    pub fn stream_trailer_buf(data: &mut [u8]) -> SecurityBufferRef<'_> {
        SecurityBufferRef {
            buffer_type: UnflaggedSecurityBuffer::StreamTrailer(data),
            buffer_flags: Default::default(),
        }
    }

    /// Creates a [SecurityBufferRef] with a `Stream` buffer type and empty buffer flags.
    pub fn stream_buf(data: &mut [u8]) -> SecurityBufferRef<'_> {
        SecurityBufferRef {
            buffer_type: UnflaggedSecurityBuffer::Stream(data),
            buffer_flags: Default::default(),
        }
    }

    /// Creates a [SecurityBufferRef] with a `Extra` buffer type and empty buffer flags.
    pub fn extra_buf(data: &mut [u8]) -> SecurityBufferRef<'_> {
        SecurityBufferRef {
            buffer_type: UnflaggedSecurityBuffer::Extra(data),
            buffer_flags: Default::default(),
        }
    }

    /// Creates a [SecurityBufferRef] with a `Padding` buffer type and empty buffer flags.
    pub fn padding_buf(data: &mut [u8]) -> SecurityBufferRef<'_> {
        SecurityBufferRef {
            buffer_type: UnflaggedSecurityBuffer::Padding(data),
            buffer_flags: Default::default(),
        }
    }

    /// Creates a [SecurityBufferRef] with a `Missing` buffer type and empty buffer flags.
    pub fn missing_buf<'a>(count: usize) -> SecurityBufferRef<'a> {
        SecurityBufferRef {
            buffer_type: UnflaggedSecurityBuffer::Missing(count),
            buffer_flags: Default::default(),
        }
    }

    /// Set buffer flags.
    pub fn with_flags(self, buffer_flags: SecurityBufferFlags) -> Self {
        let Self {
            buffer_type,
            buffer_flags: _,
        } = self;

        Self {
            buffer_type,
            buffer_flags,
        }
    }

    /// Creates a [SecurityBufferRef] from based on provided [BufferType].
    ///
    /// Inner buffers will be empty.
    pub fn with_security_buffer_type(security_buffer_type: BufferType) -> Result<Self> {
        Ok(Self {
            buffer_type: match security_buffer_type {
                BufferType::Empty => UnflaggedSecurityBuffer::Empty,
                BufferType::Data => UnflaggedSecurityBuffer::Data(&mut []),
                BufferType::Token => UnflaggedSecurityBuffer::Token(&mut []),
                BufferType::Missing => UnflaggedSecurityBuffer::Missing(0),
                BufferType::Extra => UnflaggedSecurityBuffer::Extra(&mut []),
                BufferType::Padding => UnflaggedSecurityBuffer::Padding(&mut []),
                BufferType::StreamTrailer => UnflaggedSecurityBuffer::StreamTrailer(&mut []),
                BufferType::StreamHeader => UnflaggedSecurityBuffer::StreamHeader(&mut []),
                BufferType::Stream => UnflaggedSecurityBuffer::Stream(&mut []),
                _ => return Err(Error::new(ErrorKind::UnsupportedFunction, "")),
            },
            buffer_flags: SecurityBufferFlags::NONE,
        })
    }

    /// Created a [SecurityBufferRef] from based on provided [BufferType].
    ///
    /// Inner buffers will be empty.
    pub fn with_owned_security_buffer_type(security_buffer_type: SecurityBufferType) -> Result<Self> {
        Ok(Self {
            buffer_type: match security_buffer_type.buffer_type {
                BufferType::Empty => UnflaggedSecurityBuffer::Empty,
                BufferType::Data => UnflaggedSecurityBuffer::Data(&mut []),
                BufferType::Token => UnflaggedSecurityBuffer::Token(&mut []),
                BufferType::Missing => UnflaggedSecurityBuffer::Missing(0),
                BufferType::Extra => UnflaggedSecurityBuffer::Extra(&mut []),
                BufferType::Padding => UnflaggedSecurityBuffer::Padding(&mut []),
                BufferType::StreamTrailer => UnflaggedSecurityBuffer::StreamTrailer(&mut []),
                BufferType::StreamHeader => UnflaggedSecurityBuffer::StreamHeader(&mut []),
                BufferType::Stream => UnflaggedSecurityBuffer::Stream(&mut []),
                _ => return Err(Error::new(ErrorKind::UnsupportedFunction, "")),
            },
            buffer_flags: security_buffer_type.buffer_flags,
        })
    }

    /// Creates a new [SecurityBufferRef] with the provided buffer data saving the old buffer type.
    ///
    /// *Attention*: the buffer type must not be [BufferType::Missing].
    pub fn with_data(self, data: &'data mut [u8]) -> Result<Self> {
        Ok(Self {
            buffer_type: match &self.buffer_type {
                UnflaggedSecurityBuffer::Data(_) => UnflaggedSecurityBuffer::Data(data),
                UnflaggedSecurityBuffer::Token(_) => UnflaggedSecurityBuffer::Token(data),
                UnflaggedSecurityBuffer::StreamHeader(_) => UnflaggedSecurityBuffer::StreamHeader(data),
                UnflaggedSecurityBuffer::StreamTrailer(_) => UnflaggedSecurityBuffer::StreamTrailer(data),
                UnflaggedSecurityBuffer::Stream(_) => UnflaggedSecurityBuffer::Stream(data),
                UnflaggedSecurityBuffer::Extra(_) => UnflaggedSecurityBuffer::Extra(data),
                UnflaggedSecurityBuffer::Padding(_) => UnflaggedSecurityBuffer::Padding(data),
                UnflaggedSecurityBuffer::Missing(_) => {
                    return Err(Error::new(
                        ErrorKind::InternalError,
                        "the missing buffer type does not hold any buffers inside",
                    ));
                }
                UnflaggedSecurityBuffer::Empty => UnflaggedSecurityBuffer::Empty,
            },
            buffer_flags: self.buffer_flags,
        })
    }

    /// Sets the buffer data.
    ///
    /// *Attention*: the buffer type must not be [BufferType::Missing].
    pub fn set_data(&mut self, buf: &'data mut [u8]) -> Result<()> {
        match &mut self.buffer_type {
            UnflaggedSecurityBuffer::Data(data) => *data = buf,
            UnflaggedSecurityBuffer::Token(data) => *data = buf,
            UnflaggedSecurityBuffer::StreamHeader(data) => *data = buf,
            UnflaggedSecurityBuffer::StreamTrailer(data) => *data = buf,
            UnflaggedSecurityBuffer::Stream(data) => *data = buf,
            UnflaggedSecurityBuffer::Extra(data) => *data = buf,
            UnflaggedSecurityBuffer::Padding(data) => *data = buf,
            UnflaggedSecurityBuffer::Missing(_) => {
                return Err(Error::new(
                    ErrorKind::InternalError,
                    "the missing buffer type does not hold any buffers inside",
                ));
            }
            UnflaggedSecurityBuffer::Empty => {}
        };
        Ok(())
    }

    /// Determines the [BufferType] of security buffer.
    pub fn buffer_type(&self) -> BufferType {
        match &self.buffer_type {
            UnflaggedSecurityBuffer::Data(_) => BufferType::Data,
            UnflaggedSecurityBuffer::Token(_) => BufferType::Token,
            UnflaggedSecurityBuffer::StreamHeader(_) => BufferType::StreamHeader,
            UnflaggedSecurityBuffer::StreamTrailer(_) => BufferType::StreamTrailer,
            UnflaggedSecurityBuffer::Stream(_) => BufferType::Stream,
            UnflaggedSecurityBuffer::Extra(_) => BufferType::Extra,
            UnflaggedSecurityBuffer::Padding(_) => BufferType::Padding,
            UnflaggedSecurityBuffer::Missing(_) => BufferType::Missing,
            UnflaggedSecurityBuffer::Empty => BufferType::Empty,
        }
    }

    pub fn buffer_flags(&self) -> SecurityBufferFlags {
        self.buffer_flags
    }

    pub fn owned_security_buffer_type(&self) -> SecurityBufferType {
        let buffer_type = match &self.buffer_type {
            UnflaggedSecurityBuffer::Data(_) => BufferType::Data,
            UnflaggedSecurityBuffer::Token(_) => BufferType::Token,
            UnflaggedSecurityBuffer::StreamHeader(_) => BufferType::StreamHeader,
            UnflaggedSecurityBuffer::StreamTrailer(_) => BufferType::StreamTrailer,
            UnflaggedSecurityBuffer::Stream(_) => BufferType::Stream,
            UnflaggedSecurityBuffer::Extra(_) => BufferType::Extra,
            UnflaggedSecurityBuffer::Padding(_) => BufferType::Padding,
            UnflaggedSecurityBuffer::Missing(_) => BufferType::Missing,
            UnflaggedSecurityBuffer::Empty => BufferType::Empty,
        };

        SecurityBufferType {
            buffer_type,
            buffer_flags: self.buffer_flags,
        }
    }

    /// Returns the immutable reference to the [SecurityBufferRef] with specified buffer type.
    ///
    /// If a slice contains more than one buffer with a specified buffer type, then the first one will be returned.
    pub fn find_buffer<'a>(
        buffers: &'a [SecurityBufferRef<'data>],
        buffer_type: BufferType,
    ) -> Result<&'a SecurityBufferRef<'data>> {
        buffers.iter().find(|b| b.buffer_type() == buffer_type).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidToken,
                format!("no buffer was provided with type {buffer_type:?}"),
            )
        })
    }

    /// Returns the vector of immutable references to the [SecurityBufferRef] with specified buffer type.
    pub fn buffers_of_type<'a>(
        buffers: &'a [SecurityBufferRef<'data>],
        buffer_type: BufferType,
    ) -> impl Iterator<Item = &'a SecurityBufferRef<'data>> {
        buffers.iter().filter(move |b| b.buffer_type() == buffer_type)
    }

    /// Returns the vector of immutable references to the [SecurityBufferRef] with specified buffer type.
    pub fn buffers_of_type_mut<'a>(
        buffers: &'a mut [SecurityBufferRef<'data>],
        buffer_type: BufferType,
    ) -> impl Iterator<Item = &'a mut SecurityBufferRef<'data>> {
        buffers.iter_mut().filter(move |b| b.buffer_type() == buffer_type)
    }

    /// Returns the vector of immutable references to the [SecurityBufferRef] with specified buffer type and flags.
    pub fn buffers_of_type_and_flags<'a>(
        buffers: &'a [SecurityBufferRef<'data>],
        buffer_type: BufferType,
        buffer_flags: SecurityBufferFlags,
    ) -> impl Iterator<Item = &'a SecurityBufferRef<'data>> {
        buffers
            .iter()
            .filter(move |b| b.buffer_type() == buffer_type && b.buffer_flags() == buffer_flags)
    }

    /// Returns the vector of immutable references to the [SecurityBufferRef] with specified buffer type and flags.
    pub fn buffers_of_type_and_flags_mut<'a>(
        buffers: &'a mut [SecurityBufferRef<'data>],
        buffer_type: BufferType,
        buffer_flags: SecurityBufferFlags,
    ) -> impl Iterator<Item = &'a mut SecurityBufferRef<'data>> {
        buffers
            .iter_mut()
            .filter(move |b| b.buffer_type() == buffer_type && b.buffer_flags() == buffer_flags)
    }

    /// Returns the mutable reference to the [SecurityBufferRef] with specified buffer type.
    ///
    /// If a slice contains more than one buffer with a specified buffer type, then the first one will be returned.
    pub fn find_buffer_mut<'a>(
        buffers: &'a mut [SecurityBufferRef<'data>],
        buffer_type: BufferType,
    ) -> Result<&'a mut SecurityBufferRef<'data>> {
        buffers
            .iter_mut()
            .find(|b| b.buffer_type() == buffer_type)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidToken,
                    format!("no buffer was provided with type {buffer_type:?}"),
                )
            })
    }

    /// Returns the immutable reference to the inner buffer data.
    pub fn buf_data<'a>(buffers: &'a [SecurityBufferRef<'a>], buffer_type: BufferType) -> Result<&'a [u8]> {
        Ok(SecurityBufferRef::find_buffer(buffers, buffer_type)?.data())
    }

    /// Returns the immutable reference to the inner data.
    ///
    /// Some buffer types can not hold the data, so the empty slice will be returned.
    pub fn data(&self) -> &[u8] {
        match &self.buffer_type {
            UnflaggedSecurityBuffer::Data(data) => data,
            UnflaggedSecurityBuffer::Token(data) => data,
            UnflaggedSecurityBuffer::StreamHeader(data) => data,
            UnflaggedSecurityBuffer::StreamTrailer(data) => data,
            UnflaggedSecurityBuffer::Stream(data) => data,
            UnflaggedSecurityBuffer::Extra(data) => data,
            UnflaggedSecurityBuffer::Padding(data) => data,
            UnflaggedSecurityBuffer::Missing(_) => &[],
            UnflaggedSecurityBuffer::Empty => &[],
        }
    }

    /// Calculates the buffer data length.
    pub fn buf_len(&self) -> usize {
        match &self.buffer_type {
            UnflaggedSecurityBuffer::Data(data) => data.len(),
            UnflaggedSecurityBuffer::Token(data) => data.len(),
            UnflaggedSecurityBuffer::StreamHeader(data) => data.len(),
            UnflaggedSecurityBuffer::StreamTrailer(data) => data.len(),
            UnflaggedSecurityBuffer::Stream(data) => data.len(),
            UnflaggedSecurityBuffer::Extra(data) => data.len(),
            UnflaggedSecurityBuffer::Padding(data) => data.len(),
            UnflaggedSecurityBuffer::Missing(needed_bytes_amount) => *needed_bytes_amount,
            UnflaggedSecurityBuffer::Empty => 0,
        }
    }

    /// Returns the mutable reference to the inner buffer data leaving the empty buffer on its place.
    pub fn take_buf_data_mut(
        buffers: &mut [SecurityBufferRef<'data>],
        buffer_type: BufferType,
    ) -> Result<&'data mut [u8]> {
        Ok(SecurityBufferRef::find_buffer_mut(buffers, buffer_type)?.take_data())
    }

    /// Returns the mutable reference to the inner data leaving the empty buffer on its place.
    ///
    /// Some buffer types can not hold the data, so the empty slice will be returned.
    pub fn take_data(&mut self) -> &'data mut [u8] {
        match &mut self.buffer_type {
            UnflaggedSecurityBuffer::Data(data) => take(data),
            UnflaggedSecurityBuffer::Token(data) => take(data),
            UnflaggedSecurityBuffer::StreamHeader(data) => take(data),
            UnflaggedSecurityBuffer::StreamTrailer(data) => take(data),
            UnflaggedSecurityBuffer::Stream(data) => take(data),
            UnflaggedSecurityBuffer::Extra(data) => take(data),
            UnflaggedSecurityBuffer::Padding(data) => take(data),
            UnflaggedSecurityBuffer::Missing(_) => &mut [],
            UnflaggedSecurityBuffer::Empty => &mut [],
        }
    }

    /// Writes the provided data into the inner buffer.
    ///
    /// Returns error if the inner buffer is not big enough. If the inner buffer is larger than
    /// provided data, then it'll be shrunk to the size of the data.
    pub fn write_data(&mut self, data: &[u8]) -> Result<()> {
        let data_len = data.len();

        if self.buf_len() < data_len {
            return Err(Error::new(
                ErrorKind::BufferTooSmall,
                "provided data can not fit in the destination buffer",
            ));
        }

        let mut buf = self.take_data();
        buf = &mut buf[0..data_len];
        buf.copy_from_slice(data);

        self.set_data(buf)
    }
}

impl fmt::Debug for SecurityBufferRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecurityBufferRef {{ ")?;
        f.write_fmt(format_args!("{:?},", self.buffer_flags))?;
        match &self.buffer_type {
            UnflaggedSecurityBuffer::Data(data) => write_buffer(data, "Data", f)?,
            UnflaggedSecurityBuffer::Token(data) => write_buffer(data, "Token", f)?,
            UnflaggedSecurityBuffer::StreamHeader(data) => write_buffer(data, "StreamHeader", f)?,
            UnflaggedSecurityBuffer::StreamTrailer(data) => write_buffer(data, "StreamTrailer", f)?,
            UnflaggedSecurityBuffer::Stream(data) => write_buffer(data, "Stream", f)?,
            UnflaggedSecurityBuffer::Extra(data) => write_buffer(data, "Extra", f)?,
            UnflaggedSecurityBuffer::Padding(data) => write_buffer(data, "Padding", f)?,
            UnflaggedSecurityBuffer::Missing(needed_bytes_amount) => write!(f, "Missing({})", *needed_bytes_amount)?,
            UnflaggedSecurityBuffer::Empty => f.write_str("Empty")?,
        };
        write!(f, " }}")
    }
}

fn write_buffer(buf: &[u8], buf_name: &str, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{buf_name}: ")?;
    f.write_str("0x")?;
    buf.iter().try_for_each(|byte| write!(f, "{byte:02X}"))
}

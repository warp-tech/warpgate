//! Zstd compression for the QOIZ bitmap codec.

use crate::{ServerError, ServerErrorExt as _, ServerResult};

/// Streaming compressor for QOIZ updates.
///
/// All QOIZ updates of a session form a single zstd stream.
/// The stream is flushed after each update, so the client can decode it right away.
/// Long distance matching lets an update reference content from earlier ones.
#[cfg_attr(feature = "__test", visibility::make(pub))]
pub(crate) struct Compressor {
    zctxt: zstd_safe::CCtx<'static>,
}

impl Compressor {
    #[cfg_attr(feature = "__test", visibility::make(pub))]
    pub(crate) fn new() -> ServerResult<Self> {
        let mut zctxt = zstd_safe::CCtx::default();

        zctxt
            .set_parameter(zstd_safe::CParameter::CompressionLevel(3))
            .map_err(|code| {
                ServerError::reason(
                    "qoiz init",
                    format!(
                        "failed to set zstd compression level: {}",
                        zstd_safe::get_error_name(code)
                    ),
                )
            })?;
        zctxt
            .set_parameter(zstd_safe::CParameter::EnableLongDistanceMatching(true))
            .map_err(|code| {
                ServerError::reason(
                    "qoiz init",
                    format!(
                        "failed to set zstd enable long distance matching: {}",
                        zstd_safe::get_error_name(code)
                    ),
                )
            })?;

        Ok(Self { zctxt })
    }

    /// Compresses a single QOIZ update and returns the bytes to send for it.
    #[cfg_attr(feature = "__test", visibility::make(pub))]
    pub(crate) fn compress(&mut self, input: &[u8]) -> ServerResult<Vec<u8>> {
        let mut inb = zstd_safe::InBuffer::around(input);
        let mut data = vec![0; input.len()];
        let mut outb;
        let mut pos = 0;

        loop {
            outb = zstd_safe::OutBuffer::around_pos(data.as_mut_slice(), pos);
            let res = self
                .zctxt
                .compress_stream2(
                    &mut outb,
                    &mut inb,
                    zstd_safe::zstd_sys::ZSTD_EndDirective::ZSTD_e_flush,
                )
                .map_err(|code| {
                    ServerError::reason(
                        "qoiz compress",
                        format!("failed to Zstd compress: {}", zstd_safe::get_error_name(code)),
                    )
                })?;
            if res == 0 {
                break;
            }
            pos = outb.pos();
            data.resize(data.len() + res, 0);
        }

        let len = outb.pos();
        data.truncate(len);

        Ok(data)
    }
}

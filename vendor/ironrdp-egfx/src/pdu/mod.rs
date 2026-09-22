//! Display Pipeline Virtual Channel Extension PDUs  [MS-RDPEGFX][1] implementation.
//!
//! This module provides PDU types for the Graphics Pipeline Extension, including
//! H.264/AVC420 video streaming support.
//!
//! # Server-Side Utilities
//!
//! For server implementations, the following utilities are provided:
//!
//! - [`Avc420Region`] - Region metadata for H.264 frames
//! - [`annex_b_to_avc`] - Convert H.264 Annex B to AVC format
//! - [`align_to_16`] - Align dimensions to H.264 macroblock boundaries
//! - [`encode_avc420_bitmap_stream`] - Create AVC420 bitmap streams
//!
//! [1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/da5c75f9-cd99-450c-98c4-014a496942b0

mod common;
pub use common::*;

mod cmd;
pub use cmd::*;

mod avc;
pub use avc::*;

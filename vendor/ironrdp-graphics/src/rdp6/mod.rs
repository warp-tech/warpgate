//! This module provides the RDP6 bitmap decoder implementation

pub(crate) mod bitmap_stream;
pub(crate) mod rle;

pub use bitmap_stream::*;
pub use rle::{RleDecodeError, RleEncodeError};

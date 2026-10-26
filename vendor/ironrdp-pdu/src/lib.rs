#![cfg_attr(doc, doc = include_str!("../README.md"))]
#![doc(html_logo_url = "https://cdnweb.devolutions.net/images/projects/devolutions/logos/devolutions-icon-shadow.svg")]
#![allow(clippy::arithmetic_side_effects)] // FIXME: remove

use core::fmt;

// TODO(#583): uncomment once re-exports are removed.
// use ironrdp_core::{unexpected_message_type_err, DecodeResult, EncodeResult, ReadCursor};
use ironrdp_error::Source;

mod macros;

pub mod codecs;
pub mod gcc;
pub mod geometry;
pub mod input;
pub mod mcs;
pub mod nego;
pub mod pcb;
pub mod rdp;
pub mod tpdu;
pub mod tpkt;
pub mod utf16;
pub mod utils;
pub mod x224;

pub(crate) mod basic_output;
pub(crate) mod ber;
pub(crate) mod crypto;
pub(crate) mod per;

pub use crate::basic_output::{bitmap, fast_path, pointer, slow_path, surface_commands};

pub type PduResult<T> = Result<T, PduError>;

pub type PduError = ironrdp_error::Error<PduErrorKind>;

#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum PduErrorKind {
    Encode,
    Decode,
    Other { description: &'static str },
}

pub trait PduErrorExt {
    fn decode<E: Source>(context: &'static str, source: E) -> Self;

    fn encode<E: Source>(context: &'static str, source: E) -> Self;
}

impl PduErrorExt for PduError {
    #[track_caller]
    fn decode<E: Source>(context: &'static str, source: E) -> Self {
        Self::new(context, PduErrorKind::Decode).with_source(source)
    }

    #[track_caller]
    fn encode<E: Source>(context: &'static str, source: E) -> Self {
        Self::new(context, PduErrorKind::Encode).with_source(source)
    }
}

impl core::error::Error for PduErrorKind {}

impl fmt::Display for PduErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encode => {
                write!(f, "encode error")
            }
            Self::Decode => {
                write!(f, "decode error")
            }
            Self::Other { description } => {
                write!(f, "other ({description})")
            }
        }
    }
}

/// An RDP PDU.
pub trait Pdu {
    /// Name associated to this PDU.
    const NAME: &'static str;
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum Action {
    FastPath = 0x00,
    X224 = 0x03,
}

impl Action {
    pub fn from_fp_output_header(fp_output_header: u8) -> Result<Self, u8> {
        match fp_output_header & 0b11 {
            0x00 => Ok(Self::FastPath),
            0x03 => Ok(Self::X224),
            unknown_action_bits => Err(unknown_action_bits),
        }
    }

    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PduInfo {
    pub action: Action,
    pub length: usize,
}

/// Finds next RDP PDU size by reading the next few bytes.
pub fn find_size(bytes: &[u8]) -> DecodeResult<Option<PduInfo>> {
    macro_rules! ensure_enough {
        ($bytes:expr, $len:expr) => {
            if $bytes.len() < $len {
                return Ok(None);
            }
        };
    }

    ensure_enough!(bytes, 1);
    let fp_output_header = bytes[0];

    let action = Action::from_fp_output_header(fp_output_header)
        .map_err(|unknown_action| unexpected_message_type_err("fpOutputHeader", unknown_action))?;

    match action {
        Action::X224 => {
            ensure_enough!(bytes, tpkt::TpktHeader::SIZE);
            let tpkt = tpkt::TpktHeader::read(&mut ReadCursor::new(bytes))?;

            Ok(Some(PduInfo {
                action,
                length: tpkt.packet_length(),
            }))
        }
        Action::FastPath => {
            ensure_enough!(bytes, 2);
            let a = bytes[1];

            let fast_path_length = if a & 0x80 != 0 {
                ensure_enough!(bytes, 3);
                let b = bytes[2];

                ((u16::from(a) & !0x80) << 8) + u16::from(b)
            } else {
                u16::from(a)
            };

            Ok(Some(PduInfo {
                action,
                length: usize::from(fast_path_length),
            }))
        }
    }
}

pub trait PduHint: Send + Sync + fmt::Debug + 'static {
    /// Finds next PDU size by reading the next few bytes.
    ///
    /// Returns `Some((hint_matching, size))` if the size is known.
    /// Returns `None` if the size cannot be determined yet.
    fn find_size(&self, bytes: &[u8]) -> DecodeResult<Option<(bool, usize)>>;
}

// Matches both X224 and FastPath pdus
#[derive(Clone, Copy, Debug)]
pub struct RdpHint;

pub const RDP_HINT: RdpHint = RdpHint;

impl PduHint for RdpHint {
    fn find_size(&self, bytes: &[u8]) -> DecodeResult<Option<(bool, usize)>> {
        find_size(bytes).map(|opt| opt.map(|info| (true, info.length)))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct X224Hint;

pub const X224_HINT: X224Hint = X224Hint;

impl PduHint for X224Hint {
    fn find_size(&self, bytes: &[u8]) -> DecodeResult<Option<(bool, usize)>> {
        match find_size(bytes)? {
            Some(pdu_info) => {
                let res = (pdu_info.action == Action::X224, pdu_info.length);
                Ok(Some(res))
            }
            None => Ok(None),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FastPathHint;

pub const FAST_PATH_HINT: FastPathHint = FastPathHint;

impl PduHint for FastPathHint {
    fn find_size(&self, bytes: &[u8]) -> DecodeResult<Option<(bool, usize)>> {
        match find_size(bytes)? {
            Some(pdu_info) => {
                let res = (pdu_info.action == Action::FastPath, pdu_info.length);
                Ok(Some(res))
            }
            None => Ok(None),
        }
    }
}

// Private! Used by the macros.
#[doc(hidden)]
pub use ironrdp_core;

// -- Temporary re-exports to ease teleport’s migration to the newer versions -- //
// TODO(#583): remove once Teleport migrated to the newer item paths.
// NOTE: #[deprecated] has no effect on re-exports, so this is mostly for documenting the code at this point.
#[doc(hidden)]
#[deprecated(since = "0.1.0", note = "use ironrdp_core::{ReadCursor, WriteCursor}")]
pub mod cursor {
    pub use ironrdp_core::{ReadCursor, WriteCursor};
}

#[doc(hidden)]
#[deprecated(since = "0.1.0", note = "use ironrdp_core::WriteBuf")]
pub mod write_buf {
    pub use ironrdp_core::WriteBuf;
}

#[doc(hidden)]
#[deprecated(since = "0.1.0", note = "use ironrdp_core")]
pub use ironrdp_core::*;

#[doc(hidden)]
#[deprecated(since = "0.1.0")]
#[macro_export]
macro_rules! custom_err {
    ( $description:expr, $source:expr $(,)? ) => {{
        $crate::PduError::new(
            $description,
            $crate::PduErrorKind::Other {
                description: $description,
            },
        )
        .with_source($source)
    }};
    ( $source:expr $(,)? ) => {{ $crate::custom_err!($crate::function!(), $source) }};
}

#[doc(hidden)]
#[deprecated(since = "0.1.0", note = "use ironrdp_core::other_err")]
pub use crate::pdu_other_err as other_err;

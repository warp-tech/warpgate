//! Error type for the TNS protocol layer.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A buffer ended before the expected number of bytes.
    Truncated { need: usize, got: usize },
    /// A field held a value the parser cannot accept.
    Invalid(&'static str),
    /// A TNS REFUSE packet was received (the connection was rejected).
    Refused(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { need, got } => {
                write!(f, "truncated TNS data: need {need} bytes, got {got}")
            }
            Self::Invalid(what) => write!(f, "invalid TNS data: {what}"),
            Self::Refused(msg) => write!(f, "connection refused by server: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

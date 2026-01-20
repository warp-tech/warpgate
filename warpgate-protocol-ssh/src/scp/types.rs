//! SCP protocol types and constants.

use serde::{Deserialize, Serialize};

/// SCP command parsed from exec request
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScpCommand {
    /// scp -t (to/upload)
    Upload { path: String, recursive: bool },
    /// scp -f (from/download)
    Download { path: String, recursive: bool },
    /// Not an SCP command
    NotScp,
}

/// SCP protocol message types
#[derive(Debug, Clone)]
pub enum ScpMessage {
    /// File header: C<mode> <size> <filename>
    FileHeader {
        mode: u32,
        size: u64,
        filename: String,
    },
    /// Directory header: D<mode> 0 <dirname>
    DirHeader { mode: u32, dirname: String },
    /// End of directory: E
    EndDir,
    /// OK response: \0
    Ok,
    /// Warning: \x01<message>
    Warning(String),
    /// Error: \x02<message>
    Error(String),
    /// Data chunk
    Data(Vec<u8>),
}

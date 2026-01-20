//! SFTP Protocol Parser
//!
//! Extensible parser for SSH File Transfer Protocol (SFTP).
//! Currently parses file operation messages for access control and logging.
//! Designed for future expansion (DLP, content inspection, etc.).

mod parser;
mod response;
mod tracker;
mod types;

pub use parser::SftpParser;
pub use response::build_permission_denied_response;
pub use tracker::{FileTransferTracker, TransferComplete};
pub use types::*;

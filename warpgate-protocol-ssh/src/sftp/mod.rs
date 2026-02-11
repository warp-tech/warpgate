//! SFTP Protocol Parser
//!
//! Extensible parser for SSH File Transfer Protocol (SFTP).
//! Currently parses file operation messages for access control and logging.
//! Designed for future expansion (DLP, content inspection, etc.).

mod codec;
mod tracker;
mod types;

pub use codec::{
    build_close_packet, build_denial_response, build_remove_packet, packet_to_operation,
    packet_to_response, parse_all_packets, try_parse_packet,
};
pub use tracker::{FileTransferTracker, TransferComplete};
pub use types::{SftpFileOperation, SftpResponse, TransferDirection, TransferStatus};

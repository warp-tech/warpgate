//! SFTP protocol types and constants.

use std::fmt::Display;

use serde::{Deserialize, Serialize};

/// Parsed SFTP file operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SftpFileOperation {
    Open {
        request_id: u32,
        path: String,
        flags: u32,
        is_upload: bool,
        is_download: bool,
    },
    Close {
        request_id: u32,
        handle: Vec<u8>,
    },
    Read {
        request_id: u32,
        handle: Vec<u8>,
        offset: u64,
        length: u32,
    },
    Write {
        request_id: u32,
        handle: Vec<u8>,
        offset: u64,
        data_len: usize,
        data: Vec<u8>,
    },
    Remove {
        request_id: u32,
        path: String,
    },
    Rename {
        request_id: u32,
        old_path: String,
        new_path: String,
    },
    Mkdir {
        request_id: u32,
        path: String,
    },
    Rmdir {
        request_id: u32,
        path: String,
    },
    Setstat {
        request_id: u32,
        path: String,
    },
    Symlink {
        request_id: u32,
        link_path: String,
        target_path: String,
    },
    /// SSH_FXP_EXTENDED - vendor-specific operation
    Extended {
        request_id: u32,
        request_name: String,
    },
}

/// File transfer direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferDirection {
    Upload,
    Download,
}

impl Display for TransferDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Upload => write!(f, "upload"),
            Self::Download => write!(f, "download"),
        }
    }
}

/// File transfer status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferStatus {
    Started,
    InProgress,
    Completed,
    Failed,
    Denied,
}

impl Display for TransferStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Started => write!(f, "started"),
            Self::InProgress => write!(f, "in_progress"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Denied => write!(f, "denied"),
        }
    }
}

/// Parsed SFTP response (server -> client)
#[derive(Debug, Clone)]
pub enum SftpResponse {
    /// SSH_FXP_HANDLE - response to OPEN with the file handle
    Handle { request_id: u32, handle: Vec<u8> },
    /// SSH_FXP_DATA - response to READ with file data
    Data { request_id: u32, data: Vec<u8> },
    /// SSH_FXP_STATUS - response indicating success/failure
    Status { request_id: u32, code: u32 },
}

//! SFTP protocol types and constants.

use serde::{Deserialize, Serialize};

/// SFTP packet types (SSH_FXP_*)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(dead_code)]
pub enum SftpPacketType {
    Init = 1,
    Version = 2,
    Open = 3,
    Close = 4,
    Read = 5,
    Write = 6,
    Lstat = 7,
    Fstat = 8,
    Setstat = 9,
    Fsetstat = 10,
    Opendir = 11,
    Readdir = 12,
    Remove = 13,
    Mkdir = 14,
    Rmdir = 15,
    Realpath = 16,
    Stat = 17,
    Rename = 18,
    Readlink = 19,
    Symlink = 20,
    Status = 101,
    Handle = 102,
    Data = 103,
    Name = 104,
    Attrs = 105,
    Extended = 200,
    ExtendedReply = 201,
}

/// SFTP open flags (SSH_FXF_*)
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct SftpOpenFlags {
    pub read: bool,
    pub write: bool,
    pub append: bool,
    pub create: bool,
    pub truncate: bool,
    pub exclusive: bool,
}

impl SftpOpenFlags {
    /// Parse SFTP open flags from the raw flag value
    pub fn from_raw(flags: u32) -> Self {
        Self {
            read: (flags & 0x01) != 0,      // SSH_FXF_READ
            write: (flags & 0x02) != 0,     // SSH_FXF_WRITE
            append: (flags & 0x04) != 0,    // SSH_FXF_APPEND
            create: (flags & 0x08) != 0,    // SSH_FXF_CREAT
            truncate: (flags & 0x10) != 0,  // SSH_FXF_TRUNC
            exclusive: (flags & 0x20) != 0, // SSH_FXF_EXCL
        }
    }
}

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
}

/// File transfer direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferDirection {
    Upload,
    Download,
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

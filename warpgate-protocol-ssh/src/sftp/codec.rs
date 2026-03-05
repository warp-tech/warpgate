use bytes::{Buf, Bytes};
use russh_sftp::protocol::{OpenFlags, Packet, StatusCode};

use super::types::{SftpFileOperation, SftpResponse};

pub fn try_parse_packet(data: &[u8]) -> Option<Packet> {
    if data.len() < 5 {
        return None;
    }

    let mut bytes = Bytes::copy_from_slice(data);
    bytes.advance(4); // Skip SFTP length field (4 bytes)
    Packet::try_from(&mut bytes).ok()
}

/// Parse all complete SFTP packets from a reassembly buffer.
/// Consumes parsed bytes from `buf`, leaving any incomplete trailing data.
/// Returns a Vec of successfully parsed packets.
pub fn parse_all_packets(buf: &mut Vec<u8>) -> Vec<Packet> {
    let mut packets = Vec::new();
    loop {
        if buf.len() < 4 {
            break;
        }
        // Read the 4-byte SFTP packet length (big-endian)
        let pkt_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let total_len = 4 + pkt_len; // length field + payload
        if buf.len() < total_len {
            break; // Incomplete packet, wait for more data
        }
        // Peek at packet type byte (first byte after the 4-byte length)
        let pkt_type = if pkt_len > 0 { buf[4] } else { 0 };
        // Try to parse this single packet
        let mut bytes = Bytes::copy_from_slice(&buf[4..total_len]);
        match Packet::try_from(&mut bytes) {
            Ok(packet) => {
                packets.push(packet);
            }
            Err(e) => {
                tracing::debug!(
                    packet_type = pkt_type,
                    packet_len = pkt_len,
                    error = %e,
                    "SFTP packet parse failed, skipping"
                );
            }
        }
        // Consume the bytes regardless of parse success
        buf.drain(..total_len);
    }
    packets
}

pub fn packet_to_operation(packet: &Packet) -> Option<SftpFileOperation> {
    match packet {
        Packet::Open(open) => {
            let flags = open.pflags.bits();
            let is_download = open.pflags.contains(OpenFlags::READ);
            let is_upload = open.pflags.contains(OpenFlags::WRITE);

            Some(SftpFileOperation::Open {
                request_id: open.id,
                path: open.filename.clone(),
                flags,
                is_upload,
                is_download,
            })
        }
        Packet::Close(close) => Some(SftpFileOperation::Close {
            request_id: close.id,
            handle: close.handle.as_bytes().to_vec(),
        }),
        Packet::Read(read) => Some(SftpFileOperation::Read {
            request_id: read.id,
            handle: read.handle.as_bytes().to_vec(),
            offset: read.offset,
            length: read.len,
        }),
        Packet::Write(write) => Some(SftpFileOperation::Write {
            request_id: write.id,
            handle: write.handle.as_bytes().to_vec(),
            offset: write.offset,
            data_len: write.data.len(),
            data: write.data.clone(),
        }),
        Packet::Remove(remove) => Some(SftpFileOperation::Remove {
            request_id: remove.id,
            path: remove.filename.clone(),
        }),
        Packet::Rename(rename) => Some(SftpFileOperation::Rename {
            request_id: rename.id,
            old_path: rename.oldpath.clone(),
            new_path: rename.newpath.clone(),
        }),
        Packet::MkDir(mkdir) => Some(SftpFileOperation::Mkdir {
            request_id: mkdir.id,
            path: mkdir.path.clone(),
        }),
        Packet::RmDir(rmdir) => Some(SftpFileOperation::Rmdir {
            request_id: rmdir.id,
            path: rmdir.path.clone(),
        }),
        Packet::SetStat(setstat) => Some(SftpFileOperation::Setstat {
            request_id: setstat.id,
            path: setstat.path.clone(),
        }),
        Packet::Symlink(symlink) => Some(SftpFileOperation::Symlink {
            request_id: symlink.id,
            link_path: symlink.linkpath.clone(),
            target_path: symlink.targetpath.clone(),
        }),
        Packet::Extended(ext) => Some(SftpFileOperation::Extended {
            request_id: ext.id,
            request_name: ext.request.clone(),
        }),
        // Init, Version, Lstat, Stat, Fstat, Opendir, Readdir, Realpath, Readlink — read-only metadata, safe to forward
        _ => None,
    }
}

pub fn packet_to_response(packet: &Packet) -> Option<SftpResponse> {
    match packet {
        Packet::Handle(handle) => Some(SftpResponse::Handle {
            request_id: handle.id,
            handle: handle.handle.as_bytes().to_vec(),
        }),
        Packet::Data(data) => Some(SftpResponse::Data {
            request_id: data.id,
            data: data.data.clone(),
        }),
        Packet::Status(status) => Some(SftpResponse::Status {
            request_id: status.id,
            code: status_code_to_u32(status.status_code),
        }),
        _ => None,
    }
}

pub fn build_denial_response(request_id: u32, message: &str) -> Vec<u8> {
    let packet = Packet::status(request_id, StatusCode::PermissionDenied, message, "en");
    match Bytes::try_from(packet) {
        Ok(bytes) => bytes.to_vec(),
        Err(_) => Vec::new(),
    }
}

/// Build an SFTP Close packet (to close a file handle on the server).
pub fn build_close_packet(request_id: u32, handle: &str) -> Vec<u8> {
    let packet = Packet::Close(russh_sftp::protocol::Close {
        id: request_id,
        handle: handle.to_string(),
    });
    match Bytes::try_from(packet) {
        Ok(bytes) => bytes.to_vec(),
        Err(_) => Vec::new(),
    }
}

/// Build an SFTP Remove packet (to delete a file on the server).
pub fn build_remove_packet(request_id: u32, path: &str) -> Vec<u8> {
    let packet = Packet::Remove(russh_sftp::protocol::Remove {
        id: request_id,
        filename: path.to_string(),
    });
    match Bytes::try_from(packet) {
        Ok(bytes) => bytes.to_vec(),
        Err(_) => Vec::new(),
    }
}

fn status_code_to_u32(status: StatusCode) -> u32 {
    match status {
        StatusCode::Ok => 0,
        StatusCode::Eof => 1,
        StatusCode::NoSuchFile => 2,
        StatusCode::PermissionDenied => 3,
        StatusCode::Failure => 4,
        StatusCode::BadMessage => 5,
        StatusCode::NoConnection => 6,
        StatusCode::ConnectionLost => 7,
        StatusCode::OpUnsupported => 8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh_sftp::protocol::{Extended, Open, OpenFlags};

    #[test]
    fn test_packet_to_operation_open() {
        let packet = Packet::Open(Open {
            id: 1,
            filename: "/tmp/test.txt".into(),
            pflags: OpenFlags::WRITE,
            attrs: Default::default(),
        });

        let operation = packet_to_operation(&packet);
        assert!(operation.is_some());
        match operation.unwrap() {
            SftpFileOperation::Open {
                request_id,
                path,
                is_upload,
                is_download,
                ..
            } => {
                assert_eq!(request_id, 1);
                assert_eq!(path, "/tmp/test.txt");
                assert!(is_upload);
                assert!(!is_download);
            }
            _ => panic!("Wrong operation type"),
        }
    }

    #[test]
    fn test_packet_to_operation_extended() {
        let packet = Packet::Extended(Extended {
            id: 42,
            request: "posix-rename@openssh.com".to_string(),
            data: vec![],
        });

        let operation = packet_to_operation(&packet);
        assert!(operation.is_some());
        match operation.unwrap() {
            SftpFileOperation::Extended {
                request_id,
                request_name,
            } => {
                assert_eq!(request_id, 42);
                assert_eq!(request_name, "posix-rename@openssh.com");
            }
            _ => panic!("Wrong operation type"),
        }
    }

    #[test]
    fn test_packet_to_operation_extended_statvfs() {
        let packet = Packet::Extended(Extended {
            id: 1,
            request: "statvfs@openssh.com".to_string(),
            data: vec![],
        });

        let operation = packet_to_operation(&packet);
        assert!(operation.is_some());
        match operation.unwrap() {
            SftpFileOperation::Extended {
                request_id,
                request_name,
            } => {
                assert_eq!(request_id, 1);
                assert_eq!(request_name, "statvfs@openssh.com");
            }
            _ => panic!("Wrong operation type"),
        }
    }
}

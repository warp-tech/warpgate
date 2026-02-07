use bytes::{Buf, Bytes};
use russh_sftp::protocol::{OpenFlags, Packet, StatusCode};

use super::types::{SftpFileOperation, SftpResponse};

pub fn try_parse_packet(data: &[u8]) -> Option<Packet> {
    if data.len() < 5 {
        return None;
    }

    let mut bytes = Bytes::copy_from_slice(data);
    bytes.advance(4); // Skip SSH length field (4 bytes)
    Packet::try_from(&mut bytes).ok()
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
    use russh_sftp::protocol::{Open, OpenFlags};

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
}

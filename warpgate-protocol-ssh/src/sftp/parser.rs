//! SFTP Protocol Parser
//!
//! Parses SFTP messages from raw bytes.

use bytes::{Buf, Bytes};

use super::types::{SftpFileOperation, SftpResponse};

/// SFTP Protocol Parser
///
/// Parses SFTP messages from raw bytes.
/// Thread-safe, stateless parser (state tracked separately in FileTransferTracker).
#[derive(Default)]
pub struct SftpParser;

impl SftpParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse an SFTP packet from raw bytes
    pub fn parse_packet(&self, data: &[u8]) -> Option<SftpFileOperation> {
        if data.len() < 5 {
            return None;
        }

        let mut buf = Bytes::copy_from_slice(data);
        let length = buf.get_u32() as usize;

        if buf.remaining() < length || length < 1 {
            return None;
        }

        let packet_type = buf.get_u8();

        match packet_type {
            3 => self.parse_open(&mut buf),     // SSH_FXP_OPEN
            4 => self.parse_close(&mut buf),    // SSH_FXP_CLOSE
            5 => self.parse_read(&mut buf),     // SSH_FXP_READ
            6 => self.parse_write(&mut buf),    // SSH_FXP_WRITE
            9 => self.parse_setstat(&mut buf),  // SSH_FXP_SETSTAT
            13 => self.parse_remove(&mut buf),  // SSH_FXP_REMOVE
            14 => self.parse_mkdir(&mut buf),   // SSH_FXP_MKDIR
            15 => self.parse_rmdir(&mut buf),   // SSH_FXP_RMDIR
            18 => self.parse_rename(&mut buf),  // SSH_FXP_RENAME
            20 => self.parse_symlink(&mut buf), // SSH_FXP_SYMLINK
            _ => None,
        }
    }

    fn parse_open(&self, buf: &mut Bytes) -> Option<SftpFileOperation> {
        if buf.remaining() < 4 {
            return None;
        }
        let request_id = buf.get_u32();
        let path = self.read_string(buf)?;

        if buf.remaining() < 4 {
            return None;
        }
        let flags = buf.get_u32();

        // Determine direction from flags
        // SSH_FXF_READ = 0x01, SSH_FXF_WRITE = 0x02
        let is_download = (flags & 0x01) != 0;
        let is_upload = (flags & 0x02) != 0;

        Some(SftpFileOperation::Open {
            request_id,
            path,
            flags,
            is_upload,
            is_download,
        })
    }

    fn parse_close(&self, buf: &mut Bytes) -> Option<SftpFileOperation> {
        if buf.remaining() < 4 {
            return None;
        }
        let request_id = buf.get_u32();
        let handle = self.read_bytes(buf)?;
        Some(SftpFileOperation::Close { request_id, handle })
    }

    fn parse_read(&self, buf: &mut Bytes) -> Option<SftpFileOperation> {
        if buf.remaining() < 4 {
            return None;
        }
        let request_id = buf.get_u32();
        let handle = self.read_bytes(buf)?;

        if buf.remaining() < 12 {
            return None;
        }
        let offset = buf.get_u64();
        let length = buf.get_u32();

        Some(SftpFileOperation::Read {
            request_id,
            handle,
            offset,
            length,
        })
    }

    fn parse_write(&self, buf: &mut Bytes) -> Option<SftpFileOperation> {
        if buf.remaining() < 4 {
            return None;
        }
        let request_id = buf.get_u32();
        let handle = self.read_bytes(buf)?;

        if buf.remaining() < 12 {
            return None;
        }
        let offset = buf.get_u64();
        let data_len = buf.get_u32() as usize;

        Some(SftpFileOperation::Write {
            request_id,
            handle,
            offset,
            data_len,
        })
    }

    fn parse_remove(&self, buf: &mut Bytes) -> Option<SftpFileOperation> {
        if buf.remaining() < 4 {
            return None;
        }
        let request_id = buf.get_u32();
        let path = self.read_string(buf)?;
        Some(SftpFileOperation::Remove { request_id, path })
    }

    fn parse_rename(&self, buf: &mut Bytes) -> Option<SftpFileOperation> {
        if buf.remaining() < 4 {
            return None;
        }
        let request_id = buf.get_u32();
        let old_path = self.read_string(buf)?;
        let new_path = self.read_string(buf)?;
        Some(SftpFileOperation::Rename {
            request_id,
            old_path,
            new_path,
        })
    }

    fn parse_mkdir(&self, buf: &mut Bytes) -> Option<SftpFileOperation> {
        if buf.remaining() < 4 {
            return None;
        }
        let request_id = buf.get_u32();
        let path = self.read_string(buf)?;
        // Note: attrs follow but we don't need them for access control
        Some(SftpFileOperation::Mkdir { request_id, path })
    }

    fn parse_rmdir(&self, buf: &mut Bytes) -> Option<SftpFileOperation> {
        if buf.remaining() < 4 {
            return None;
        }
        let request_id = buf.get_u32();
        let path = self.read_string(buf)?;
        Some(SftpFileOperation::Rmdir { request_id, path })
    }

    fn parse_setstat(&self, buf: &mut Bytes) -> Option<SftpFileOperation> {
        if buf.remaining() < 4 {
            return None;
        }
        let request_id = buf.get_u32();
        let path = self.read_string(buf)?;
        // Note: attrs follow but we don't need them for access control
        Some(SftpFileOperation::Setstat { request_id, path })
    }

    fn parse_symlink(&self, buf: &mut Bytes) -> Option<SftpFileOperation> {
        if buf.remaining() < 4 {
            return None;
        }
        let request_id = buf.get_u32();
        let link_path = self.read_string(buf)?;
        let target_path = self.read_string(buf)?;
        Some(SftpFileOperation::Symlink {
            request_id,
            link_path,
            target_path,
        })
    }

    fn read_string(&self, buf: &mut Bytes) -> Option<String> {
        if buf.remaining() < 4 {
            return None;
        }
        let len = buf.get_u32() as usize;
        if buf.remaining() < len {
            return None;
        }
        let bytes = buf.copy_to_bytes(len);
        String::from_utf8(bytes.to_vec()).ok()
    }

    fn read_bytes(&self, buf: &mut Bytes) -> Option<Vec<u8>> {
        if buf.remaining() < 4 {
            return None;
        }
        let len = buf.get_u32() as usize;
        if buf.remaining() < len {
            return None;
        }
        Some(buf.copy_to_bytes(len).to_vec())
    }

    /// Parse an SFTP response packet (server -> client)
    pub fn parse_response(&self, data: &[u8]) -> Option<SftpResponse> {
        if data.len() < 5 {
            return None;
        }

        let mut buf = Bytes::copy_from_slice(data);
        let length = buf.get_u32() as usize;

        if buf.remaining() < length || length < 1 {
            return None;
        }

        let packet_type = buf.get_u8();

        match packet_type {
            101 => self.parse_status_response(&mut buf), // SSH_FXP_STATUS
            102 => self.parse_handle_response(&mut buf), // SSH_FXP_HANDLE
            103 => self.parse_data_response(&mut buf, length - 1), // SSH_FXP_DATA
            _ => None,
        }
    }

    fn parse_handle_response(&self, buf: &mut Bytes) -> Option<SftpResponse> {
        if buf.remaining() < 4 {
            return None;
        }
        let request_id = buf.get_u32();
        let handle = self.read_bytes(buf)?;
        Some(SftpResponse::Handle { request_id, handle })
    }

    fn parse_data_response(
        &self,
        buf: &mut Bytes,
        remaining_length: usize,
    ) -> Option<SftpResponse> {
        if buf.remaining() < 4 {
            return None;
        }
        let request_id = buf.get_u32();

        // Read the data length
        if buf.remaining() < 4 {
            return None;
        }
        let data_len = buf.get_u32() as usize;

        // Sanity check: data_len should not exceed remaining packet length
        if data_len > remaining_length.saturating_sub(8) {
            return None;
        }

        if buf.remaining() < data_len {
            return None;
        }
        let data = buf.copy_to_bytes(data_len).to_vec();

        Some(SftpResponse::Data { request_id, data })
    }

    fn parse_status_response(&self, buf: &mut Bytes) -> Option<SftpResponse> {
        if buf.remaining() < 8 {
            return None;
        }
        let request_id = buf.get_u32();
        let code = buf.get_u32();
        Some(SftpResponse::Status { request_id, code })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_sftp_packet(packet_type: u8, payload: &[u8]) -> Vec<u8> {
        let length = payload.len() as u32 + 1; // +1 for packet type
        let mut packet = Vec::new();
        packet.extend_from_slice(&length.to_be_bytes());
        packet.push(packet_type);
        packet.extend_from_slice(payload);
        packet
    }

    fn build_string(s: &str) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&(s.len() as u32).to_be_bytes());
        result.extend_from_slice(s.as_bytes());
        result
    }

    #[test]
    fn test_parse_open_read() {
        let parser = SftpParser::new();

        let mut payload = Vec::new();
        payload.extend_from_slice(&1u32.to_be_bytes()); // request_id
        payload.extend_from_slice(&build_string("/tmp/test.txt")); // path
        payload.extend_from_slice(&0x01u32.to_be_bytes()); // flags (read)
        payload.extend_from_slice(&0u32.to_be_bytes()); // attrs

        let packet = build_sftp_packet(3, &payload); // SSH_FXP_OPEN

        let result = parser.parse_packet(&packet);
        assert!(result.is_some());

        if let Some(SftpFileOperation::Open {
            request_id,
            path,
            is_upload,
            is_download,
            ..
        }) = result
        {
            assert_eq!(request_id, 1);
            assert_eq!(path, "/tmp/test.txt");
            assert!(!is_upload);
            assert!(is_download);
        } else {
            panic!("Expected Open operation");
        }
    }

    #[test]
    fn test_parse_open_write() {
        let parser = SftpParser::new();

        let mut payload = Vec::new();
        payload.extend_from_slice(&2u32.to_be_bytes()); // request_id
        payload.extend_from_slice(&build_string("/tmp/output.txt")); // path
        payload.extend_from_slice(&0x0Au32.to_be_bytes()); // flags (write | create)
        payload.extend_from_slice(&0u32.to_be_bytes()); // attrs

        let packet = build_sftp_packet(3, &payload);

        let result = parser.parse_packet(&packet);
        assert!(result.is_some());

        if let Some(SftpFileOperation::Open {
            request_id,
            is_upload,
            is_download,
            ..
        }) = result
        {
            assert_eq!(request_id, 2);
            assert!(is_upload);
            assert!(!is_download);
        } else {
            panic!("Expected Open operation");
        }
    }

    #[test]
    fn test_parse_short_packet() {
        let parser = SftpParser::new();

        // Too short
        let result = parser.parse_packet(&[0, 0, 0, 1]);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_close() {
        let parser = SftpParser::new();

        let mut payload = Vec::new();
        payload.extend_from_slice(&3u32.to_be_bytes()); // request_id
        payload.extend_from_slice(&build_string("handle123")); // handle as string

        let packet = build_sftp_packet(4, &payload); // SSH_FXP_CLOSE

        let result = parser.parse_packet(&packet);
        assert!(result.is_some());

        if let Some(SftpFileOperation::Close { request_id, handle }) = result {
            assert_eq!(request_id, 3);
            assert_eq!(handle, b"handle123");
        } else {
            panic!("Expected Close operation");
        }
    }

    #[test]
    fn test_parse_handle_response() {
        let parser = SftpParser::new();

        let mut payload = Vec::new();
        payload.extend_from_slice(&42u32.to_be_bytes()); // request_id
        payload.extend_from_slice(&build_string("file_handle_xyz")); // handle

        let packet = build_sftp_packet(102, &payload); // SSH_FXP_HANDLE

        let result = parser.parse_response(&packet);
        assert!(result.is_some());

        if let Some(SftpResponse::Handle { request_id, handle }) = result {
            assert_eq!(request_id, 42);
            assert_eq!(handle, b"file_handle_xyz");
        } else {
            panic!("Expected Handle response");
        }
    }

    #[test]
    fn test_parse_data_response() {
        let parser = SftpParser::new();

        let test_data = b"Hello, World! This is file content.";
        let mut payload = Vec::new();
        payload.extend_from_slice(&99u32.to_be_bytes()); // request_id
        payload.extend_from_slice(&(test_data.len() as u32).to_be_bytes()); // data length
        payload.extend_from_slice(test_data); // data

        let packet = build_sftp_packet(103, &payload); // SSH_FXP_DATA

        let result = parser.parse_response(&packet);
        assert!(result.is_some());

        if let Some(SftpResponse::Data { request_id, data }) = result {
            assert_eq!(request_id, 99);
            assert_eq!(data, test_data);
        } else {
            panic!("Expected Data response");
        }
    }

    #[test]
    fn test_parse_status_response() {
        let parser = SftpParser::new();

        let mut payload = Vec::new();
        payload.extend_from_slice(&123u32.to_be_bytes()); // request_id
        payload.extend_from_slice(&0u32.to_be_bytes()); // status code (SSH_FX_OK)
                                                        // Error message and language tag follow but we don't parse them

        let packet = build_sftp_packet(101, &payload); // SSH_FXP_STATUS

        let result = parser.parse_response(&packet);
        assert!(result.is_some());

        if let Some(SftpResponse::Status { request_id, code }) = result {
            assert_eq!(request_id, 123);
            assert_eq!(code, 0);
        } else {
            panic!("Expected Status response");
        }
    }
}

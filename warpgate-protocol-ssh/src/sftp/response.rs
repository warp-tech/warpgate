//! SFTP Response Builder
//!
//! Builds SFTP protocol responses for access control.

/// SFTP status codes
#[allow(dead_code)]
pub mod status_codes {
    pub const SSH_FX_OK: u32 = 0;
    pub const SSH_FX_EOF: u32 = 1;
    pub const SSH_FX_NO_SUCH_FILE: u32 = 2;
    pub const SSH_FX_PERMISSION_DENIED: u32 = 3;
    pub const SSH_FX_FAILURE: u32 = 4;
    pub const SSH_FX_BAD_MESSAGE: u32 = 5;
    pub const SSH_FX_NO_CONNECTION: u32 = 6;
    pub const SSH_FX_CONNECTION_LOST: u32 = 7;
    pub const SSH_FX_OP_UNSUPPORTED: u32 = 8;
}

/// SFTP packet types
#[allow(dead_code)]
pub mod packet_types {
    pub const SSH_FXP_STATUS: u8 = 101;
}

/// Build SSH_FXP_STATUS packet with SSH_FX_PERMISSION_DENIED
///
/// This is sent back to the client when an operation is blocked due to
/// file transfer permissions.
pub fn build_permission_denied_response(request_id: u32, message: &str) -> Vec<u8> {
    build_status_response(
        request_id,
        status_codes::SSH_FX_PERMISSION_DENIED,
        message,
        "en",
    )
}

/// Build a generic SSH_FXP_STATUS response
pub fn build_status_response(
    request_id: u32,
    status_code: u32,
    error_message: &str,
    language_tag: &str,
) -> Vec<u8> {
    let mut packet = Vec::new();

    // Calculate payload length:
    // - packet_type: 1 byte
    // - request_id: 4 bytes
    // - status_code: 4 bytes
    // - error_message: 4 bytes (length) + message bytes
    // - language_tag: 4 bytes (length) + tag bytes
    let payload_len = 1 + 4 + 4 + 4 + error_message.len() + 4 + language_tag.len();

    // Length field (4 bytes, big-endian) - does not include itself
    packet.extend_from_slice(&(payload_len as u32).to_be_bytes());

    // Packet type: SSH_FXP_STATUS (101)
    packet.push(packet_types::SSH_FXP_STATUS);

    // Request ID (4 bytes, big-endian)
    packet.extend_from_slice(&request_id.to_be_bytes());

    // Status code (4 bytes, big-endian)
    packet.extend_from_slice(&status_code.to_be_bytes());

    // Error message (length-prefixed string)
    packet.extend_from_slice(&(error_message.len() as u32).to_be_bytes());
    packet.extend_from_slice(error_message.as_bytes());

    // Language tag (length-prefixed string)
    packet.extend_from_slice(&(language_tag.len() as u32).to_be_bytes());
    packet.extend_from_slice(language_tag.as_bytes());

    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_permission_denied_response() {
        let response = build_permission_denied_response(
            42,
            "Permission denied: file upload is not allowed on target 'prod-server'",
        );

        // Verify structure
        assert!(response.len() > 4);

        // Parse length
        let length = u32::from_be_bytes([response[0], response[1], response[2], response[3]]);
        assert_eq!(length as usize, response.len() - 4);

        // Parse packet type
        assert_eq!(response[4], packet_types::SSH_FXP_STATUS);

        // Parse request_id
        let request_id = u32::from_be_bytes([response[5], response[6], response[7], response[8]]);
        assert_eq!(request_id, 42);

        // Parse status code
        let status_code =
            u32::from_be_bytes([response[9], response[10], response[11], response[12]]);
        assert_eq!(status_code, status_codes::SSH_FX_PERMISSION_DENIED);
    }

    #[test]
    fn test_build_status_response_custom() {
        let response =
            build_status_response(123, status_codes::SSH_FX_NO_SUCH_FILE, "Not found", "en-US");

        // Verify basic structure
        assert!(response.len() > 4);

        // Parse request_id
        let request_id = u32::from_be_bytes([response[5], response[6], response[7], response[8]]);
        assert_eq!(request_id, 123);

        // Parse status code
        let status_code =
            u32::from_be_bytes([response[9], response[10], response[11], response[12]]);
        assert_eq!(status_code, status_codes::SSH_FX_NO_SUCH_FILE);
    }
}

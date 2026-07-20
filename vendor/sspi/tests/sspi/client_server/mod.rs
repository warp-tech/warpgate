// The network_client and __test-data features are required for the client_server tests.
#![cfg(all(feature = "network_client", feature = "__test-data"))]

mod credssp;
mod kerberos;
mod negotiate;
mod ntlm;

use sspi::credssp::SspiContext;
use sspi::{EncryptionFlags, SecurityBufferFlags, SecurityBufferRef, Sspi};

const TARGET_NAME: &str = "TERMSRV/DESKTOP-8F33RFH.example.com";

fn test_encryption(client: &mut SspiContext, server: &mut SspiContext) {
    let plain_message = b"Devolutions/sspi-rs";

    let mut token = [0; 1024];
    let mut data = plain_message.to_vec();

    let mut message = vec![
        SecurityBufferRef::token_buf(token.as_mut_slice()),
        SecurityBufferRef::data_buf(data.as_mut_slice()),
    ];

    client.encrypt_message(EncryptionFlags::empty(), &mut message).unwrap();
    server.decrypt_message(&mut message).unwrap();

    assert_eq!(plain_message, message[1].data());
}

fn test_stream_buffer_encryption(client: &mut SspiContext, server: &mut SspiContext) {
    // https://learn.microsoft.com/en-us/windows/win32/secauthn/sspi-kerberos-interoperability-with-gssapi

    let plain_message = b"Devolutions/sspi-rs";

    let mut token = [0; 1024];
    let mut data = plain_message.to_vec();
    let mut message = [
        SecurityBufferRef::token_buf(token.as_mut_slice()),
        SecurityBufferRef::data_buf(data.as_mut_slice()),
    ];

    client.encrypt_message(EncryptionFlags::empty(), &mut message).unwrap();

    let mut buffer = message[0].data().to_vec();
    buffer.extend_from_slice(message[1].data());

    let mut message = [
        SecurityBufferRef::stream_buf(&mut buffer),
        SecurityBufferRef::data_buf(&mut []),
    ];

    server.decrypt_message(&mut message).unwrap();

    assert_eq!(message[1].data(), plain_message);
}

fn test_rpc_request_encryption(client: &mut SspiContext, server: &mut SspiContext) {
    // RPC header
    let header = [
        5, 0, 0, 3, 16, 0, 0, 0, 60, 1, 76, 0, 1, 0, 0, 0, 208, 0, 0, 0, 0, 0, 0, 0,
    ];
    // Unencrypted data in RPC Request
    let plaintext = [
        108, 0, 0, 0, 0, 0, 0, 0, 108, 0, 0, 0, 0, 0, 0, 0, 1, 0, 4, 128, 84, 0, 0, 0, 96, 0, 0, 0, 0, 0, 0, 0, 20, 0,
        0, 0, 2, 0, 64, 0, 2, 0, 0, 0, 0, 0, 36, 0, 3, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 223, 243, 137, 88,
        86, 131, 83, 53, 105, 218, 109, 33, 80, 4, 0, 0, 0, 0, 20, 0, 2, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
        1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 138, 227, 19, 113, 2, 244, 54, 113, 2, 64, 40, 0,
        96, 89, 120, 185, 79, 82, 223, 17, 139, 109, 131, 220, 222, 215, 32, 133, 1, 0, 0, 0, 51, 5, 113, 113, 186,
        190, 55, 73, 131, 25, 181, 219, 239, 156, 204, 54, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    // RPC security trailer header
    let trailer = [16, 6, 8, 0, 0, 0, 0, 0];

    let mut header_data = header.to_vec();
    let mut data = plaintext.to_vec();
    let mut trailer_data = trailer.to_vec();
    let mut token_data = vec![0; 76];
    let mut message = vec![
        SecurityBufferRef::data_buf(&mut header_data).with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
        SecurityBufferRef::data_buf(&mut data),
        SecurityBufferRef::data_buf(&mut trailer_data)
            .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
        SecurityBufferRef::token_buf(&mut token_data),
    ];

    client.encrypt_message(EncryptionFlags::empty(), &mut message).unwrap();

    assert_eq!(header[..], message[0].data()[..]);
    assert_eq!(trailer[..], message[2].data()[..]);

    server.decrypt_message(&mut message).unwrap();

    assert_eq!(header[..], message[0].data()[..]);
    assert_eq!(message[1].data(), plaintext);
    assert_eq!(trailer[..], message[2].data()[..]);
}

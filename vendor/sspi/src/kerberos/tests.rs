use picky_krb::constants::key_usages::{ACCEPTOR_SEAL, INITIATOR_SEAL};
use picky_krb::crypto::CipherSuite;

use crate::kerberos::{EncryptionParams, KerberosConfig, KerberosState, test_data};
use crate::{EncryptionFlags, Kerberos, SecurityBufferFlags, SecurityBufferRef, Sspi};

#[test]
fn stream_buffer_decryption() {
    // https://learn.microsoft.com/en-us/windows/win32/secauthn/sspi-kerberos-interoperability-with-gssapi

    let mut kerberos_server = test_data::fake_server();
    let mut kerberos_client = test_data::fake_client();

    let plain_message = b"some plain message";

    let mut token = [0; 1024];
    let mut data = plain_message.to_vec();
    let mut message = [
        SecurityBufferRef::token_buf(token.as_mut_slice()),
        SecurityBufferRef::data_buf(data.as_mut_slice()),
    ];

    kerberos_server
        .encrypt_message(EncryptionFlags::empty(), &mut message)
        .unwrap();

    let mut buffer = message[0].data().to_vec();
    buffer.extend_from_slice(message[1].data());

    let mut message = [
        SecurityBufferRef::stream_buf(&mut buffer),
        SecurityBufferRef::data_buf(&mut []),
    ];

    kerberos_client.decrypt_message(&mut message).unwrap();

    assert_eq!(message[1].data(), plain_message);
}

#[test]
fn secbuffer_readonly_with_checksum() {
    // All values in this test (session keys, sequence number, encrypted and decrypted data) were extracted
    // from the original Windows Kerberos implementation calls.
    // We keep this test to guarantee full compatibility with the original Kerberos.

    let session_key = [
        114, 67, 55, 26, 76, 210, 61, 0, 164, 44, 11, 133, 108, 220, 234, 145, 61, 144, 123, 45, 54, 175, 164, 168, 99,
        18, 99, 240, 242, 157, 95, 134,
    ];
    let sub_session_key = [
        91, 11, 188, 227, 10, 91, 180, 246, 64, 129, 251, 200, 118, 82, 109, 65, 241, 177, 109, 32, 124, 39, 127, 171,
        222, 132, 199, 199, 126, 110, 3, 166,
    ];

    let mut kerberos_server = Kerberos {
        state: KerberosState::Final,
        config: KerberosConfig {
            kdc_url: None,
            client_computer_name: "hostname".into(),
        },
        auth_identity: None,
        encryption_params: EncryptionParams {
            encryption_type: Some(CipherSuite::Aes256CtsHmacSha196),
            session_key: Some(session_key.to_vec().into()),
            sub_session_key: Some(sub_session_key.to_vec().into()),
            sspi_encrypt_key_usage: ACCEPTOR_SEAL,
            sspi_decrypt_key_usage: INITIATOR_SEAL,
            ec: 16,
        },
        seq_number: 681238048,
        realm: None,
        kdc_url: None,
        channel_bindings: None,
        #[cfg(feature = "scard")]
        dh_parameters: None,
        krb5_user_to_user: false,
        server: Some(Box::new(test_data::fake_server_properties())),
    };

    // RPC header
    let header = [
        5, 0, 0, 3, 16, 0, 0, 0, 60, 1, 76, 0, 1, 0, 0, 0, 208, 0, 0, 0, 0, 0, 0, 0,
    ];
    // RPC security trailer header
    let trailer = [16, 6, 8, 0, 0, 0, 0, 0];
    // Encrypted data in RPC Request
    let enc_data = [
        41, 85, 192, 239, 104, 188, 180, 100, 229, 73, 83, 199, 77, 83, 79, 17, 163, 206, 241, 29, 90, 28, 89, 203, 83,
        176, 160, 252, 197, 221, 76, 113, 185, 141, 16, 200, 149, 55, 32, 96, 29, 49, 57, 124, 181, 147, 110, 198, 125,
        116, 150, 47, 35, 224, 117, 25, 10, 229, 201, 222, 153, 101, 131, 93, 204, 32, 9, 145, 186, 45, 224, 160, 131,
        23, 236, 111, 88, 48, 54, 4, 118, 114, 129, 119, 130, 164, 178, 4, 110, 74, 37, 1, 215, 177, 16, 204, 238, 83,
        255, 40, 240, 32, 209, 213, 90, 19, 126, 58, 34, 33, 72, 15, 206, 96, 67, 15, 169, 248, 176, 9, 173, 196, 159,
        239, 250, 120, 206, 52, 53, 229, 230, 66, 64, 109, 100, 21, 77, 193, 3, 40, 183, 209, 177, 152, 165, 171, 108,
        151, 112, 134, 53, 165, 128, 145, 147, 167, 5, 72, 35, 101, 42, 183, 67, 101, 48, 255, 84, 208, 112, 199, 154,
        62, 185, 87, 204, 228, 45, 30, 184, 47, 129, 145, 245, 168, 118, 174, 48, 98, 174, 167, 208, 0, 113, 246, 219,
        29, 192, 171, 97, 117, 115, 120, 115, 45, 44, 113, 62, 39,
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
    // RPC Request security trailer data. Basically, it's a GSS API Wrap token
    let security_trailer_data = [
        5, 4, 6, 255, 0, 16, 0, 28, 0, 0, 0, 0, 40, 154, 222, 33, 170, 177, 218, 93, 176, 5, 210, 44, 38, 242, 179,
        168, 249, 202, 242, 199, 63, 162, 33, 40, 106, 186, 187, 28, 11, 229, 207, 219, 66, 86, 243, 16, 158, 100, 133,
        159, 87, 153, 196, 14, 251, 169, 164, 12, 18, 85, 182, 56, 72, 30, 137, 238, 50, 122, 73, 95, 109, 194, 60,
        120,
    ];

    let mut header_data = header.to_vec();
    let mut encrypted_data = enc_data.to_vec();
    let mut trailer_data = trailer.to_vec();
    let mut token_data = security_trailer_data.to_vec();
    let mut message = vec![
        SecurityBufferRef::data_buf(&mut header_data).with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
        SecurityBufferRef::data_buf(&mut encrypted_data),
        SecurityBufferRef::data_buf(&mut trailer_data)
            .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
        SecurityBufferRef::token_buf(&mut token_data),
    ];

    kerberos_server.decrypt_message(&mut message).unwrap();

    assert_eq!(header[..], message[0].data()[..]);
    assert_eq!(plaintext[..], message[1].data()[..]);
    assert_eq!(trailer[..], message[2].data()[..]);
}

#[test]
fn rpc_request_encryption() {
    let mut kerberos_server = test_data::fake_server();
    let mut kerberos_client = test_data::fake_client();

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

    kerberos_client
        .encrypt_message(EncryptionFlags::empty(), &mut message)
        .unwrap();

    assert_eq!(header[..], message[0].data()[..]);
    assert_eq!(trailer[..], message[2].data()[..]);

    kerberos_server.decrypt_message(&mut message).unwrap();

    assert_eq!(header[..], message[0].data()[..]);
    assert_eq!(message[1].data(), plaintext);
    assert_eq!(trailer[..], message[2].data()[..]);
}

#[test]
fn integrity_only_wrap_decryption() {
    // A standards-compliant SASL/GSSAPI peer (RFC 4752 / RFC 4121 §4.2.4) may
    // send an integrity-only (conf=false) Wrap token: the payload is carried in
    // the clear followed by the get_mic checksum, right-rotated by RRC. This
    // exercises the unsealed WRAP verification path (RRC undo, EC/RRC header
    // zeroing for the checksum input, and checksum validation) by feeding a
    // known-good token built the way a compliant sender would and asserting the
    // cleartext is recovered.
    use picky_krb::crypto::aes::{AesSize, checksum_sha_aes};
    use picky_krb::gss_api::WrapToken;

    // Arbitrary AES-256 session key.
    let session_key = [
        0x9e, 0x8f, 0x7d, 0x6c, 0x5b, 0x4a, 0x39, 0x28, 0x17, 0x06, 0xf5, 0xe4, 0xd3, 0xc2, 0xb1, 0xa0, 0x10, 0x21,
        0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
    ];

    let plaintext: &[u8] = b"GSSAPI integrity-only payload";

    // The acceptor sends the token; a client (initiator) decrypts it with the
    // ACCEPTOR_SEAL key usage. Wrap tokens — sealed or not — use the SEAL usage.
    let key_usage = ACCEPTOR_SEAL;
    let aes_size = AesSize::Aes256;

    // The checksum is computed over `plaintext | header`, with the EC and RRC
    // fields of the 16-octet header zeroed.
    let seq_num = 42;
    let mut wrap_token = WrapToken::with_seq_number(seq_num);
    // SentByAcceptor (0x01) set, Sealed (0x02) clear -> integrity-only.
    wrap_token.flags = 0x01;
    wrap_token.ec = 0;
    wrap_token.rrc = 0;

    let mut to_sign = plaintext.to_vec();
    to_sign.extend_from_slice(&wrap_token.header());
    let checksum = checksum_sha_aes(&session_key, key_usage, &to_sign, &aes_size).unwrap();

    // For unsealed tokens, EC encodes the trailing checksum length (RFC 4121
    // §4.2.3). The sender right-rotates `plaintext | checksum` by RRC.
    let rrc = u16::try_from(checksum.len()).unwrap();
    let mut payload = plaintext.to_vec();
    payload.extend_from_slice(&checksum);
    payload.rotate_right(usize::from(rrc));

    wrap_token.ec = rrc;
    wrap_token.rrc = rrc;
    wrap_token.checksum = payload;

    let mut token_bytes = Vec::new();
    wrap_token.encode(&mut token_bytes).unwrap();

    let mut kerberos_client = Kerberos {
        state: KerberosState::Final,
        config: KerberosConfig {
            kdc_url: None,
            client_computer_name: "hostname".into(),
        },
        auth_identity: None,
        encryption_params: EncryptionParams {
            encryption_type: Some(CipherSuite::Aes256CtsHmacSha196),
            session_key: None,
            sub_session_key: Some(session_key.to_vec().into()),
            sspi_encrypt_key_usage: INITIATOR_SEAL,
            sspi_decrypt_key_usage: ACCEPTOR_SEAL,
            ec: 0,
        },
        seq_number: 0,
        realm: None,
        kdc_url: None,
        channel_bindings: None,
        #[cfg(feature = "scard")]
        dh_parameters: None,
        krb5_user_to_user: false,
        server: None,
    };

    let mut buffer = token_bytes;
    let mut message = [
        SecurityBufferRef::stream_buf(&mut buffer),
        SecurityBufferRef::data_buf(&mut []),
    ];

    kerberos_client.decrypt_message(&mut message).unwrap();

    assert_eq!(message[1].data(), plaintext);
}

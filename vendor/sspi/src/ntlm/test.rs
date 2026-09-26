use crate::crypto::{HASH_SIZE, Rc4};
use crate::ntlm::messages::test::TEST_CREDENTIALS;
use crate::ntlm::{
    AuthenticateMessage, CHALLENGE_SIZE, ChallengeMessage, Mic, NegotiateFlags, NegotiateMessage, Ntlm, NtlmState,
    SIGNATURE_SIZE,
};
use crate::*;

const TEST_SEQ_NUM: u32 = 1_234_567_890;
const SEALING_KEY: [u8; HASH_SIZE] = [
    0xa4, 0xf1, 0xba, 0xa6, 0x7c, 0xdc, 0x1a, 0x12, 0x20, 0xc0, 0x2b, 0x3d, 0xc0, 0x61, 0xa7, 0x73,
];
const SIGNING_KEY: [u8; HASH_SIZE] = [
    0x20, 0xc0, 0x2b, 0x3d, 0xc0, 0x61, 0xa7, 0x73, 0xa4, 0xf1, 0xba, 0xa6, 0x7c, 0xdc, 0x1a, 0x12,
];

pub(super) const TEST_DATA: &[u8] = b"Hello, World!!!";

pub(super) const ENCRYPTED_TEST_DATA: [u8; 15] = [
    0x20, 0x2e, 0xdd, 0xd9, 0x56, 0x5e, 0xc4, 0x59, 0x42, 0xdb, 0x94, 0xfd, 0x6b, 0xf3, 0x11,
];

pub(super) const DIGEST_FOR_TEST_DATA: [u8; 8] = [0x58, 0x27, 0x4d, 0x35, 0x1f, 0x2d, 0x3c, 0xfd];

pub(super) const SIGNATURE_FOR_TEST_DATA: [u8; 16] = [
    0x1, 0x0, 0x0, 0x0, 0x58, 0x27, 0x4d, 0x35, 0x1f, 0x2d, 0x3c, 0xfd, 0xd2, 0x2, 0x96, 0x49,
];

#[test]
fn encrypt_message_crypts_data() {
    let mut context = Ntlm::new();
    context.send_sealing_key = Some(Rc4::new(&SEALING_KEY));

    let mut token = [0; 100];
    let mut data = TEST_DATA.to_vec();
    let mut buffers = vec![
        SecurityBufferRef::token_buf(token.as_mut_slice()),
        SecurityBufferRef::data_buf(data.as_mut_slice()),
    ];
    let expected = &ENCRYPTED_TEST_DATA;

    let result = context.encrypt_message(EncryptionFlags::empty(), &mut buffers).unwrap();
    let output = SecurityBufferRef::find_buffer(&buffers, BufferType::Data).unwrap();

    assert_eq!(result, SecurityStatus::Ok);
    assert_eq!(expected, output.data());
}

#[test]
fn encrypt_message_correct_computes_digest() {
    let mut context = Ntlm::new();
    context.flags.set(NegotiateFlags::NTLM_SSP_NEGOTIATE_KEY_EXCH, true);
    context.our_seq_number = TEST_SEQ_NUM;
    context.send_signing_key = SIGNING_KEY.into();
    context.send_sealing_key = Some(Rc4::new(&SEALING_KEY));

    let mut token = [0; 100];
    let mut data = TEST_DATA.to_vec();
    let mut buffers = vec![
        SecurityBufferRef::token_buf(token.as_mut_slice()),
        SecurityBufferRef::data_buf(data.as_mut_slice()),
    ];
    let expected = &DIGEST_FOR_TEST_DATA;

    let result = context.encrypt_message(EncryptionFlags::empty(), &mut buffers).unwrap();
    let signature = SecurityBufferRef::find_buffer(&buffers, BufferType::Token).unwrap();

    assert_eq!(result, SecurityStatus::Ok);
    assert_eq!(expected, &signature.data()[4..12]);
}

#[test]
fn encrypt_message_correct_computes_unencrypted_digest() {
    // When the NTLM_SSP_NEGOTIATE_KEY_EXCH flag is not set, the digest should be computed without encryption (HMAC only).
    let digest = &[70, 148, 67, 212, 16, 164, 169, 167];

    let mut context = Ntlm::new();
    context.our_seq_number = TEST_SEQ_NUM;
    context.send_signing_key = SIGNING_KEY.into();
    context.send_sealing_key = Some(Rc4::new(&SEALING_KEY));

    let mut token = [0; 100];
    let mut data = TEST_DATA.to_vec();
    let mut buffers = vec![
        SecurityBufferRef::token_buf(token.as_mut_slice()),
        SecurityBufferRef::data_buf(data.as_mut_slice()),
    ];

    let result = context.encrypt_message(EncryptionFlags::empty(), &mut buffers).unwrap();
    let signature = SecurityBufferRef::find_buffer(&buffers, BufferType::Token).unwrap();

    assert_eq!(result, SecurityStatus::Ok);
    assert_eq!(digest, &signature.data()[4..12]);
}

#[test]
fn encrypt_message_writes_seq_num_to_signature() {
    let mut context = Ntlm::new();
    context.our_seq_number = TEST_SEQ_NUM;
    context.send_signing_key = SIGNING_KEY.into();
    context.send_sealing_key = Some(Rc4::new(&SEALING_KEY));

    let mut token = [0; 100];
    let mut data = TEST_DATA.to_vec();
    let mut buffers = vec![
        SecurityBufferRef::token_buf(token.as_mut_slice()),
        SecurityBufferRef::data_buf(data.as_mut_slice()),
    ];
    let expected = TEST_SEQ_NUM.to_le_bytes();

    let result = context.encrypt_message(EncryptionFlags::empty(), &mut buffers).unwrap();
    let signature = SecurityBufferRef::find_buffer(&buffers, BufferType::Token).unwrap();

    assert_eq!(result, SecurityStatus::Ok);
    assert_eq!(expected, signature.data()[12..SIGNATURE_SIZE]);
}

#[test]
fn decrypt_message_decrypts_data() {
    let mut context = Ntlm::new();
    context.flags.set(NegotiateFlags::NTLM_SSP_NEGOTIATE_KEY_EXCH, true);
    context.remote_seq_number = TEST_SEQ_NUM;
    context.recv_signing_key = SIGNING_KEY.into();
    context.recv_sealing_key = Some(Rc4::new(&SEALING_KEY));

    let mut encrypted_test_data = ENCRYPTED_TEST_DATA.to_vec();
    let mut signature_test_data = SIGNATURE_FOR_TEST_DATA.to_vec();

    let mut buffers = vec![
        SecurityBufferRef::data_buf(&mut encrypted_test_data),
        SecurityBufferRef::token_buf(&mut signature_test_data),
    ];
    let expected = TEST_DATA;

    context.decrypt_message(&mut buffers).unwrap();
    let data = SecurityBufferRef::find_buffer(&buffers, BufferType::Data).unwrap();

    assert_eq!(expected, data.data());
}

#[test]
fn decrypt_message_does_not_fail_on_unencrypted_signature() {
    // When the NTLM_SSP_NEGOTIATE_KEY_EXCH flag is not set, the digest should be computed without encryption (HMAC only).
    let signature = [1, 0, 0, 0, 70, 148, 67, 212, 16, 164, 169, 167, 210, 2, 150, 73];

    let mut context = Ntlm::new();
    context.remote_seq_number = TEST_SEQ_NUM;
    context.recv_signing_key = SIGNING_KEY.into();
    context.recv_sealing_key = Some(Rc4::new(&SEALING_KEY));

    let mut encrypted_test_data = ENCRYPTED_TEST_DATA.to_vec();
    let mut signature_test_data = signature.to_vec();

    let mut buffers = vec![
        SecurityBufferRef::data_buf(&mut encrypted_test_data),
        SecurityBufferRef::token_buf(&mut signature_test_data),
    ];

    context.decrypt_message(&mut buffers).unwrap();
}

#[test]
fn decrypt_message_does_not_fail_on_correct_signature() {
    let mut context = Ntlm::new();
    context.flags.set(NegotiateFlags::NTLM_SSP_NEGOTIATE_KEY_EXCH, true);
    context.remote_seq_number = TEST_SEQ_NUM;
    context.recv_signing_key = SIGNING_KEY.into();
    context.recv_sealing_key = Some(Rc4::new(&SEALING_KEY));

    let mut encrypted_test_data = ENCRYPTED_TEST_DATA.to_vec();
    let mut signature_test_data = SIGNATURE_FOR_TEST_DATA.to_vec();

    let mut buffers = vec![
        SecurityBufferRef::data_buf(&mut encrypted_test_data),
        SecurityBufferRef::token_buf(&mut signature_test_data),
    ];

    context.decrypt_message(&mut buffers).unwrap();
}

#[test]
fn decrypt_message_fails_on_incorrect_version() {
    let mut context = Ntlm::new();
    context.remote_seq_number = TEST_SEQ_NUM;
    context.recv_signing_key = SIGNING_KEY.into();
    context.recv_sealing_key = Some(Rc4::new(&SEALING_KEY));

    let mut encrypted_test_data = ENCRYPTED_TEST_DATA.to_vec();
    let mut token = [
        0x02, 0x00, 0x00, 0x00, 0x2e, 0xdf, 0xf2, 0x61, 0x29, 0xd6, 0x4d, 0xa9, 0xd2, 0x02, 0x96, 0x49,
    ];

    let mut buffers = vec![
        SecurityBufferRef::data_buf(&mut encrypted_test_data),
        SecurityBufferRef::token_buf(&mut token),
    ];

    assert!(context.decrypt_message(&mut buffers).is_err());
}

#[test]
fn decrypt_message_fails_on_incorrect_checksum() {
    let mut context = Ntlm::new();
    context.remote_seq_number = TEST_SEQ_NUM;
    context.recv_signing_key = SIGNING_KEY.into();
    context.recv_sealing_key = Some(Rc4::new(&SEALING_KEY));

    let mut encrypted_test_data = ENCRYPTED_TEST_DATA.to_vec();
    let mut token = [
        0x01, 0x00, 0x00, 0x00, 0x2e, 0xdf, 0xff, 0x61, 0x29, 0xd6, 0x4d, 0xa9, 0xd2, 0x02, 0x96, 0x49,
    ];

    let mut buffers = vec![
        SecurityBufferRef::data_buf(&mut encrypted_test_data),
        SecurityBufferRef::token_buf(&mut token),
    ];

    assert!(context.decrypt_message(&mut buffers).is_err());
}

#[test]
fn decrypt_message_fails_on_incorrect_seq_num() {
    let mut context = Ntlm::new();
    context.remote_seq_number = TEST_SEQ_NUM;
    context.recv_signing_key = SIGNING_KEY.into();
    context.recv_sealing_key = Some(Rc4::new(&SEALING_KEY));

    let mut encrypted_test_data = ENCRYPTED_TEST_DATA.to_vec();
    let mut token = [
        0x01, 0x00, 0x00, 0x00, 0x2e, 0xdf, 0xf2, 0x61, 0x29, 0xd6, 0x4d, 0xa9, 0xd2, 0x02, 0x96, 0x40,
    ];

    let mut buffers = vec![
        SecurityBufferRef::data_buf(&mut encrypted_test_data),
        SecurityBufferRef::token_buf(&mut token),
    ];

    assert!(context.decrypt_message(&mut buffers).is_err());
}

#[test]
fn decrypt_message_fails_on_incorrect_signing_key() {
    let mut context = Ntlm::new();
    context.remote_seq_number = TEST_SEQ_NUM;
    context.recv_signing_key = SEALING_KEY.into();
    context.recv_sealing_key = Some(Rc4::new(&SEALING_KEY));

    let mut encrypted_test_data = ENCRYPTED_TEST_DATA.to_vec();
    let mut signature_test_data = SIGNATURE_FOR_TEST_DATA.to_vec();

    let mut buffers = vec![
        SecurityBufferRef::data_buf(&mut encrypted_test_data),
        SecurityBufferRef::token_buf(&mut signature_test_data),
    ];

    assert!(context.decrypt_message(&mut buffers).is_err());
}

#[test]
fn decrypt_message_fails_on_incorrect_sealing_key() {
    let mut context = Ntlm::new();
    context.remote_seq_number = TEST_SEQ_NUM;
    context.recv_signing_key = SIGNING_KEY.into();
    context.recv_sealing_key = Some(Rc4::new(&SIGNING_KEY));

    let mut encrypted_test_data = ENCRYPTED_TEST_DATA.to_vec();
    let mut signature_test_data = SIGNATURE_FOR_TEST_DATA.to_vec();

    let mut buffers = vec![
        SecurityBufferRef::data_buf(&mut encrypted_test_data),
        SecurityBufferRef::token_buf(&mut signature_test_data),
    ];

    assert!(context.decrypt_message(&mut buffers).is_err());
}

#[test]
fn make_signature_verified_by_verify_signature() {
    let mut sender = Ntlm::new();
    let mut reciever = Ntlm::new();

    sender.send_signing_key = SIGNING_KEY.into();
    sender.send_sealing_key = Some(Rc4::new(&SEALING_KEY));

    reciever.recv_signing_key = SIGNING_KEY.into();
    reciever.recv_sealing_key = Some(Rc4::new(&SEALING_KEY));

    let mut plain_test_data = TEST_DATA.to_vec();
    let mut signature_test_data = [0u8; 16];
    let mut make_signature_buffers = vec![
        SecurityBufferRef::data_buf(&mut plain_test_data),
        SecurityBufferRef::token_buf(&mut signature_test_data),
    ];
    assert!(
        sender
            .make_signature(0, &mut make_signature_buffers, TEST_SEQ_NUM)
            .is_ok()
    );

    let mut verify_signature_buffers = vec![
        SecurityBufferRef::data_buf(&mut plain_test_data),
        SecurityBufferRef::token_buf(&mut signature_test_data),
    ];
    assert!(
        reciever
            .verify_signature(&mut verify_signature_buffers, TEST_SEQ_NUM)
            .is_ok()
    );
}

#[test]
fn verify_signature_fails_on_invalid_signature() {
    let mut context = Ntlm::new();

    context.recv_signing_key = SIGNING_KEY.into();
    context.recv_sealing_key = Some(Rc4::new(&SEALING_KEY));

    let mut test_data = TEST_DATA.to_vec();
    let mut token = [
        0x01, 0x00, 0x00, 0x00, 0x2e, 0xdf, 0xff, 0x61, 0x29, 0xd6, 0x4d, 0xa9, 0xd2, 0x02, 0x96, 0x49,
    ];

    let mut verify_signature_buffers = vec![
        SecurityBufferRef::data_buf(&mut test_data),
        SecurityBufferRef::token_buf(&mut token),
    ];
    assert!(
        context
            .verify_signature(&mut verify_signature_buffers, TEST_SEQ_NUM)
            .is_err()
    );
}

#[test]
fn initialize_security_context_wrong_state_negotiate() {
    let mut context = Ntlm::new();
    context.state = NtlmState::Negotiate;

    let mut output = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
    let mut credentials = Some(TEST_CREDENTIALS.clone());

    let mut builder = context
        .initialize_security_context()
        .with_credentials_handle(&mut credentials)
        .with_context_requirements(ClientRequestFlags::empty())
        .with_target_data_representation(DataRepresentation::Native)
        .with_output(&mut output);

    assert!(context.initialize_security_context_impl(&mut builder).is_err());
    assert_eq!(context.state, NtlmState::Negotiate);
}

#[test]
fn initialize_security_context_wrong_state_authenticate() {
    let mut context = Ntlm::new();
    context.state = NtlmState::Authenticate;

    let mut output = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
    let mut credentials = Some(TEST_CREDENTIALS.clone());

    let mut builder = context
        .initialize_security_context()
        .with_credentials_handle(&mut credentials)
        .with_context_requirements(ClientRequestFlags::empty())
        .with_target_data_representation(DataRepresentation::Native)
        .with_output(&mut output);

    assert!(context.initialize_security_context_impl(&mut builder).is_err());
    assert_eq!(context.state, NtlmState::Authenticate);
}

#[test]
fn initialize_security_context_wrong_state_completion() {
    let mut context = Ntlm::new();
    context.state = NtlmState::Completion;

    let mut output = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
    let mut credentials = Some(TEST_CREDENTIALS.clone());

    let mut builder = context
        .initialize_security_context()
        .with_credentials_handle(&mut credentials)
        .with_context_requirements(ClientRequestFlags::empty())
        .with_target_data_representation(DataRepresentation::Native)
        .with_output(&mut output);

    assert!(context.initialize_security_context_impl(&mut builder).is_err());
    assert_eq!(context.state, NtlmState::Completion);
}

#[test]
fn initialize_security_context_wrong_state_final() {
    let mut context = Ntlm::new();
    context.state = NtlmState::Final;

    let mut output = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
    let mut credentials = Some(TEST_CREDENTIALS.clone());

    let mut builder = context
        .initialize_security_context()
        .with_credentials_handle(&mut credentials)
        .with_context_requirements(ClientRequestFlags::empty())
        .with_target_data_representation(DataRepresentation::Native)
        .with_output(&mut output);

    assert!(context.initialize_security_context_impl(&mut builder).is_err());
    assert_eq!(context.state, NtlmState::Final);
}

#[test]
fn initialize_security_context_writes_negotiate_message() {
    let mut context = Ntlm::new();

    context.state = NtlmState::Initial;

    let mut output = vec![SecurityBuffer::new(Vec::with_capacity(1024), BufferType::Token)];
    let mut credentials = Some(TEST_CREDENTIALS.clone());

    let mut builder = context
        .initialize_security_context()
        .with_credentials_handle(&mut credentials)
        .with_context_requirements(ClientRequestFlags::empty())
        .with_target_data_representation(DataRepresentation::Native)
        .with_output(&mut output);

    let result = context.initialize_security_context_impl(&mut builder).unwrap();

    assert_eq!(result.status, SecurityStatus::ContinueNeeded);
    let output = SecurityBuffer::find_buffer(&output, BufferType::Token).unwrap();
    assert_eq!(context.state, NtlmState::Challenge);
    assert!(!output.buffer.is_empty());
}

#[test]
fn initialize_security_context_reads_challenge_message() {
    let mut context = Ntlm::new();

    context.state = NtlmState::Challenge;
    context.negotiate_message = Some(NegotiateMessage::new(Vec::new()));

    let mut input = [SecurityBuffer::new(
        vec![
            0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x30, 0x00,
            0x00, 0x00, 0x97, 0x82, 0x88, 0xe0, 0xfe, 0x14, 0x51, 0x74, 0x06, 0x57, 0x92, 0x8a, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ],
        BufferType::Token,
    )];
    let mut output = vec![SecurityBuffer::new(Vec::with_capacity(1024), BufferType::Token)];
    let mut credentials = Some(TEST_CREDENTIALS.clone());

    let mut builder = context
        .initialize_security_context()
        .with_credentials_handle(&mut credentials)
        .with_context_requirements(ClientRequestFlags::empty())
        .with_target_data_representation(DataRepresentation::Native)
        .with_output(&mut output)
        .with_input(&mut input);

    let result = context.initialize_security_context_impl(&mut builder).unwrap();
    assert_eq!(result.status, SecurityStatus::Ok);
    assert_ne!(context.state, NtlmState::Challenge);
}

#[test]
fn initialize_security_context_writes_authenticate_message() {
    let mut context = Ntlm::new();
    context.state = NtlmState::Challenge;
    context.negotiate_message = Some(NegotiateMessage::new(Vec::new()));

    let mut input = [SecurityBuffer::new(
        vec![
            0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x30, 0x00,
            0x00, 0x00, 0x97, 0x82, 0x88, 0xe0, 0xfe, 0x14, 0x51, 0x74, 0x06, 0x57, 0x92, 0x8a, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ],
        BufferType::Token,
    )];
    let mut output = vec![SecurityBuffer::new(Vec::with_capacity(1024), BufferType::Token)];
    let mut credentials = Some(TEST_CREDENTIALS.clone());

    let mut builder = context
        .initialize_security_context()
        .with_credentials_handle(&mut credentials)
        .with_context_requirements(ClientRequestFlags::empty())
        .with_target_data_representation(DataRepresentation::Native)
        .with_output(&mut output)
        .with_input(&mut input);

    let result = context.initialize_security_context_impl(&mut builder).unwrap();

    assert_eq!(result.status, SecurityStatus::Ok);
    let output = SecurityBuffer::find_buffer(&output, BufferType::Token).unwrap();
    assert_eq!(context.state, NtlmState::Final);
    assert!(!output.buffer.is_empty());
}

#[test]
fn initialize_security_context_fails_on_empty_output_on_challenge_state() {
    let mut context = Ntlm::new();
    context.state = NtlmState::Challenge;

    let mut output = vec![SecurityBuffer::new(Vec::with_capacity(1024), BufferType::Token)];
    let mut credentials = Some(TEST_CREDENTIALS.clone());

    let mut builder = context
        .initialize_security_context()
        .with_credentials_handle(&mut credentials)
        .with_context_requirements(ClientRequestFlags::empty())
        .with_target_data_representation(DataRepresentation::Native)
        .with_output(&mut output);

    assert!(context.initialize_security_context_impl(&mut builder).is_err());
}

#[test]
fn accept_security_context_wrong_state_negotiate() {
    let mut context = Ntlm::new();
    context.state = NtlmState::Negotiate;

    let mut output = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
    let mut credentials = Some(TEST_CREDENTIALS.clone());
    let builder = context
        .accept_security_context()
        .with_credentials_handle(&mut credentials)
        .with_context_requirements(ServerRequestFlags::empty())
        .with_target_data_representation(DataRepresentation::Native)
        .with_output(&mut output);

    assert!(context.accept_security_context_impl(builder).is_err());
    assert_eq!(context.state, NtlmState::Negotiate);
}

#[test]
fn accept_security_context_wrong_state_challenge() {
    let mut context = Ntlm::new();
    context.state = NtlmState::Challenge;

    let mut output = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
    let mut credentials = Some(TEST_CREDENTIALS.clone());
    let builder = context
        .accept_security_context()
        .with_credentials_handle(&mut credentials)
        .with_context_requirements(ServerRequestFlags::empty())
        .with_target_data_representation(DataRepresentation::Native)
        .with_output(&mut output);

    assert!(context.accept_security_context_impl(builder).is_err());
    assert_eq!(context.state, NtlmState::Challenge);
}

#[test]
fn accept_security_context_wrong_state_completion() {
    let mut context = Ntlm::new();
    context.state = NtlmState::Completion;

    let mut output = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
    let mut credentials = Some(TEST_CREDENTIALS.clone());
    let builder = context
        .accept_security_context()
        .with_credentials_handle(&mut credentials)
        .with_context_requirements(ServerRequestFlags::empty())
        .with_target_data_representation(DataRepresentation::Native)
        .with_output(&mut output);

    assert!(context.accept_security_context_impl(builder).is_err());
    assert_eq!(context.state, NtlmState::Completion);
}

#[test]
fn accept_security_context_wrong_state_final() {
    let mut context = Ntlm::new();
    context.state = NtlmState::Final;

    let mut output = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
    let mut credentials = Some(TEST_CREDENTIALS.clone());
    let builder = context
        .accept_security_context()
        .with_credentials_handle(&mut credentials)
        .with_context_requirements(ServerRequestFlags::empty())
        .with_target_data_representation(DataRepresentation::Native)
        .with_output(&mut output);

    assert!(context.accept_security_context_impl(builder).is_err());
    assert_eq!(context.state, NtlmState::Final);
}

#[test]
fn accept_security_context_reads_negotiate_message() {
    let mut context = Ntlm::new();
    context.state = NtlmState::Initial;

    let mut input = [SecurityBuffer::new(
        vec![
            0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0x97, 0x82, 0x08, 0xe0, 0x00, 0x00,
            0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
        ],
        BufferType::Token,
    )];
    let mut output = vec![SecurityBuffer::new(Vec::with_capacity(1024), BufferType::Token)];
    let mut credentials = Some(TEST_CREDENTIALS.clone());
    let builder = context
        .accept_security_context()
        .with_credentials_handle(&mut credentials)
        .with_context_requirements(ServerRequestFlags::empty())
        .with_target_data_representation(DataRepresentation::Native)
        .with_output(&mut output)
        .with_input(&mut input);

    let result = context.accept_security_context_impl(builder).unwrap();
    assert_eq!(result.status, SecurityStatus::ContinueNeeded);
    assert_ne!(context.state, NtlmState::Challenge);
}

#[test]
fn accept_security_context_writes_challenge_message() {
    let mut context = Ntlm::new();
    context.state = NtlmState::Initial;

    let mut input = [SecurityBuffer::new(
        vec![
            0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0x97, 0x82, 0x08, 0xe0, 0x00, 0x00,
            0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
        ],
        BufferType::Token,
    )];
    let mut output = vec![SecurityBuffer::new(Vec::with_capacity(1024), BufferType::Token)];
    let mut credentials = Some(TEST_CREDENTIALS.clone());
    let builder = context
        .accept_security_context()
        .with_credentials_handle(&mut credentials)
        .with_context_requirements(ServerRequestFlags::empty())
        .with_target_data_representation(DataRepresentation::Native)
        .with_output(&mut output)
        .with_input(&mut input);

    let result = context.accept_security_context_impl(builder).unwrap();
    assert_eq!(result.status, SecurityStatus::ContinueNeeded);
    let output = SecurityBuffer::find_buffer(&output, BufferType::Token).unwrap();
    assert_eq!(context.state, NtlmState::Authenticate);
    assert!(!output.buffer.is_empty());
}

#[test]
fn accept_security_context_reads_authenticate() {
    let mut context = Ntlm::new();
    context.state = NtlmState::Authenticate;
    context.negotiate_message = Some(NegotiateMessage::new(vec![0x01, 0x02, 0x03]));
    context.challenge_message = Some(ChallengeMessage::new(
        vec![0x04, 0x05, 0x06],
        Vec::new(),
        [0x00; CHALLENGE_SIZE],
        0,
    ));

    let mut input = [SecurityBuffer::new(
        vec![
            0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, // signature
            0x03, 0x00, 0x00, 0x00, // message type
            0x18, 0x00, 0x18, 0x00, 0x55, 0x00, 0x00, 0x00, // LmChallengeResponseFields
            0x30, 0x00, 0x30, 0x00, 0x6d, 0x00, 0x00, 0x00, // NtChallengeResponseFields
            0x06, 0x00, 0x06, 0x00, 0x40, 0x00, 0x00, 0x00, // DomainNameFields
            0x04, 0x00, 0x04, 0x00, 0x46, 0x00, 0x00, 0x00, // UserNameFields
            0x0b, 0x00, 0x0b, 0x00, 0x4a, 0x00, 0x00, 0x00, // WorkstationFields
            0x10, 0x00, 0x10, 0x00, 0x9d, 0x00, 0x00, 0x00, // EncryptedRandomSessionKeyFields
            0x35, 0xb2, 0x08, 0xe0, // NegotiateFlags
            0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, // domain
            0x55, 0x73, 0x65, 0x72, // user
            0x57, 0x6f, 0x72, 0x6b, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, // workstation
            0x13, 0x23, 0x04, 0xd8, 0x5f, 0x66, 0x52, 0xce, 0x41, 0xd6, 0xa9, 0x98, 0xf6, 0xbc, 0x73, 0x1b, 0x04, 0xd8,
            0x5f, 0x41, 0xd6, 0xa9, 0x5f, 0x66, // lm challenge
            0x1f, 0x7b, 0x1d, 0x2a, 0x15, 0xf5, 0x5d, 0x95, 0xc3, 0xce, 0x90, 0xbd, 0x10, 0x1e, 0xe3, 0xa8, 0x01, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x57, 0xbd, 0xb1, 0x07, 0x8b, 0xcf, 0x01, 0x20, 0xc0, 0x2b, 0x3d,
            0xc0, 0x61, 0xa7, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // nt challenge
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, // encrypted key
        ],
        BufferType::Token,
    )];
    let mut output = vec![SecurityBuffer::new(Vec::with_capacity(1024), BufferType::Token)];
    let mut credentials = Some(TEST_CREDENTIALS.clone());
    let builder = context
        .accept_security_context()
        .with_credentials_handle(&mut credentials)
        .with_context_requirements(ServerRequestFlags::empty())
        .with_target_data_representation(DataRepresentation::Native)
        .with_output(&mut output)
        .with_input(&mut input);

    let result = context.accept_security_context_impl(builder).unwrap();
    assert_eq!(result.status, SecurityStatus::CompleteNeeded);
    assert_eq!(context.state, NtlmState::Completion);
}

#[test]
fn accept_security_context_fails_on_empty_output_on_negotiate_state() {
    let mut context = Ntlm::new();

    context.state = NtlmState::Initial;

    let mut output = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
    let mut credentials = Some(TEST_CREDENTIALS.clone());
    let builder = context
        .accept_security_context()
        .with_credentials_handle(&mut credentials)
        .with_context_requirements(ServerRequestFlags::empty())
        .with_target_data_representation(DataRepresentation::Native)
        .with_output(&mut output);

    assert!(context.accept_security_context_impl(builder).is_err());
}

#[test]
fn complete_auth_token_fails_on_incorrect_state() {
    let mut context = Ntlm::new();
    context.state = NtlmState::Authenticate;

    assert!(context.complete_auth_token(&mut []).is_err());
}

#[test]
fn complete_auth_token_changes_state() {
    let mut context = Ntlm::new();
    context.flags = NegotiateFlags::NTLM_SSP_NEGOTIATE_KEY_EXCH;
    context.state = NtlmState::Completion;
    context.identity = Some(TEST_CREDENTIALS.clone());
    context.allowed_identities = Some(vec![TEST_CREDENTIALS.clone()]);
    context.negotiate_message = Some(NegotiateMessage::new(vec![0x01, 0x02, 0x03]));
    context.challenge_message = Some(ChallengeMessage::new(
        vec![0x04, 0x05, 0x06],
        Vec::new(),
        [0x00; CHALLENGE_SIZE],
        0,
    ));
    context.authenticate_message = Some(AuthenticateMessage::new(
        vec![
            0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x03, 0x00, 0x00, 0x00, 0x18, 0x00, 0x18, 0x00, 0x98, 0x00,
            0x00, 0x00, 0x7a, 0x01, 0x7a, 0x01, 0xb0, 0x00, 0x00, 0x00, 0x16, 0x00, 0x16, 0x00, 0x58, 0x00, 0x00, 0x00,
            0x1a, 0x00, 0x1a, 0x00, 0x6e, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00, 0x88, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x10, 0x00, 0x2a, 0x02, 0x00, 0x00, 0x35, 0x82, 0x88, 0xe2, 0x06, 0x01, 0xb0, 0x1d, 0x00, 0x00, 0x00, 0x0f,
            0x12, 0x28, 0x00, 0xa0, 0xb2, 0x29, 0x47, 0x12, 0x1e, 0x8e, 0x54, 0xf8, 0x29, 0xdb, 0x52, 0x1e, 0x41, 0x00,
            0x57, 0x00, 0x41, 0x00, 0x4b, 0x00, 0x45, 0x00, 0x43, 0x00, 0x4f, 0x00, 0x44, 0x00, 0x49, 0x00, 0x4e, 0x00,
            0x47, 0x00, 0x41, 0x00, 0x64, 0x00, 0x6d, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x69, 0x00, 0x73, 0x00, 0x74, 0x00,
            0x72, 0x00, 0x61, 0x00, 0x74, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x57, 0x00, 0x49, 0x00, 0x4e, 0x00, 0x44, 0x00,
            0x4f, 0x00, 0x57, 0x00, 0x53, 0x00, 0x37, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf5, 0x61, 0x4e, 0x2f,
            0x00, 0xd0, 0x15, 0xb0, 0x70, 0xb0, 0x3e, 0x82, 0x91, 0x5f, 0xc7, 0x08, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x20, 0xfd, 0xae, 0x48, 0x07, 0xcb, 0xcb, 0x01, 0xa5, 0x00, 0x28, 0x29, 0xcd, 0x07, 0xe3, 0xbc,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x16, 0x00, 0x41, 0x00, 0x57, 0x00, 0x41, 0x00, 0x4b, 0x00, 0x45, 0x00,
            0x43, 0x00, 0x4f, 0x00, 0x44, 0x00, 0x49, 0x00, 0x4e, 0x00, 0x47, 0x00, 0x01, 0x00, 0x10, 0x00, 0x57, 0x00,
            0x49, 0x00, 0x4e, 0x00, 0x32, 0x00, 0x4b, 0x00, 0x38, 0x00, 0x52, 0x00, 0x32, 0x00, 0x04, 0x00, 0x24, 0x00,
            0x61, 0x00, 0x77, 0x00, 0x61, 0x00, 0x6b, 0x00, 0x65, 0x00, 0x63, 0x00, 0x6f, 0x00, 0x64, 0x00, 0x69, 0x00,
            0x6e, 0x00, 0x67, 0x00, 0x2e, 0x00, 0x61, 0x00, 0x74, 0x00, 0x68, 0x00, 0x2e, 0x00, 0x63, 0x00, 0x78, 0x00,
            0x03, 0x00, 0x36, 0x00, 0x57, 0x00, 0x49, 0x00, 0x4e, 0x00, 0x32, 0x00, 0x4b, 0x00, 0x38, 0x00, 0x52, 0x00,
            0x32, 0x00, 0x2e, 0x00, 0x61, 0x00, 0x77, 0x00, 0x61, 0x00, 0x6b, 0x00, 0x65, 0x00, 0x63, 0x00, 0x6f, 0x00,
            0x64, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x67, 0x00, 0x2e, 0x00, 0x61, 0x00, 0x74, 0x00, 0x68, 0x00, 0x2e, 0x00,
            0x63, 0x00, 0x78, 0x00, 0x05, 0x00, 0x24, 0x00, 0x61, 0x00, 0x77, 0x00, 0x61, 0x00, 0x6b, 0x00, 0x65, 0x00,
            0x63, 0x00, 0x6f, 0x00, 0x64, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x67, 0x00, 0x2e, 0x00, 0x61, 0x00, 0x74, 0x00,
            0x68, 0x00, 0x2e, 0x00, 0x63, 0x00, 0x78, 0x00, 0x07, 0x00, 0x08, 0x00, 0x20, 0xfd, 0xae, 0x48, 0x07, 0xcb,
            0xcb, 0x01, 0x06, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x30, 0x00, 0x30, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x7b, 0xd0, 0x9e, 0x33, 0x06, 0x75,
            0xe3, 0x3e, 0x52, 0x7b, 0x4a, 0xc4, 0x75, 0x5f, 0x9b, 0x98, 0x26, 0x5d, 0xcb, 0x05, 0x6a, 0x6a, 0xcc, 0x0f,
            0xb8, 0x4f, 0xab, 0x09, 0x22, 0x30, 0x7a, 0x5d, 0x0a, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x2a, 0x00, 0x54, 0x00, 0x45, 0x00,
            0x52, 0x00, 0x4d, 0x00, 0x53, 0x00, 0x52, 0x00, 0x56, 0x00, 0x2f, 0x00, 0x31, 0x00, 0x39, 0x00, 0x32, 0x00,
            0x2e, 0x00, 0x31, 0x00, 0x36, 0x00, 0x38, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x35, 0x00,
            0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x57, 0xc6, 0xb5,
            0x0c, 0x14, 0xc1, 0xf0, 0x64, 0xe7, 0xcc, 0x8b, 0xf0, 0x6d, 0x7a, 0x13,
        ],
        Some(Mic::new(
            [
                0xcf, 0x40, 0x63, 0x95, 0xcf, 0xe2, 0x50, 0x4d, 0xbb, 0x1f, 0x7b, 0x3e, 0x7, 0xd4, 0xb6, 0x49,
            ],
            64,
        )),
        vec![
            0x02, 0x00, 0x16, 0x00, 0x41, 0x00, 0x57, 0x00, 0x41, 0x00, 0x4b, 0x00, 0x45, 0x00, 0x43, 0x00, 0x4f, 0x00,
            0x44, 0x00, 0x49, 0x00, 0x4e, 0x00, 0x47, 0x00, 0x01, 0x00, 0x10, 0x00, 0x57, 0x00, 0x49, 0x00, 0x4e, 0x00,
            0x32, 0x00, 0x4b, 0x00, 0x38, 0x00, 0x52, 0x00, 0x32, 0x00, 0x04, 0x00, 0x24, 0x00, 0x61, 0x00, 0x77, 0x00,
            0x61, 0x00, 0x6b, 0x00, 0x65, 0x00, 0x63, 0x00, 0x6f, 0x00, 0x64, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x67, 0x00,
            0x2e, 0x00, 0x61, 0x00, 0x74, 0x00, 0x68, 0x00, 0x2e, 0x00, 0x63, 0x00, 0x78, 0x00, 0x03, 0x00, 0x36, 0x00,
            0x57, 0x00, 0x49, 0x00, 0x4e, 0x00, 0x32, 0x00, 0x4b, 0x00, 0x38, 0x00, 0x52, 0x00, 0x32, 0x00, 0x2e, 0x00,
            0x61, 0x00, 0x77, 0x00, 0x61, 0x00, 0x6b, 0x00, 0x65, 0x00, 0x63, 0x00, 0x6f, 0x00, 0x64, 0x00, 0x69, 0x00,
            0x6e, 0x00, 0x67, 0x00, 0x2e, 0x00, 0x61, 0x00, 0x74, 0x00, 0x68, 0x00, 0x2e, 0x00, 0x63, 0x00, 0x78, 0x00,
            0x05, 0x00, 0x24, 0x00, 0x61, 0x00, 0x77, 0x00, 0x61, 0x00, 0x6b, 0x00, 0x65, 0x00, 0x63, 0x00, 0x6f, 0x00,
            0x64, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x67, 0x00, 0x2e, 0x00, 0x61, 0x00, 0x74, 0x00, 0x68, 0x00, 0x2e, 0x00,
            0x63, 0x00, 0x78, 0x00, 0x07, 0x00, 0x08, 0x00, 0x20, 0xfd, 0xae, 0x48, 0x07, 0xcb, 0xcb, 0x01, 0x06, 0x00,
            0x04, 0x00, 0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x30, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x7b, 0xd0, 0x9e, 0x33, 0x06, 0x75, 0xe3, 0x3e, 0x52, 0x7b,
            0x4a, 0xc4, 0x75, 0x5f, 0x9b, 0x98, 0x26, 0x5d, 0xcb, 0x05, 0x6a, 0x6a, 0xcc, 0x0f, 0xb8, 0x4f, 0xab, 0x09,
            0x22, 0x30, 0x7a, 0x5d, 0x0a, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x2a, 0x00, 0x54, 0x00, 0x45, 0x00, 0x52, 0x00, 0x4d, 0x00,
            0x53, 0x00, 0x52, 0x00, 0x56, 0x00, 0x2f, 0x00, 0x31, 0x00, 0x39, 0x00, 0x32, 0x00, 0x2e, 0x00, 0x31, 0x00,
            0x36, 0x00, 0x38, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x35, 0x00, 0x30, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        [0xa5, 0x00, 0x28, 0x29, 0xcd, 0x07, 0xe3, 0xbc],
        Some([
            0x0c, 0x57, 0xc6, 0xb5, 0x0c, 0x14, 0xc1, 0xf0, 0x64, 0xe7, 0xcc, 0x8b, 0xf0, 0x6d, 0x7a, 0x13,
        ]),
    ));

    context.complete_auth_token(&mut []).unwrap();
    assert_eq!(context.state, NtlmState::Final);
}

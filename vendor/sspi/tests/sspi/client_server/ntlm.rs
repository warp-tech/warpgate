use sspi::builders::{AcquireCredentialsHandle, WithoutCredentialUse};
use sspi::credssp::SspiContext;
use sspi::ntlm::NtlmConfig;
use sspi::{
    AcquireCredentialsHandleResult, AuthIdentity, BufferType, ClientRequestFlags, CredentialUse, Credentials,
    DataRepresentation, EncryptionFlags, InitializeSecurityContextResult, Ntlm, Secret, SecurityBuffer,
    SecurityBufferFlags, SecurityBufferRef, SecurityStatus, ServerRequestFlags, Sspi, Username,
};

use crate::client_server::{TARGET_NAME, test_encryption, test_rpc_request_encryption, test_stream_buffer_encryption};

// Simulates readonly buffers encryption. In that case, the NTLM security package should not encrypt the data,
// but instead compute the checksum and write into the token buffer.
//
// More info: https://github.com/Devolutions/sspi-rs/pull/629.
//
// This is supported only by NTLM security package and do not implemented for Kerberos.
fn test_readonly_buffers_encryption(client: &mut SspiContext, server: &mut SspiContext) {
    let plain_message = b"Devolutions/sspi-rs";

    let mut token = [0; 1024];
    let mut data_1 = plain_message.to_vec();
    let mut data_2 = plain_message.to_vec();

    let mut message = vec![
        SecurityBufferRef::token_buf(token.as_mut_slice()),
        SecurityBufferRef::data_buf(data_1.as_mut_slice()).with_flags(SecurityBufferFlags::SECBUFFER_READONLY),
        SecurityBufferRef::data_buf(data_2.as_mut_slice())
            .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
    ];

    client.encrypt_message(EncryptionFlags::empty(), &mut message).unwrap();

    // Make sure that readonly buffers was not encrypted.
    assert_eq!(plain_message, message[1].data());
    assert_eq!(plain_message, message[2].data());

    server.decrypt_message(&mut message).unwrap();

    assert_eq!(plain_message, message[1].data());
    assert_eq!(plain_message, message[2].data());
}

fn run_ntlm(config: NtlmConfig, target_name: Option<&str>, username: &str, password: &str) {
    let credentials = Credentials::AuthIdentity(AuthIdentity {
        username: Username::parse(username).unwrap(),
        password: Secret::from(password.to_owned()),
    });

    let mut client = SspiContext::Ntlm(Ntlm::with_config(config.clone()));
    let mut server = SspiContext::Ntlm(Ntlm::with_config(config));

    let builder = AcquireCredentialsHandle::<'_, _, _, WithoutCredentialUse>::new();
    let AcquireCredentialsHandleResult {
        credentials_handle: mut client_credentials_handle,
        ..
    } = builder
        .with_auth_data(&credentials)
        .with_credential_use(CredentialUse::Outbound)
        .execute(&mut client)
        .unwrap();

    let builder = AcquireCredentialsHandle::<'_, _, _, WithoutCredentialUse>::new();
    let AcquireCredentialsHandleResult {
        credentials_handle: mut server_credentials_handle,
        ..
    } = builder
        .with_auth_data(&credentials)
        .with_credential_use(CredentialUse::Inbound)
        .execute(&mut server)
        .unwrap();

    let mut input_token = [SecurityBuffer::new(Vec::new(), BufferType::Token)];
    let mut output_token = [SecurityBuffer::new(Vec::new(), BufferType::Token)];

    for _ in 0..3 {
        let mut builder = client
            .initialize_security_context()
            .with_credentials_handle(&mut client_credentials_handle)
            .with_context_requirements(
                ClientRequestFlags::MUTUAL_AUTH
                    | ClientRequestFlags::USE_SESSION_KEY
                    | ClientRequestFlags::INTEGRITY
                    | ClientRequestFlags::CONFIDENTIALITY,
            )
            .with_target_data_representation(DataRepresentation::Native)
            .with_input(&mut input_token)
            .with_output(&mut output_token);
        builder.target_name = target_name;
        let InitializeSecurityContextResult { status, .. } =
            client.initialize_security_context_sync(&mut builder).unwrap();

        input_token[0].buffer.clear();

        let builder = server
            .accept_security_context()
            .with_credentials_handle(&mut server_credentials_handle)
            .with_context_requirements(ServerRequestFlags::empty())
            .with_target_data_representation(DataRepresentation::Native)
            .with_input(&mut output_token)
            .with_output(&mut input_token);
        server.accept_security_context_sync(builder).unwrap();

        output_token[0].buffer.clear();

        if status == SecurityStatus::Ok {
            test_encryption(&mut client, &mut server);
            test_stream_buffer_encryption(&mut client, &mut server);
            test_rpc_request_encryption(&mut client, &mut server);
            test_readonly_buffers_encryption(&mut client, &mut server);
            return;
        }
    }

    panic!("NTLM authentication should not exceed 3 steps")
}

#[test]
fn ntlm_with_computer_name() {
    run_ntlm(
        NtlmConfig {
            client_computer_name: Some("DESKTOP-3D83IAN.example.com".to_owned()),
        },
        Some(TARGET_NAME),
        "test_user",
        "test_password",
    );
}

#[test]
fn ntlm_without_computer_name() {
    run_ntlm(
        NtlmConfig {
            client_computer_name: None,
        },
        Some(TARGET_NAME),
        "test_user",
        "test_password",
    );
}

#[test]
fn ntlm_guest_logon() {
    run_ntlm(
        NtlmConfig {
            client_computer_name: None,
        },
        Some("cifs/DESKTOP-8F33RFH.example.com"),
        "/GUEST",
        "",
    );
}

#[test]
fn ntlm_without_target_name() {
    run_ntlm(
        NtlmConfig {
            client_computer_name: None,
        },
        None,
        "test_user",
        "test_password",
    );
}

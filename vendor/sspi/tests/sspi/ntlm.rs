use sspi::Ntlm;

use crate::common::{
    CREDENTIALS, CredentialsProxyImpl, check_messages_encryption, create_client_credentials_handle,
    create_server_credentials_handle, process_authentication_without_complete,
    set_identity_and_try_complete_authentication, try_complete_authentication,
};

#[test]
fn successful_ntlm_authentication_with_client_auth_data() {
    let mut credentials_proxy = CredentialsProxyImpl::new(&CREDENTIALS);

    let mut client = Ntlm::new();
    let client_credentials_handle = create_client_credentials_handle(&mut client, Some(&*CREDENTIALS)).unwrap();

    let mut server = Ntlm::new();
    let server_credentials_handle = create_server_credentials_handle(&mut server).unwrap();

    let (client_status, server_status) = process_authentication_without_complete(
        &mut client,
        client_credentials_handle,
        &mut server,
        server_credentials_handle,
    )
    .unwrap();
    try_complete_authentication(&mut client, client_status).unwrap();
    set_identity_and_try_complete_authentication(&mut server, server_status, &mut credentials_proxy).unwrap();

    check_messages_encryption(&mut client, &mut server).unwrap();
}

mod nt_hash {
    use md4::{Digest, Md4};
    use sspi::ntlm::Ntlm;
    use sspi::{AuthIdentityBuffers, NtlmHash, Sspi, SspiImpl};

    /// Password: "Password123!" -> NT hash: 2B576ACBE6BCFDA7294D6BD18041B8FE
    const TEST_NT_HASH: &str = "2B576ACBE6BCFDA7294D6BD18041B8FE";
    const TEST_USERNAME: &str = "testuser";
    const TEST_DOMAIN: &str = "TESTDOMAIN";

    fn password_to_ntlm_hash(password: &str) -> [u8; 16] {
        let utf16_password: Vec<u8> = password.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

        let mut hasher = Md4::new();
        hasher.update(&utf16_password);
        let result = hasher.finalize();
        let mut hash = [0u8; 16];
        hash.copy_from_slice(&result);
        hash
    }

    #[test]
    fn test_ntlm_negotiate_with_hash() {
        let nt_hash: NtlmHash = TEST_NT_HASH.try_into().expect("valid hash");

        assert_eq!(nt_hash.as_bytes(), &password_to_ntlm_hash("Password123!"));

        let credentials = AuthIdentityBuffers::from_utf8_with_hash(TEST_USERNAME, TEST_DOMAIN, &nt_hash);

        let mut ntlm = Ntlm::with_auth_identity(Some(credentials.clone()), Default::default());

        let mut output = vec![sspi::SecurityBuffer::new(Vec::new(), sspi::BufferType::Token)];

        let mut binding = Some(credentials.clone());

        let mut builder = ntlm
            .initialize_security_context()
            .with_credentials_handle(&mut binding)
            .with_context_requirements(sspi::ClientRequestFlags::CONFIDENTIALITY)
            .with_target_data_representation(sspi::DataRepresentation::Native)
            .with_output(&mut output);

        let result = ntlm.initialize_security_context_impl(&mut builder);

        // Should succeed in creating NEGOTIATE message
        assert!(result.is_ok(), "Failed to create NEGOTIATE message: {result:?}");
        let result = result.unwrap().resolve_to_result().unwrap();
        assert_eq!(result.status, sspi::SecurityStatus::ContinueNeeded);
        assert!(!output[0].buffer.is_empty(), "NEGOTIATE token should not be empty");
    }
}

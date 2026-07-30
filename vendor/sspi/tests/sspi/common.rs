use std::io;
use std::sync::LazyLock;

use sspi::{
    AcquireCredentialsHandleResult, AuthIdentity, BufferType, ClientRequestFlags, ContextNames, CredentialUse,
    DataRepresentation, EncryptionFlags, SecurityBuffer, SecurityBufferRef, SecurityStatus, ServerRequestFlags, Sspi,
    SspiEx, Username, credssp,
};
use time::OffsetDateTime;

pub(crate) static CREDENTIALS: LazyLock<AuthIdentity> = LazyLock::new(|| AuthIdentity {
    username: Username::new("Username", Some("Domain")).unwrap(),
    password: String::from("Password").into(),
});

const MESSAGE_TO_CLIENT: &[u8] = b"Hello, client!";

pub(crate) struct CredentialsProxyImpl<'a> {
    credentials: &'a AuthIdentity,
}

impl<'a> CredentialsProxyImpl<'a> {
    pub(crate) fn new(credentials: &'a AuthIdentity) -> Self {
        Self { credentials }
    }
}

impl credssp::CredentialsProxy for CredentialsProxyImpl<'_> {
    type AuthenticationData = AuthIdentity;

    fn auth_data_by_user(&mut self, username: &Username) -> io::Result<Self::AuthenticationData> {
        assert_eq!(username.account_name(), self.credentials.username.account_name());

        Ok(self.credentials.clone())
    }

    fn auth_data(&mut self) -> io::Result<Vec<Self::AuthenticationData>> {
        Ok(vec![self.credentials.clone()])
    }
}

pub(crate) fn create_client_credentials_handle<T>(
    client: &mut T,
    auth_data: Option<&T::AuthenticationData>,
) -> sspi::Result<T::CredentialsHandle>
where
    T: Sspi,
{
    let AcquireCredentialsHandleResult {
        credentials_handle,
        expiry,
    } = if let Some(auth_data) = auth_data {
        client
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(auth_data)
            .execute(client)?
    } else {
        client
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .execute(client)?
    };

    if let Some(expiry) = expiry {
        let now = OffsetDateTime::now_utc();
        assert!(now < expiry);
    }

    Ok(credentials_handle)
}

pub(crate) fn create_server_credentials_handle<T>(server: &mut T) -> sspi::Result<T::CredentialsHandle>
where
    T: Sspi,
{
    let AcquireCredentialsHandleResult {
        credentials_handle,
        expiry,
    } = server
        .acquire_credentials_handle()
        .with_credential_use(CredentialUse::Inbound)
        .execute(server)?;
    if let Some(expiry) = expiry {
        let now = OffsetDateTime::now_utc();
        assert!(now < expiry);
    }

    Ok(credentials_handle)
}

pub(crate) fn process_authentication_without_complete<ClientSspi, ServerSspi>(
    client: &mut ClientSspi,
    mut client_creds_handle: ClientSspi::CredentialsHandle,
    server: &mut ServerSspi,
    mut server_creds_handle: ServerSspi::CredentialsHandle,
) -> sspi::Result<(SecurityStatus, SecurityStatus)>
where
    ClientSspi: Sspi,
    ServerSspi: Sspi,
{
    let mut server_output = Vec::new();
    let mut client_status;
    let mut server_status = SecurityStatus::ContinueNeeded;

    loop {
        let mut client_output = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];

        let mut builder = client
            .initialize_security_context()
            .with_credentials_handle(&mut client_creds_handle)
            .with_context_requirements(ClientRequestFlags::ALLOCATE_MEMORY | ClientRequestFlags::CONFIDENTIALITY)
            .with_target_data_representation(DataRepresentation::Native)
            .with_input(&mut server_output)
            .with_output(&mut client_output);

        let client_result = client
            .initialize_security_context_impl(&mut builder)?
            .resolve_to_result()?;
        client_status = client_result.status;

        if client_status != SecurityStatus::ContinueNeeded && server_status != SecurityStatus::ContinueNeeded {
            return Ok((client_status, server_status));
        }

        server_output = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];

        let builder = server
            .accept_security_context()
            .with_credentials_handle(&mut server_creds_handle)
            .with_context_requirements(ServerRequestFlags::ALLOCATE_MEMORY)
            .with_target_data_representation(DataRepresentation::Native)
            .with_input(&mut client_output)
            .with_output(&mut server_output);
        let server_result = server.accept_security_context_impl(builder)?.resolve_to_result()?;
        server_status = server_result.status;

        if client_status != SecurityStatus::ContinueNeeded && server_status != SecurityStatus::ContinueNeeded {
            return Ok((client_status, server_status));
        }
    }
}

pub(crate) fn try_complete_authentication<T>(server: &mut T, auth_server_status: SecurityStatus) -> sspi::Result<()>
where
    T: Sspi,
{
    if auth_server_status == SecurityStatus::CompleteNeeded || auth_server_status == SecurityStatus::CompleteAndContinue
    {
        let mut token = Vec::new();
        server.complete_auth_token(&mut token)?;
    }

    Ok(())
}

pub(crate) fn set_identity_and_try_complete_authentication<T, C>(
    server: &mut T,
    auth_server_status: SecurityStatus,
    credentials_proxy: &mut C,
) -> sspi::Result<()>
where
    T: Sspi + SspiEx,
    C: credssp::CredentialsProxy<AuthenticationData = T::AuthenticationData>,
{
    if auth_server_status == SecurityStatus::CompleteNeeded || auth_server_status == SecurityStatus::CompleteAndContinue
    {
        let ContextNames { username } = server.query_context_names()?;
        let auth_data = credentials_proxy.auth_data_by_user(&username)?;
        server.custom_set_auth_identity(auth_data).unwrap();

        let mut token = Vec::new();
        server.complete_auth_token(&mut token)?;
    }

    Ok(())
}

pub(crate) fn check_messages_encryption(client: &mut impl Sspi, server: &mut impl Sspi) -> sspi::Result<()> {
    let server_sizes = server.query_context_sizes()?;

    let mut token = vec![0; server_sizes.security_trailer as usize];
    let mut data = MESSAGE_TO_CLIENT.to_vec();
    let mut messages = [
        SecurityBufferRef::token_buf(token.as_mut_slice()),
        SecurityBufferRef::data_buf(data.as_mut_slice()),
    ];
    server.encrypt_message(EncryptionFlags::empty(), &mut messages)?;
    assert_ne!(MESSAGE_TO_CLIENT, messages[1].data());

    println!(
        "Message to client: {:x?}, encrypted message: {:x?}, token: {:x?}",
        MESSAGE_TO_CLIENT,
        messages[0].data(),
        messages[1].data()
    );

    let [mut token, mut data] = messages;

    let mut messages = vec![
        SecurityBufferRef::data_buf(data.take_data()),
        SecurityBufferRef::token_buf(token.take_data()),
    ];

    client.decrypt_message(&mut messages)?;

    assert_eq!(MESSAGE_TO_CLIENT, messages[0].data());

    Ok(())
}

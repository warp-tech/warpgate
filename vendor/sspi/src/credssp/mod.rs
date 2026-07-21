#[cfg(feature = "tsssp")]
pub mod sspi_cred_ssp;
mod ts_request;

use std::io;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use rand::rngs::{StdRng, SysRng};
use rand_core::{Rng as _, SeedableRng as _};
use ts_request::{NONCE_SIZE, TS_REQUEST_VERSION};
pub use ts_request::{NStatusCode, TsRequest, read_ts_credentials, write_ts_credentials};

#[cfg(feature = "tsssp")]
use self::sspi_cred_ssp::SspiCredSsp;
use crate::builders::{AcquireCredentialsHandle, ChangePassword, WithoutCredentialUse};
use crate::crypto::compute_sha256;
use crate::generator::{
    Generator, GeneratorAcceptSecurityContext, GeneratorChangePassword, GeneratorInitSecurityContext, NetworkRequest,
    YieldPointLocal,
};
use crate::kerberos::{self, Kerberos};
use crate::ntlm::{self, Ntlm, NtlmConfig, SIGNATURE_SIZE};
use crate::pku2u::{self, Pku2u, Pku2uConfig};
use crate::{
    AcceptSecurityContextResult, AcquireCredentialsHandleResult, AuthIdentity, AuthIdentityBuffers, BufferType,
    CertContext, CertTrustStatus, ClientRequestFlags, ConnectionInfo, ContextNames, ContextSizes, CredentialUse,
    Credentials, CredentialsBuffers, DataRepresentation, DecryptionFlags, EncryptionFlags, Error, ErrorKind,
    FilledAcceptSecurityContext, FilledAcquireCredentialsHandle, FilledInitializeSecurityContext,
    InitializeSecurityContextResult, Negotiate, NegotiateConfig, PackageInfo, SecurityBuffer, SecurityBufferRef,
    SecurityStatus, ServerRequestFlags, Sspi, SspiEx, SspiImpl, StreamSizes, Username, negotiate,
};

pub const EARLY_USER_AUTH_RESULT_PDU_SIZE: usize = 4;

const HASH_MAGIC_LEN: usize = 38;
const SERVER_CLIENT_HASH_MAGIC: &[u8; HASH_MAGIC_LEN] = b"CredSSP Server-To-Client Binding Hash\0";
const CLIENT_SERVER_HASH_MAGIC: &[u8; HASH_MAGIC_LEN] = b"CredSSP Client-To-Server Binding Hash\0";

/// Provides an interface for implementing proxy credentials structures.
pub trait CredentialsProxy {
    type AuthenticationData;

    /// A method signature for implementing a behavior of searching and returning
    /// a user password based on a username and a domain provided as arguments.
    ///
    /// # Arguments
    ///
    /// * `username` - The username in UPN or Down-Level Logon Name format
    fn auth_data_by_user(&mut self, username: &Username) -> io::Result<Self::AuthenticationData>;

    /// Return all candidate credentials for this user.
    ///
    /// When multiple credentials are returned, the NTLM verifier will try each
    /// one until it finds a match (or rejects if none match).
    ///
    /// # Security considerations
    ///
    /// Candidates should represent a bounded set of currently-valid credentials
    /// (e.g., TTL-bound tokens, or "current + previous" within a defined grace
    /// period), not an unbounded history. Implementations should cap the number
    /// of candidates and ensure existing rate-limiting / lockout behavior remains
    /// effective, so that multi-credential verification does not multiply online
    /// guessing attempts. This mechanism is for selection among multiple valid
    /// credentials, not for weakening a policy that intends immediate
    /// invalidation.
    ///
    /// The default implementation wraps the single result from `auth_data_by_user`.
    fn auth_data_candidates_by_user(&mut self, username: &Username) -> io::Result<Vec<Self::AuthenticationData>> {
        Ok(vec![self.auth_data_by_user(username)?])
    }

    /// A method signature for implementing a behavior of searching and returning
    /// all available authentication data.
    fn auth_data(&mut self) -> io::Result<Vec<Self::AuthenticationData>>;
}

macro_rules! try_cred_ssp_server {
    ($e:expr, $ts_request:ident) => {
        match $e {
            Ok(v) => v,
            Err(e) => {
                let error = crate::Error::from(e);
                $ts_request.error_code = Some(construct_error(&error));

                return Err(ServerError {
                    ts_request: Some(Box::new($ts_request)),
                    error,
                });
            }
        }
    };
}

/// Indicates to the `CredSspClient` whether or not to transfer
/// the credentials in the auth_info `TsRequest` field.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum CredSspMode {
    WithCredentials,
    /// Indicates that the client requires credential-less logon over CredSSP (also known as "restricted admin mode").
    CredentialLess,
}

/// The result of a CredSSP client processing.
#[derive(Debug, Clone)]
pub enum ClientState {
    /// Used as a result of processing of negotiation tokens.
    ReplyNeeded(TsRequest),
    /// Used as a result of processing of authentication info.
    FinalMessage(TsRequest),
}

/// The result of a CredSSP server processing.
#[derive(Debug, Clone)]
pub enum ServerState {
    /// Used as a result of processing of negotiation tokens.
    ReplyNeeded(TsRequest),
    /// Used as a result of the final state. Contains result of processing of authentication info.
    Finished(AuthIdentity),
}

/// The error of a CredSSP server processing.
/// Contains `TsRequest` with non-empty `error_code`, and the error which caused the server to fail.
#[derive(Debug, Clone)]
pub struct ServerError {
    pub ts_request: Option<Box<TsRequest>>,
    pub error: Error,
}

/// The Early User Authorization Result PDU is sent from server to client
/// and is used to convey authorization information to the client.
/// This PDU is only sent by the server if the client advertised support for it
/// by specifying the ['HYBRID_EX protocol'](struct.SecurityProtocol.htlm)
/// of the [RDP Negotiation Request (RDP_NEG_REQ)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/902b090b-9cb3-4efc-92bf-ee13373371e3)
/// and it MUST be sent immediately after the CredSSP handshake has completed.
#[derive(Debug, Copy, Clone, FromPrimitive, ToPrimitive)]
#[repr(u32)]
pub enum EarlyUserAuthResult {
    /// The user has permission to access the server.
    Success = 0,
    /// The user does not have permission to access the server.
    AccessDenied = 5,
}

impl EarlyUserAuthResult {
    pub fn from_buffer(mut stream: impl io::Read) -> Result<Self, io::Error> {
        let result = stream.read_u32::<LittleEndian>()?;

        EarlyUserAuthResult::from_u32(result).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("got invalid Early User Authorization Result: {result:x}"),
            )
        })
    }
    pub fn to_buffer(self, mut stream: impl io::Write) -> Result<(), io::Error> {
        stream.write_u32::<LittleEndian>(self.to_u32().unwrap())
    }
    pub fn buffer_len(self) -> usize {
        EARLY_USER_AUTH_RESULT_PDU_SIZE
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum CredSspState {
    NegoToken,
    AuthInfo,
    PubKeyInfo,
    Final,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum EndpointType {
    Client,
    Server,
}

/// CredSSP client authentication protocol.
///
/// From MSDN: [1.3 Overview](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/e36b36f6-edf4-4df1-9905-9e53b7d7c7b7):
/// > The CredSSP Protocol then uses the Simple and Protected Generic Security Service Application Program Interface Negotiation Mechanism (SPNEGO)
/// > to authenticate the user and server in the encrypted TLS session.
/// > SPNEGO provides a framework for two parties that are engaged in authentication to select from a set of
/// > possible authentication mechanisms. This framework provides selection in a manner that preserves
/// > the opaque nature of the security protocols to the application protocol that uses SPNEGO. In this case,
/// > the CredSSP Protocol is the application protocol that uses SPNEGO.
///
/// According to the specification, we should always use the Negotiate security package in CredSSP.
/// However, mstsc and other RDP clients send plain NTLM messages (without SPNEGO wrappers) inside CredSSP when Kerberos is not possible.
#[derive(Debug, Clone)]
pub enum ClientMode {
    Negotiate(NegotiateConfig),
    Pku2u(Box<Pku2uConfig>),
    Ntlm(NtlmConfig),
}

/// Implements the CredSSP *client*. The client's credentials are to
/// be securely delegated to the server.
///
/// # MSDN
///
/// * [Glossary](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/97e4a826-1112-4ab4-8662-cfa58418b4c1)
#[derive(Debug)]
pub struct CredSspClient {
    state: CredSspState,
    context: Option<CredSspContext>,
    credentials: Credentials,
    public_key: Vec<u8>,
    cred_ssp_mode: CredSspMode,
    client_nonce: [u8; NONCE_SIZE],
    credentials_handle: Option<CredentialsBuffers>,
    ts_request_version: u32,
    client_mode: Option<ClientMode>,
    service_principal_name: String,
}

impl CredSspClient {
    pub fn new(
        public_key: Vec<u8>,
        credentials: Credentials,
        cred_ssp_mode: CredSspMode,
        client_mode: ClientMode,
        service_principal_name: String,
    ) -> crate::Result<Self> {
        let mut rng = StdRng::try_from_rng(&mut SysRng)?;
        let mut client_nonce = [0; NONCE_SIZE];
        rng.fill_bytes(&mut client_nonce);
        Ok(Self {
            state: CredSspState::NegoToken,
            context: None,
            credentials,
            public_key,
            cred_ssp_mode,
            client_nonce,
            credentials_handle: None,
            ts_request_version: TS_REQUEST_VERSION,
            client_mode: Some(client_mode),
            service_principal_name,
        })
    }

    pub fn new_with_version(
        public_key: Vec<u8>,
        credentials: Credentials,
        cred_ssp_mode: CredSspMode,
        ts_request_version: u32,
        client_mode: ClientMode,
        service_principal_name: String,
    ) -> crate::Result<Self> {
        let mut rng = StdRng::try_from_rng(&mut SysRng)?;
        let mut client_nonce = [0; NONCE_SIZE];
        rng.fill_bytes(&mut client_nonce);
        Ok(Self {
            state: CredSspState::NegoToken,
            context: None,
            credentials,
            public_key,
            cred_ssp_mode,
            client_nonce,
            credentials_handle: None,
            ts_request_version,
            client_mode: Some(client_mode),
            service_principal_name,
        })
    }

    #[instrument(fields(state = ?self.state), skip_all)]
    pub fn process(
        &mut self,
        ts_request: TsRequest,
    ) -> Generator<'_, NetworkRequest, crate::Result<Vec<u8>>, crate::Result<ClientState>> {
        Generator::<NetworkRequest, crate::Result<Vec<u8>>, crate::Result<ClientState>>::new(
            move |mut yield_point| async move { self.process_impl(&mut yield_point, ts_request).await },
        )
    }

    async fn process_impl(
        &mut self,
        yield_point: &mut YieldPointLocal,
        mut ts_request: TsRequest,
    ) -> crate::Result<ClientState> {
        ts_request.check_error()?;
        if let Some(ref mut context) = self.context {
            context.check_peer_version(ts_request.version)?;
        } else {
            self.context = match self
                .client_mode
                .take()
                .expect("CredSsp client mode should never be empty")
            {
                ClientMode::Negotiate(negotiate_config) => Some(CredSspContext::new(SspiContext::Negotiate(
                    Negotiate::new_client(negotiate_config)?,
                ))),
                ClientMode::Pku2u(pku2u) => Some(CredSspContext::new(SspiContext::Pku2u(
                    Pku2u::new_client_from_config(*pku2u)?,
                ))),
                ClientMode::Ntlm(ntlm) => Some(CredSspContext::new(SspiContext::Ntlm(Ntlm::with_config(ntlm)))),
            };

            let sspi_context = &mut self
                .context
                .as_mut()
                .expect("Should not panic because the CredSSP context is set before")
                .sspi_context;
            let builder = AcquireCredentialsHandle::<'_, _, _, WithoutCredentialUse>::new();
            let AcquireCredentialsHandleResult { credentials_handle, .. } = builder
                .with_auth_data(&self.credentials)
                .with_credential_use(CredentialUse::Outbound)
                .execute(sspi_context)?;
            self.credentials_handle = credentials_handle;
        }

        ts_request.version = self.ts_request_version;

        match self.state {
            CredSspState::NegoToken => {
                let mut input_token = [SecurityBuffer::new(
                    ts_request.nego_tokens.take().unwrap_or_default(),
                    BufferType::Token,
                )];
                let mut output_token = vec![SecurityBuffer::new(Vec::with_capacity(1024), BufferType::Token)];

                let mut credentials_handle = self.credentials_handle.take();
                let cred_ssp_context = self
                    .context
                    .as_mut()
                    .expect("Should not panic because the CredSSP context is set before");
                let mut builder = cred_ssp_context
                    .sspi_context
                    .initialize_security_context()
                    .with_credentials_handle(&mut credentials_handle)
                    .with_context_requirements(
                        ClientRequestFlags::MUTUAL_AUTH
                            | ClientRequestFlags::USE_SESSION_KEY
                            | ClientRequestFlags::INTEGRITY
                            | ClientRequestFlags::CONFIDENTIALITY,
                    )
                    .with_target_data_representation(DataRepresentation::Native)
                    .with_target_name(&self.service_principal_name)
                    .with_input(&mut input_token)
                    .with_output(&mut output_token);
                let result = cred_ssp_context
                    .sspi_context
                    .initialize_security_context_impl(yield_point, &mut builder)
                    .await?;
                self.credentials_handle = credentials_handle;
                ts_request.nego_tokens = Some(output_token.remove(0).buffer);

                if result.status == SecurityStatus::Ok {
                    debug!("CredSSp finished NLA stage.");

                    let peer_version =
                        self.context.as_ref().unwrap().peer_version.expect(
                            "An encrypt public key client function cannot be fired without any incoming TSRequest",
                        );
                    ts_request.pub_key_auth = Some(
                        self.context
                            .as_mut()
                            .expect("Should not panic because the CredSSP context is set before")
                            .encrypt_public_key(
                                self.public_key.as_ref(),
                                EndpointType::Client,
                                &Some(self.client_nonce),
                                peer_version,
                            )?,
                    );
                    ts_request.client_nonce = Some(self.client_nonce);

                    if let Some(nego_tokens) = &ts_request.nego_tokens
                        && nego_tokens.is_empty()
                    {
                        ts_request.nego_tokens = None;
                    }

                    self.state = CredSspState::AuthInfo;
                }

                Ok(ClientState::ReplyNeeded(ts_request))
            }
            CredSspState::AuthInfo => {
                ts_request.nego_tokens = None;

                let pub_key_auth = ts_request.pub_key_auth.take().ok_or_else(|| {
                    Error::new(
                        ErrorKind::InvalidToken,
                        String::from("CredSSP client expected an encrypted public key"),
                    )
                })?;
                let peer_version = self
                    .context
                    .as_ref()
                    .expect("Should not panic because the CredSSP context is set before")
                    .peer_version
                    .expect("An decrypt public key client function cannot be fired without any incoming TSRequest");
                self.context.as_mut().unwrap().decrypt_public_key(
                    self.public_key.as_ref(),
                    pub_key_auth.as_ref(),
                    EndpointType::Client,
                    &Some(self.client_nonce),
                    peer_version,
                )?;

                ts_request.auth_info = Some(
                    self.context
                        .as_mut()
                        .unwrap()
                        .encrypt_ts_credentials(self.credentials_handle.as_ref().unwrap(), self.cred_ssp_mode)?,
                );
                debug!("tscredentials has been written");

                self.state = CredSspState::Final;

                Ok(ClientState::FinalMessage(ts_request))
            }
            CredSspState::Final | CredSspState::PubKeyInfo => Err(Error::new(
                ErrorKind::OutOfSequence,
                "CredSSP client's 'process' method must not be fired after the 'Finished' state",
            )),
        }
    }
}

/// CredSSP client authentication protocol.
///
/// From MSDN: [1.3 Overview](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/e36b36f6-edf4-4df1-9905-9e53b7d7c7b7):
/// > The CredSSP Protocol then uses the Simple and Protected Generic Security Service Application Program Interface Negotiation Mechanism (SPNEGO)
/// > to authenticate the user and server in the encrypted TLS session.
/// > SPNEGO provides a framework for two parties that are engaged in authentication to select from a set of
/// > possible authentication mechanisms. This framework provides selection in a manner that preserves
/// > the opaque nature of the security protocols to the application protocol that uses SPNEGO. In this case,
/// > the CredSSP Protocol is the application protocol that uses SPNEGO.
///
/// According to the specification, we should always use the Negotiate security package in CredSSP.
/// However, mstsc and other RDP clients send plain NTLM messages (without SPNEGO wrappers) inside CredSSP when Kerberos is not possible.
#[derive(Debug, Clone)]
pub enum ServerMode {
    Negotiate(NegotiateConfig),
    Pku2u(Box<Pku2uConfig>),
    Ntlm(NtlmConfig),
}

/// Implements the CredSSP *server*. The client's credentials
/// securely delegated to the server for authentication using TLS.
///
/// # MSDN
///
/// * [Glossary](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/97e4a826-1112-4ab4-8662-cfa58418b4c1)
#[derive(Debug)]
pub struct CredSspServer<C: CredentialsProxy<AuthenticationData = AuthIdentity>> {
    credentials: C,
    state: CredSspState,
    context: Option<CredSspContext>,
    public_key: Vec<u8>,
    credentials_handle: Option<CredentialsBuffers>,
    ts_request_version: u32,
    context_config: Option<ServerMode>,
}

impl<C: CredentialsProxy<AuthenticationData = AuthIdentity> + Send> CredSspServer<C> {
    pub fn new(public_key: Vec<u8>, credentials: C, client_mode: ServerMode) -> crate::Result<Self> {
        Ok(Self {
            state: CredSspState::NegoToken,
            context: None,
            credentials,
            public_key,
            credentials_handle: None,
            ts_request_version: TS_REQUEST_VERSION,
            context_config: Some(client_mode),
        })
    }

    pub fn new_with_version(
        public_key: Vec<u8>,
        credentials: C,
        ts_request_version: u32,
        client_mode: ServerMode,
    ) -> crate::Result<Self> {
        Ok(Self {
            state: CredSspState::NegoToken,
            context: None,
            credentials,
            public_key,
            credentials_handle: None,
            ts_request_version,
            context_config: Some(client_mode),
        })
    }

    fn exchange_pub_key_auth(
        &mut self,
        pub_key_auth: &[u8],
        client_nonce: &Option<[u8; NONCE_SIZE]>,
    ) -> crate::Result<Vec<u8>> {
        let peer_version = self
            .context
            .as_ref()
            .unwrap()
            .peer_version
            .expect("a decrypt public key server function cannot be fired without any incoming TSRequest");

        let context = self.context.as_mut().unwrap();

        context.decrypt_public_key(
            &self.public_key,
            pub_key_auth,
            EndpointType::Server,
            client_nonce,
            peer_version,
        )?;

        context.encrypt_public_key(&self.public_key, EndpointType::Server, client_nonce, peer_version)
    }

    #[instrument(fields(state = ?self.state), skip_all)]
    pub fn process(
        &mut self,
        ts_request: TsRequest,
    ) -> Generator<'_, NetworkRequest, crate::Result<Vec<u8>>, Result<ServerState, ServerError>> {
        Generator::<NetworkRequest, crate::Result<Vec<u8>>, Result<ServerState, ServerError>>::new(
            move |mut yield_point| async move { self.process_impl(&mut yield_point, ts_request).await },
        )
    }

    async fn process_impl(
        &mut self,
        yield_point: &mut YieldPointLocal,
        mut ts_request: TsRequest,
    ) -> Result<ServerState, ServerError> {
        if self.context.is_none() {
            self.context = match self
                .context_config
                .take()
                .expect("CredSsp client mode should never be empty")
            {
                ServerMode::Negotiate(neg_config) => {
                    Some(CredSspContext::new(SspiContext::Negotiate(try_cred_ssp_server!(
                        Negotiate::new_server(
                            neg_config,
                            try_cred_ssp_server!(self.credentials.auth_data(), ts_request)
                        ),
                        ts_request
                    ))))
                }
                ServerMode::Ntlm(ntlm) => Some(CredSspContext::new(SspiContext::Ntlm(Ntlm::with_config(ntlm)))),
                ServerMode::Pku2u(pku2u) => Some(CredSspContext::new(SspiContext::Pku2u(try_cred_ssp_server!(
                    Pku2u::new_server_from_config(*pku2u),
                    ts_request
                )))),
            };
            let AcquireCredentialsHandleResult { credentials_handle, .. } = try_cred_ssp_server!(
                AcquireCredentialsHandle::<'_, _, _, WithoutCredentialUse>::new()
                    .with_credential_use(CredentialUse::Inbound)
                    .execute(
                        // clippy::panicking_unwrap false positive. We set self.context just above.
                        #[allow(clippy::panicking_unwrap)]
                        &mut self
                            .context
                            .as_mut()
                            .expect("Should not panic because the CredSSP context is set before")
                            .sspi_context
                    ),
                ts_request
            );
            self.credentials_handle = credentials_handle;
        }
        try_cred_ssp_server!(
            self.context
                .as_mut()
                .expect("Should not panic because the CredSSP context is set before")
                .check_peer_version(ts_request.version),
            ts_request
        );

        ts_request.version = self.ts_request_version;

        match self.state {
            CredSspState::AuthInfo => {
                let auth_info = try_cred_ssp_server!(
                    ts_request.auth_info.take().ok_or_else(|| {
                        Error::new(
                            ErrorKind::InvalidToken,
                            String::from("expected an encrypted ts credentials"),
                        )
                    }),
                    ts_request
                );

                let read_credentials = try_cred_ssp_server!(
                    self.context.as_mut().unwrap().decrypt_ts_credentials(&auth_info),
                    ts_request
                );

                self.state = CredSspState::Final;

                let auth_identity = try_cred_ssp_server!(
                    AuthIdentity::try_from(read_credentials.into_auth_identity().unwrap())
                        .map_err(|e| Error::new(ErrorKind::InvalidParameter, e)),
                    ts_request
                );

                Ok(ServerState::Finished(auth_identity))
            }
            CredSspState::NegoToken => {
                let input = ts_request.nego_tokens.take().unwrap_or_default();
                let mut input_token = vec![SecurityBuffer::new(input, BufferType::Token)];
                let mut output_token = vec![SecurityBuffer::new(Vec::with_capacity(1024), BufferType::Token)];

                let mut credentials_handle = self.credentials_handle.take();
                let sspi_context = &mut self.context.as_mut().unwrap().sspi_context;

                let builder = sspi_context
                    .accept_security_context()
                    .with_credentials_handle(&mut credentials_handle)
                    .with_context_requirements(ServerRequestFlags::empty())
                    .with_target_data_representation(DataRepresentation::Native)
                    .with_input(&mut input_token)
                    .with_output(&mut output_token);
                match try_cred_ssp_server!(
                    sspi_context.accept_security_context_impl(yield_point, builder).await,
                    ts_request
                ) {
                    AcceptSecurityContextResult {
                        status: SecurityStatus::ContinueNeeded,
                        ..
                    } => {
                        ts_request.nego_tokens = Some(output_token.remove(0).buffer);
                    }
                    AcceptSecurityContextResult {
                        status: SecurityStatus::CompleteNeeded | SecurityStatus::Ok,
                        ..
                    } => {
                        let ContextNames { username } = try_cred_ssp_server!(
                            self.context.as_mut().unwrap().sspi_context.query_context_names(),
                            ts_request
                        );
                        let candidates = try_cred_ssp_server!(
                            self.credentials
                                .auth_data_candidates_by_user(&username)
                                .map_err(|e| Error::new(ErrorKind::LogonDenied, e.to_string())),
                            ts_request
                        );
                        let cred_candidates = candidates.into_iter().map(Credentials::AuthIdentity).collect();
                        try_cred_ssp_server!(
                            self.context
                                .as_mut()
                                .unwrap()
                                .sspi_context
                                .custom_set_auth_identities(cred_candidates),
                            ts_request
                        );

                        try_cred_ssp_server!(
                            self.context.as_mut().unwrap().sspi_context.complete_auth_token(&mut []),
                            ts_request
                        );

                        if let Some(pub_key_auth) = ts_request.pub_key_auth.as_ref() {
                            ts_request.nego_tokens = None;

                            let pub_key_auth = try_cred_ssp_server!(
                                self.exchange_pub_key_auth(pub_key_auth, &ts_request.client_nonce),
                                ts_request
                            );
                            ts_request.pub_key_auth = Some(pub_key_auth);

                            self.state = CredSspState::AuthInfo;
                        } else {
                            let output = output_token.remove(0).buffer;
                            if !output.is_empty() {
                                ts_request.nego_tokens = Some(output);
                                self.state = CredSspState::PubKeyInfo;
                            } else {
                                try_cred_ssp_server!(
                                    Err(Error::new(
                                        ErrorKind::InvalidToken,
                                        "CredSSP server error: the security package returned an empty token",
                                    )),
                                    ts_request
                                );
                            }
                        }
                    }
                    result => {
                        try_cred_ssp_server!(
                            Err(Error::new(
                                ErrorKind::InternalError,
                                format!("SSPI returned unexpected status: {:?}", result.status)
                            )),
                            ts_request
                        )
                    }
                };

                self.credentials_handle = credentials_handle;

                Ok(ServerState::ReplyNeeded(ts_request))
            }
            CredSspState::PubKeyInfo => {
                ts_request.nego_tokens = None;

                let pub_key_auth = try_cred_ssp_server!(
                    ts_request.pub_key_auth.take().ok_or_else(|| {
                        Error::new(
                            ErrorKind::InvalidToken,
                            String::from("CredSSP server expected an encrypted public key"),
                        )
                    }),
                    ts_request
                );

                let pub_key_auth = try_cred_ssp_server!(
                    self.exchange_pub_key_auth(&pub_key_auth, &ts_request.client_nonce),
                    ts_request
                );
                ts_request.pub_key_auth = Some(pub_key_auth);

                self.state = CredSspState::AuthInfo;

                Ok(ServerState::ReplyNeeded(ts_request))
            }
            CredSspState::Final => Err(ServerError {
                ts_request: Some(Box::new(ts_request)),
                error: Error::new(
                    ErrorKind::UnsupportedFunction,
                    "CredSSP server's 'process' method must not be fired after the 'Finished' state",
                ),
            }),
        }
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum SspiContext {
    Ntlm(Ntlm),
    Kerberos(Kerberos),
    Negotiate(Negotiate),
    Pku2u(Pku2u),
    #[cfg(feature = "tsssp")]
    CredSsp(SspiCredSsp),
}

impl SspiContext {
    pub fn package_name(&self) -> &str {
        match self {
            SspiContext::Ntlm(_) => ntlm::PKG_NAME,
            SspiContext::Kerberos(_) => kerberos::PKG_NAME,
            SspiContext::Negotiate(_) => negotiate::PKG_NAME,
            SspiContext::Pku2u(_) => pku2u::PKG_NAME,
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(_) => sspi_cred_ssp::PKG_NAME,
        }
    }
}

impl SspiImpl for SspiContext {
    type CredentialsHandle = Option<CredentialsBuffers>;
    type AuthenticationData = Credentials;

    #[instrument(ret, level = "debug", fields(security_package = self.package_name()), skip_all)]
    fn acquire_credentials_handle_impl(
        &mut self,
        builder: FilledAcquireCredentialsHandle<'_, Self::CredentialsHandle, Self::AuthenticationData>,
    ) -> crate::Result<AcquireCredentialsHandleResult<Self::CredentialsHandle>> {
        Ok(match self {
            SspiContext::Ntlm(ntlm) => {
                let auth_identity = match builder.auth_data {
                    Some(Credentials::AuthIdentity(identity)) => Some(identity),
                    #[cfg(feature = "scard")]
                    Some(Credentials::SmartCard(_identity)) => {
                        return Err(Error::new(
                            ErrorKind::UnknownCredentials,
                            "smart card auth is not supported in NTLM",
                        ));
                    }
                    Some(Credentials::Keytab(_)) => {
                        return Err(Error::new(
                            ErrorKind::UnknownCredentials,
                            "keytab auth is not supported in NTLM",
                        ));
                    }
                    None => None,
                };
                builder
                    .full_transform(auth_identity)
                    .execute(ntlm)?
                    .transform_credentials_handle(&|a: Option<AuthIdentityBuffers>| {
                        a.map(CredentialsBuffers::AuthIdentity)
                    })
            }
            SspiContext::Kerberos(kerberos) => builder.execute(kerberos)?,
            SspiContext::Negotiate(negotiate) => builder.execute(negotiate)?,
            SspiContext::Pku2u(pku2u) => {
                let auth_identity = if let Some(Credentials::AuthIdentity(identity)) = builder.auth_data {
                    identity
                } else {
                    return Err(Error::new(
                        ErrorKind::NoCredentials,
                        "auth identity is not provided for the Pku2u",
                    ));
                };
                builder
                    .full_transform(Some(auth_identity))
                    .execute(pku2u)?
                    .transform_credentials_handle(&|a: Option<AuthIdentityBuffers>| {
                        a.map(CredentialsBuffers::AuthIdentity)
                    })
            }
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => builder.execute(credssp)?,
        })
    }

    #[instrument(ret, level = "debug", fields(security_package = self.package_name()), skip_all)]
    fn accept_security_context_impl<'a>(
        &'a mut self,
        builder: FilledAcceptSecurityContext<'a, Self::CredentialsHandle>,
    ) -> crate::Result<GeneratorAcceptSecurityContext<'a>> {
        Ok(GeneratorAcceptSecurityContext::new(move |mut yield_point| async move {
            self.accept_security_context_impl(&mut yield_point, builder).await
        }))
    }

    fn initialize_security_context_impl<'ctx, 'b, 'g>(
        &'ctx mut self,
        builder: &'b mut FilledInitializeSecurityContext<'ctx, 'ctx, Self::CredentialsHandle>,
    ) -> crate::Result<GeneratorInitSecurityContext<'g>>
    where
        'ctx: 'g,
        'b: 'g,
    {
        Ok(Generator::new(move |mut yield_point| async move {
            self.initialize_security_context_impl(&mut yield_point, builder).await
        }))
    }
}

impl<'a> SspiContext {
    #[instrument(ret, level = "debug", fields(security_package = self.package_name()), skip_all)]
    async fn change_password_impl(
        &mut self,
        yield_point: &mut YieldPointLocal,
        change_password: ChangePassword<'a>,
    ) -> crate::Result<()> {
        match self {
            SspiContext::Kerberos(kerberos) => kerberos.change_password(yield_point, change_password).await,
            SspiContext::Negotiate(negotiate) => negotiate.change_password(yield_point, change_password).await,
            _ => Err(Error::new(
                ErrorKind::UnsupportedFunction,
                "change password not supported for this protocol",
            )),
        }
    }

    #[cfg(feature = "network_client")]
    pub fn initialize_security_context_sync(
        &mut self,
        builder: &mut FilledInitializeSecurityContext<'_, '_, <Self as SspiImpl>::CredentialsHandle>,
    ) -> crate::Result<InitializeSecurityContextResult> {
        Generator::new(move |mut yield_point| async move {
            self.initialize_security_context_impl(&mut yield_point, builder).await
        })
        .resolve_with_default_network_client()
    }

    #[cfg(feature = "network_client")]
    pub fn accept_security_context_sync(
        &mut self,
        builder: FilledAcceptSecurityContext<'_, <Self as SspiImpl>::CredentialsHandle>,
    ) -> crate::Result<AcceptSecurityContextResult> {
        Generator::new(move |mut yield_point| async move {
            self.accept_security_context_impl(&mut yield_point, builder).await
        })
        .resolve_with_default_network_client()
    }

    #[cfg(feature = "network_client")]
    pub fn change_password_sync(&mut self, builder: ChangePassword<'_>) -> crate::Result<()> {
        Generator::new(move |mut yield_point| async move { self.change_password_impl(&mut yield_point, builder).await })
            .resolve_with_default_network_client()
    }

    pub(crate) async fn accept_security_context_impl(
        &mut self,
        yield_point: &mut YieldPointLocal,
        builder: FilledAcceptSecurityContext<'a, <Self as SspiImpl>::CredentialsHandle>,
    ) -> crate::Result<AcceptSecurityContextResult> {
        match self {
            SspiContext::Ntlm(ntlm) => {
                let mut auth_identity = match builder.credentials_handle {
                    Some(Some(CredentialsBuffers::AuthIdentity(identity))) => Some(identity.clone()),
                    #[cfg(feature = "scard")]
                    Some(Some(CredentialsBuffers::SmartCard(_identity))) => {
                        return Err(Error::new(
                            ErrorKind::UnknownCredentials,
                            "smart card auth is not supported in NTLM",
                        ));
                    }
                    Some(Some(CredentialsBuffers::Keytab(_))) => {
                        return Err(Error::new(
                            ErrorKind::UnknownCredentials,
                            "keytab auth is not supported in NTLM",
                        ));
                    }
                    Some(None) => None,
                    None => {
                        return Err(Error::new(
                            ErrorKind::NoCredentials,
                            "credentials handle is not provided for the NTLM",
                        ));
                    }
                };
                let new_builder = builder.full_transform(Some(&mut auth_identity));
                ntlm.accept_security_context_impl(new_builder)
            }
            SspiContext::Kerberos(kerberos) => kerberos.accept_security_context_impl(yield_point, builder).await,
            SspiContext::Negotiate(negotiate) => negotiate.accept_security_context_impl(yield_point, builder).await,
            SspiContext::Pku2u(pku2u) => {
                let mut creds_handle = builder
                    .credentials_handle
                    .as_ref()
                    .and_then(|creds| (*creds).clone())
                    .and_then(|creds_handle| creds_handle.into_auth_identity());
                let new_builder = builder.full_transform(Some(&mut creds_handle));
                pku2u.accept_security_context_impl(yield_point, new_builder).await
            }
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => credssp.accept_security_context_impl(yield_point, builder).await,
        }
    }

    #[instrument(ret, level = "debug", fields(security_package = self.package_name()), skip_all)]
    async fn initialize_security_context_impl(
        &'a mut self,
        yield_point: &mut YieldPointLocal,
        builder: &'a mut FilledInitializeSecurityContext<'_, '_, <Self as SspiImpl>::CredentialsHandle>,
    ) -> crate::Result<InitializeSecurityContextResult> {
        match self {
            SspiContext::Ntlm(ntlm) => {
                let mut auth_identity =
                    if let Some(Some(CredentialsBuffers::AuthIdentity(identity))) = builder.credentials_handle_mut() {
                        Some(identity.clone())
                    } else {
                        None
                    };
                let mut new_builder = builder.full_transform(Some(&mut auth_identity));
                ntlm.initialize_security_context_impl(&mut new_builder)
            }
            SspiContext::Kerberos(kerberos) => kerberos.initialize_security_context_impl(yield_point, builder).await,
            SspiContext::Negotiate(negotiate) => negotiate.initialize_security_context_impl(yield_point, builder).await,
            SspiContext::Pku2u(pku2u) => {
                let mut auth_identity =
                    if let Some(Some(CredentialsBuffers::AuthIdentity(identity))) = builder.credentials_handle_mut() {
                        Some(identity.clone())
                    } else {
                        None
                    };
                let mut new_builder = builder.full_transform(Some(&mut auth_identity));
                pku2u.initialize_security_context_impl(&mut new_builder)
            }
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => credssp.initialize_security_context_impl(yield_point, builder).await,
        }
    }
}

impl Sspi for SspiContext {
    #[instrument(ret, level = "debug", fields(security_package = self.package_name()), skip(self))]
    fn complete_auth_token(&mut self, token: &mut [SecurityBuffer]) -> crate::Result<SecurityStatus> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.complete_auth_token(token),
            SspiContext::Kerberos(kerberos) => kerberos.complete_auth_token(token),
            SspiContext::Negotiate(negotiate) => negotiate.complete_auth_token(token),
            SspiContext::Pku2u(pku2u) => pku2u.complete_auth_token(token),
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => credssp.complete_auth_token(token),
        }
    }

    #[instrument(ret, level = "debug", fields(security_package = self.package_name()), skip(self))]
    fn encrypt_message(
        &mut self,
        flags: EncryptionFlags,
        message: &mut [SecurityBufferRef<'_>],
    ) -> crate::Result<SecurityStatus> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.encrypt_message(flags, message),
            SspiContext::Kerberos(kerberos) => kerberos.encrypt_message(flags, message),
            SspiContext::Negotiate(negotiate) => negotiate.encrypt_message(flags, message),
            SspiContext::Pku2u(pku2u) => pku2u.encrypt_message(flags, message),
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => credssp.encrypt_message(flags, message),
        }
    }

    #[instrument(ret, level = "debug", fields(security_package = self.package_name()), skip(self))]
    fn decrypt_message(&mut self, message: &mut [SecurityBufferRef<'_>]) -> crate::Result<DecryptionFlags> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.decrypt_message(message),
            SspiContext::Kerberos(kerberos) => kerberos.decrypt_message(message),
            SspiContext::Negotiate(negotiate) => negotiate.decrypt_message(message),
            SspiContext::Pku2u(pku2u) => pku2u.decrypt_message(message),
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => credssp.decrypt_message(message),
        }
    }

    #[instrument(ret, level = "debug", fields(security_package = self.package_name()), skip(self))]
    fn query_context_sizes(&mut self) -> crate::Result<ContextSizes> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.query_context_sizes(),
            SspiContext::Kerberos(kerberos) => kerberos.query_context_sizes(),
            SspiContext::Negotiate(negotiate) => negotiate.query_context_sizes(),
            SspiContext::Pku2u(pku2u) => pku2u.query_context_sizes(),
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => credssp.query_context_sizes(),
        }
    }

    #[instrument(ret, level = "debug", fields(security_package = self.package_name()), skip(self))]
    fn query_context_names(&mut self) -> crate::Result<ContextNames> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.query_context_names(),
            SspiContext::Kerberos(kerberos) => kerberos.query_context_names(),
            SspiContext::Negotiate(negotiate) => negotiate.query_context_names(),
            SspiContext::Pku2u(pku2u) => pku2u.query_context_names(),
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => credssp.query_context_names(),
        }
    }

    #[instrument(ret, level = "debug", fields(security_package = self.package_name()), skip(self))]
    fn query_context_stream_sizes(&mut self) -> crate::Result<StreamSizes> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.query_context_stream_sizes(),
            SspiContext::Kerberos(kerberos) => kerberos.query_context_stream_sizes(),
            SspiContext::Negotiate(negotiate) => negotiate.query_context_stream_sizes(),
            SspiContext::Pku2u(pku2u) => pku2u.query_context_stream_sizes(),
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => credssp.query_context_stream_sizes(),
        }
    }

    #[instrument(ret, level = "debug", fields(security_package = self.package_name()), skip(self))]
    fn query_context_package_info(&mut self) -> crate::Result<PackageInfo> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.query_context_package_info(),
            SspiContext::Kerberos(kerberos) => kerberos.query_context_package_info(),
            SspiContext::Negotiate(negotiate) => negotiate.query_context_package_info(),
            SspiContext::Pku2u(pku2u) => pku2u.query_context_package_info(),
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => credssp.query_context_package_info(),
        }
    }

    #[instrument(ret, level = "debug", fields(security_package = self.package_name()), skip(self))]
    fn query_context_cert_trust_status(&mut self) -> crate::Result<CertTrustStatus> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.query_context_cert_trust_status(),
            SspiContext::Kerberos(kerberos) => kerberos.query_context_cert_trust_status(),
            SspiContext::Negotiate(negotiate) => negotiate.query_context_cert_trust_status(),
            SspiContext::Pku2u(pku2u) => pku2u.query_context_cert_trust_status(),
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => credssp.query_context_cert_trust_status(),
        }
    }

    #[instrument(ret, level = "debug", fields(security_package = self.package_name()), skip(self))]
    fn query_context_remote_cert(&mut self) -> crate::Result<CertContext> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.query_context_remote_cert(),
            SspiContext::Kerberos(kerberos) => kerberos.query_context_remote_cert(),
            SspiContext::Negotiate(negotiate) => negotiate.query_context_remote_cert(),
            SspiContext::Pku2u(pku2u) => pku2u.query_context_remote_cert(),
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => credssp.query_context_remote_cert(),
        }
    }

    #[instrument(ret, level = "debug", fields(security_package = self.package_name()), skip(self))]
    fn query_context_negotiation_package(&mut self) -> crate::Result<PackageInfo> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.query_context_negotiation_package(),
            SspiContext::Kerberos(kerberos) => kerberos.query_context_negotiation_package(),
            SspiContext::Negotiate(negotiate) => negotiate.query_context_negotiation_package(),
            SspiContext::Pku2u(pku2u) => pku2u.query_context_negotiation_package(),
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => credssp.query_context_negotiation_package(),
        }
    }

    #[instrument(ret, level = "debug", fields(security_package = self.package_name()), skip(self))]
    fn query_context_connection_info(&mut self) -> crate::Result<ConnectionInfo> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.query_context_connection_info(),
            SspiContext::Kerberos(kerberos) => kerberos.query_context_connection_info(),
            SspiContext::Negotiate(negotiate) => negotiate.query_context_connection_info(),
            SspiContext::Pku2u(pku2u) => pku2u.query_context_connection_info(),
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => credssp.query_context_connection_info(),
        }
    }

    #[instrument(fields(security_package = self.package_name()), skip(self))]
    fn query_context_session_key(&self) -> crate::Result<crate::SessionKeys> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.query_context_session_key(),
            SspiContext::Kerberos(kerberos) => kerberos.query_context_session_key(),
            SspiContext::Negotiate(negotiate) => negotiate.query_context_session_key(),
            SspiContext::Pku2u(pku2u) => pku2u.query_context_session_key(),
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => credssp.query_context_session_key(),
        }
    }

    fn change_password<'a>(
        &'a mut self,
        change_password: ChangePassword<'a>,
    ) -> crate::Result<GeneratorChangePassword<'a>> {
        Ok(GeneratorChangePassword::new(move |mut yield_point| async move {
            self.change_password_impl(&mut yield_point, change_password).await
        }))
    }

    fn make_signature(
        &mut self,
        flags: u32,
        message: &mut [SecurityBufferRef<'_>],
        sequence_number: u32,
    ) -> crate::Result<()> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.make_signature(flags, message, sequence_number),
            SspiContext::Kerberos(kerberos) => kerberos.make_signature(flags, message, sequence_number),
            SspiContext::Negotiate(negotiate) => negotiate.make_signature(flags, message, sequence_number),
            SspiContext::Pku2u(pku2u) => pku2u.make_signature(flags, message, sequence_number),
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => credssp.make_signature(flags, message, sequence_number),
        }
    }

    fn verify_signature(&mut self, message: &mut [SecurityBufferRef<'_>], sequence_number: u32) -> crate::Result<u32> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.verify_signature(message, sequence_number),
            SspiContext::Kerberos(kerberos) => kerberos.verify_signature(message, sequence_number),
            SspiContext::Negotiate(negotiate) => negotiate.verify_signature(message, sequence_number),
            SspiContext::Pku2u(pku2u) => pku2u.verify_signature(message, sequence_number),
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => credssp.verify_signature(message, sequence_number),
        }
    }
}

impl SspiEx for SspiContext {
    // #[instrument(level = "trace", ret, fields(security_package = self.package_name()), skip(self))]
    fn custom_set_auth_identity(&mut self, identity: Self::AuthenticationData) -> crate::Result<()> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.custom_set_auth_identity(identity.auth_identity().ok_or_else(|| {
                Error::new(
                    ErrorKind::IncompleteCredentials,
                    "provided credentials are not password-based",
                )
            })?),
            SspiContext::Kerberos(kerberos) => kerberos.custom_set_auth_identity(identity),
            SspiContext::Negotiate(negotiate) => negotiate.custom_set_auth_identity(identity),
            SspiContext::Pku2u(pku2u) => pku2u.custom_set_auth_identity(identity.auth_identity().ok_or_else(|| {
                Error::new(
                    ErrorKind::IncompleteCredentials,
                    "provided credentials are not password-based",
                )
            })?),
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => credssp.custom_set_auth_identity(identity),
        }
    }

    fn custom_set_auth_identities(&mut self, identities: Vec<Self::AuthenticationData>) -> crate::Result<()> {
        match self {
            SspiContext::Ntlm(ntlm) => {
                // NOTE: non-AuthIdentity credentials (e.g. SmartCard) are silently
                // dropped here. Multi-credential only applies to password-based auth.
                let auth_identities: Vec<AuthIdentity> =
                    identities.into_iter().filter_map(|c| c.auth_identity()).collect();
                ntlm.custom_set_auth_identities(auth_identities)
            }
            SspiContext::Negotiate(negotiate) => negotiate.custom_set_auth_identities(identities),
            _ => match identities.into_iter().next() {
                Some(identity) => self.custom_set_auth_identity(identity),
                None => Err(Error::new(ErrorKind::NoCredentials, "no credentials provided")),
            },
        }
    }
}

#[derive(Debug)]
struct CredSspContext {
    peer_version: Option<u32>,
    sspi_context: SspiContext,
}

impl CredSspContext {
    fn new(sspi_context: SspiContext) -> Self {
        Self {
            peer_version: None,
            sspi_context,
        }
    }

    fn check_peer_version(&mut self, other_peer_version: u32) -> crate::Result<()> {
        if let Some(peer_version) = self.peer_version {
            if peer_version != other_peer_version {
                Err(Error::new(
                    ErrorKind::MessageAltered,
                    format!("CredSSP peer changed protocol version from {peer_version} to {other_peer_version}"),
                ))
            } else {
                Ok(())
            }
        } else {
            self.peer_version = Some(other_peer_version);

            Ok(())
        }
    }

    fn encrypt_public_key(
        &mut self,
        public_key: &[u8],
        endpoint: EndpointType,
        client_nonce: &Option<[u8; NONCE_SIZE]>,
        peer_version: u32,
    ) -> crate::Result<Vec<u8>> {
        let hash_magic = match endpoint {
            EndpointType::Client => CLIENT_SERVER_HASH_MAGIC,
            EndpointType::Server => SERVER_CLIENT_HASH_MAGIC,
        };

        if peer_version < 5 {
            self.encrypt_public_key_echo(public_key, endpoint)
        } else {
            self.encrypt_public_key_hash(
                public_key,
                hash_magic,
                &client_nonce.ok_or(Error::new(
                    ErrorKind::InvalidToken,
                    String::from("client nonce from the TSRequest is empty, but a peer version is >= 5"),
                ))?,
            )
        }
    }

    fn decrypt_public_key(
        &mut self,
        public_key: &[u8],
        encrypted_public_key: &[u8],
        endpoint: EndpointType,
        client_nonce: &Option<[u8; NONCE_SIZE]>,
        peer_version: u32,
    ) -> crate::Result<()> {
        let hash_magic = match endpoint {
            EndpointType::Client => SERVER_CLIENT_HASH_MAGIC,
            EndpointType::Server => CLIENT_SERVER_HASH_MAGIC,
        };

        if peer_version < 5 {
            self.decrypt_public_key_echo(public_key, encrypted_public_key, endpoint)
        } else {
            self.decrypt_public_key_hash(
                public_key,
                encrypted_public_key,
                hash_magic,
                &client_nonce.ok_or(Error::new(
                    ErrorKind::InvalidToken,
                    String::from("client nonce from the TSRequest is empty, but a peer version is >= 5"),
                ))?,
            )
        }
    }

    fn encrypt_public_key_echo(&mut self, public_key: &[u8], endpoint: EndpointType) -> crate::Result<Vec<u8>> {
        let mut public_key = public_key.to_vec();

        if let SspiContext::Ntlm(_) = self.sspi_context
            && endpoint == EndpointType::Server
        {
            integer_increment_le(&mut public_key);
        }

        self.encrypt_message(&public_key)
    }

    fn encrypt_public_key_hash(
        &mut self,
        public_key: &[u8],
        hash_magic: &[u8],
        client_nonce: &[u8],
    ) -> crate::Result<Vec<u8>> {
        let mut data = hash_magic.to_vec();
        data.extend(client_nonce);
        data.extend(public_key);

        self.encrypt_message(&compute_sha256(&data))
    }

    fn decrypt_public_key_echo(
        &mut self,
        public_key: &[u8],
        encrypted_public_key: &[u8],
        endpoint: EndpointType,
    ) -> crate::Result<()> {
        let mut decrypted_public_key = self.decrypt_message(encrypted_public_key)?;
        if endpoint == EndpointType::Client {
            integer_decrement_le(&mut decrypted_public_key);
        }

        if public_key != decrypted_public_key.as_slice() {
            error!("Expected and decrypted public key are not the same");

            return Err(Error::new(
                ErrorKind::MessageAltered,
                String::from("could not verify a public key echo"),
            ));
        }

        Ok(())
    }

    fn decrypt_public_key_hash(
        &mut self,
        public_key: &[u8],
        encrypted_public_key: &[u8],
        hash_magic: &[u8],
        client_nonce: &[u8],
    ) -> crate::Result<()> {
        let decrypted_public_key = self.decrypt_message(encrypted_public_key)?;

        let mut data = hash_magic.to_vec();
        data.extend(client_nonce);
        data.extend(public_key);
        let expected_public_key = compute_sha256(&data);

        if expected_public_key.as_ref() != decrypted_public_key.as_slice() {
            error!("Expected and decrypted public key hash are not the same");

            return Err(Error::new(
                ErrorKind::MessageAltered,
                String::from("could not verify a public key hash"),
            ));
        }

        Ok(())
    }

    fn encrypt_ts_credentials(
        &mut self,
        credentials: &CredentialsBuffers,
        cred_ssp_mode: CredSspMode,
    ) -> crate::Result<Vec<u8>> {
        self.encrypt_message(&write_ts_credentials(credentials, cred_ssp_mode)?)
    }

    fn decrypt_ts_credentials(&mut self, auth_info: &[u8]) -> crate::Result<CredentialsBuffers> {
        let ts_credentials_buffer = self.decrypt_message(auth_info)?;

        read_ts_credentials(ts_credentials_buffer.as_slice())
    }

    fn encrypt_message(&mut self, input: &[u8]) -> crate::Result<Vec<u8>> {
        let mut token = [0; 1024];
        let mut data = input.to_vec();

        let mut buffers = vec![
            SecurityBufferRef::token_buf(token.as_mut_slice()),
            SecurityBufferRef::data_buf(data.as_mut_slice()),
        ];

        self.sspi_context
            .encrypt_message(EncryptionFlags::empty(), &mut buffers)?;

        let mut output = SecurityBufferRef::find_buffer(&buffers, BufferType::Token)?
            .data()
            .to_vec();
        output.extend_from_slice(SecurityBufferRef::find_buffer_mut(&mut buffers, BufferType::Data)?.data());

        Ok(output)
    }

    fn decrypt_message(&mut self, input: &[u8]) -> crate::Result<Vec<u8>> {
        let mut input = input.to_vec();
        let (signature, data) = input.split_at_mut(SIGNATURE_SIZE);
        let mut buffers = vec![
            SecurityBufferRef::data_buf(data),
            SecurityBufferRef::token_buf(signature),
        ];

        self.sspi_context.decrypt_message(&mut buffers)?;

        let output = SecurityBufferRef::buf_data(&buffers, BufferType::Data)?.to_vec();

        Ok(output)
    }
}

fn integer_decrement_le(buffer: &mut [u8]) {
    for elem in buffer.iter_mut() {
        let (value, overflow) = elem.overflowing_sub(1);
        *elem = value;
        if !overflow {
            break;
        }
    }
}

fn integer_increment_le(buffer: &mut [u8]) {
    for elem in buffer.iter_mut() {
        let (value, overflow) = elem.overflowing_add(1);
        *elem = value;
        if !overflow {
            break;
        }
    }
}

fn construct_error(e: &Error) -> NStatusCode {
    let code = ((e.error_type as i64 & 0x0000_FFFF) | (0x7 << 16) | 0xC000_0000) as u32;
    NStatusCode(code)
}

#[cfg(test)]
mod tests {
    use static_assertions::assert_impl_one;

    use super::CredSspClient;

    #[test]
    fn cred_sspi_client_is_send() {
        assert_impl_one!(CredSspClient: Send);
    }

    #[test]
    fn cred_sspi_client_is_sync() {
        assert_impl_one!(CredSspClient: Sync);
    }
}

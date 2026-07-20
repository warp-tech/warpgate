mod config;
pub mod hash;
mod messages;
#[cfg(test)]
mod test;

use std::fmt::Debug;
use std::io;
use std::sync::LazyLock;

use bitflags::bitflags;
use byteorder::{LittleEndian, WriteBytesExt};
pub use hash::{NTLM_HASH_PREFIX, NtlmHash, NtlmHashError};
use messages::{client, server};

pub use self::config::NtlmConfig;
use super::channel_bindings::ChannelBindings;
use crate::crypto::{HASH_SIZE, Rc4, compute_hmac_md5};
use crate::generator::{GeneratorAcceptSecurityContext, GeneratorInitSecurityContext};
use crate::utils::{extract_encrypted_data, save_decrypted_data};
use crate::{
    AcceptSecurityContextResult, AcquireCredentialsHandleResult, AuthIdentity, AuthIdentityBuffers, BufferType,
    CertTrustStatus, ClientRequestFlags, ClientResponseFlags, ContextNames, ContextSizes, CredentialUse,
    DecryptionFlags, EncryptionFlags, Error, ErrorKind, FilledAcceptSecurityContext, FilledAcquireCredentialsHandle,
    FilledInitializeSecurityContext, InitializeSecurityContextResult, PACKAGE_ID_NONE, PackageCapabilities,
    PackageInfo, Secret, SecurityBuffer, SecurityBufferFlags, SecurityBufferRef, SecurityPackageType, SecurityStatus,
    ServerResponseFlags, Sspi, SspiEx, SspiImpl,
};

pub const PKG_NAME: &str = "NTLM";
pub const NTLM_VERSION_SIZE: usize = 8;
pub const DEFAULT_NTLM_VERSION: [u8; NTLM_VERSION_SIZE] = [0x0a, 0x00, 0x63, 0x45, 0x00, 0x00, 0x00, 0x0f];

pub const ENCRYPTED_RANDOM_SESSION_KEY_SIZE: usize = 16;
pub const SIGNATURE_SIZE: usize = SIGNATURE_VERSION_SIZE + SIGNATURE_CHECKSUM_SIZE + SIGNATURE_SEQ_NUM_SIZE;

const CHALLENGE_SIZE: usize = 8;
const SESSION_KEY_SIZE: usize = 16;
const MESSAGE_INTEGRITY_CHECK_SIZE: usize = 16;
const LM_CHALLENGE_RESPONSE_BUFFER_SIZE: usize = HASH_SIZE + CHALLENGE_SIZE;

const SIGNATURE_VERSION_SIZE: usize = 4;
const SIGNATURE_SEQ_NUM_SIZE: usize = 4;
const SIGNATURE_CHECKSUM_SIZE: usize = 8;
const MESSAGES_VERSION: u32 = 1;

pub static PACKAGE_INFO: LazyLock<PackageInfo> = LazyLock::new(|| PackageInfo {
    capabilities: PackageCapabilities::empty(),
    rpc_id: PACKAGE_ID_NONE,
    max_token_len: 0xb48,
    name: SecurityPackageType::Ntlm,
    comment: String::from("NTLM Security Package"),
});

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum NtlmState {
    Initial,
    Negotiate,
    Challenge,
    Authenticate,
    Completion,
    Final,
}

/// Specifies the NT LAN Manager (NTLM) Authentication Protocol, used for authentication between clients and servers.
/// NTLM is used by application protocols to authenticate remote users and, optionally, to provide session security when requested by the application.
///
/// # MSDN
///
/// * [[MS-NLMP]: NT LAN Manager (NTLM) Authentication Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b38c36ed-2804-4868-a9ff-8dd3182128e4)
#[derive(Debug, Clone)]
pub struct Ntlm {
    config: NtlmConfig,

    negotiate_message: Option<NegotiateMessage>,
    challenge_message: Option<ChallengeMessage>,
    authenticate_message: Option<AuthenticateMessage>,

    channel_bindings: Option<ChannelBindings>,

    state: NtlmState,
    flags: NegotiateFlags,
    identity: Option<AuthIdentityBuffers>,
    /// Server-side candidate credentials for authentication verification.
    /// `complete_authenticate` tries each one until it finds a match.
    allowed_identities: Option<Vec<AuthIdentityBuffers>>,
    version: [u8; NTLM_VERSION_SIZE],

    send_single_host_data: bool,

    signing: bool, // integrity
    sealing: bool, // confidentiality
    send_signing_key: Secret<[u8; HASH_SIZE]>,
    recv_signing_key: Secret<[u8; HASH_SIZE]>,
    send_sealing_key: Option<Rc4>,
    recv_sealing_key: Option<Rc4>,

    // If the NTLM is used as client, then our_seq_number is the client sequence number and remote seq_number is the server sequence number.
    // If the NTLM is used as server, then our_seq_number is the server sequence number and remote seq_number is the client sequence number.
    our_seq_number: u32,
    remote_seq_number: u32,
    // This flag is needed to correctly reset cipher state after MIC token generation/verification.
    is_client: bool,

    session_key: Option<[u8; SESSION_KEY_SIZE]>,
}

#[derive(Debug, Clone)]
struct Mic {
    value: [u8; MESSAGE_INTEGRITY_CHECK_SIZE],
    offset: u8,
}

#[derive(Debug, Clone)]
struct NegotiateMessage {
    message: Vec<u8>,
}

#[derive(Debug, Clone)]
struct ChallengeMessage {
    message: Vec<u8>,
    target_info: Vec<u8>,
    server_challenge: [u8; CHALLENGE_SIZE],
    timestamp: u64,
}

#[derive(Debug, Clone)]
struct AuthenticateMessage {
    message: Vec<u8>,
    mic: Option<Mic>,
    target_info: Vec<u8>,
    client_challenge: [u8; CHALLENGE_SIZE],
    encrypted_random_session_key: Option<[u8; ENCRYPTED_RANDOM_SESSION_KEY_SIZE]>,
}

impl Ntlm {
    pub fn new() -> Self {
        Self {
            config: NtlmConfig::default(),

            negotiate_message: None,
            challenge_message: None,
            authenticate_message: None,

            channel_bindings: None,

            state: NtlmState::Initial,
            flags: NegotiateFlags::empty(),
            identity: None,
            allowed_identities: None,
            version: DEFAULT_NTLM_VERSION,

            send_single_host_data: false,

            signing: true,
            sealing: true,
            send_signing_key: Secret::new([0x00; HASH_SIZE]),
            recv_signing_key: Secret::new([0x00; HASH_SIZE]),
            send_sealing_key: None,
            recv_sealing_key: None,
            session_key: None,

            our_seq_number: 0,
            remote_seq_number: 0,
            is_client: true,
        }
    }

    pub fn with_config(config: NtlmConfig) -> Self {
        Self {
            config,

            negotiate_message: None,
            challenge_message: None,
            authenticate_message: None,

            channel_bindings: None,

            state: NtlmState::Initial,
            flags: NegotiateFlags::empty(),
            identity: None,
            allowed_identities: None,
            version: DEFAULT_NTLM_VERSION,

            send_single_host_data: false,

            signing: true,
            sealing: true,
            send_signing_key: Secret::new([0x00; HASH_SIZE]),
            recv_signing_key: Secret::new([0x00; HASH_SIZE]),
            send_sealing_key: None,
            recv_sealing_key: None,
            session_key: None,

            our_seq_number: 0,
            remote_seq_number: 0,
            is_client: true,
        }
    }

    pub fn with_auth_identity(identity: Option<AuthIdentityBuffers>, config: NtlmConfig) -> Self {
        Self {
            config,

            negotiate_message: None,
            challenge_message: None,
            authenticate_message: None,

            channel_bindings: None,

            state: NtlmState::Initial,
            flags: NegotiateFlags::empty(),
            identity,
            allowed_identities: None,
            version: DEFAULT_NTLM_VERSION,

            send_single_host_data: false,

            signing: true,
            sealing: true,
            send_signing_key: Secret::new([0x00; HASH_SIZE]),
            recv_signing_key: Secret::new([0x00; HASH_SIZE]),
            send_sealing_key: None,
            recv_sealing_key: None,
            session_key: None,

            our_seq_number: 0,
            remote_seq_number: 0,
            is_client: true,
        }
    }

    fn config(&self) -> &NtlmConfig {
        &self.config
    }

    pub fn set_version(&mut self, version: [u8; NTLM_VERSION_SIZE]) {
        self.version = version;
    }

    /// Sets the channel bindings for the session to the appropriately formatted structure
    /// containing the token, passed as the argument, calculated according to the RFC 5929
    /// procedure for the `tls-server-end-point` channel binding type. The MD5 hash of this
    /// structure will be transmitted to the server as an AVPair in the AUTHENTICATE message.
    pub fn set_channel_bindings(&mut self, token: &[u8]) {
        self.channel_bindings = Some(ChannelBindings {
            initiator_addr_type: 0,
            initiator: vec![],
            acceptor_addr_type: 0,
            acceptor: vec![],
            application_data: token.to_vec(),
        });
    }

    /// Resets the cipher state.
    ///
    /// According to the specification, we need to reset ciphers before and after MIC token generation/verification.
    /// [3.2.5.1 NTLM RC4 Key State for MechListMIC and First Signed Message](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/f38ae8e3-847d-4829-b933-5ac1911a00ba):
    /// > When NTLM is negotiated, the SPNG server MUST set OriginalHandle to ServerHandle before generating the mechListMIC,
    /// > then set ServerHandle to OriginalHandle after generating the mechListMIC. This results in the RC4 key state
    /// > being the same for the mechListMIC and for the first message signed by the application.
    /// >
    /// > Because the RC4 key state is the same for the mechListMIC and for the first message signed by the application,
    /// > the SPNEGO Extension server MUST set OriginalHandle to ClientHandle before validating the mechListMIC and then
    /// > set ClientHandle to OriginalHandle after validating the mechListMIC.
    fn reset_cipher_state(&mut self) -> crate::Result<()> {
        use crate::ntlm::messages::computations::generate_signing_key;
        use crate::ntlm::messages::{CLIENT_SEAL_MAGIC, CLIENT_SIGN_MAGIC, SERVER_SEAL_MAGIC, SERVER_SIGN_MAGIC};

        let session_key = self.session_key.as_ref().ok_or_else(|| {
            Error::new(
                ErrorKind::OutOfSequence,
                "the session key is not established, cannot reset cipher state",
            )
        })?;

        if self.is_client {
            self.send_signing_key = generate_signing_key(session_key.as_ref(), CLIENT_SIGN_MAGIC);
            self.recv_signing_key = generate_signing_key(session_key.as_ref(), SERVER_SIGN_MAGIC);
            self.send_sealing_key = Some(Rc4::new(
                generate_signing_key(session_key.as_ref(), CLIENT_SEAL_MAGIC).as_ref(),
            ));
            self.recv_sealing_key = Some(Rc4::new(
                generate_signing_key(session_key.as_ref(), SERVER_SEAL_MAGIC).as_ref(),
            ));
        } else {
            self.send_signing_key = generate_signing_key(session_key, SERVER_SIGN_MAGIC);
            self.recv_signing_key = generate_signing_key(session_key, CLIENT_SIGN_MAGIC);
            self.send_sealing_key = Some(Rc4::new(generate_signing_key(session_key, SERVER_SEAL_MAGIC).as_ref()));
            self.recv_sealing_key = Some(Rc4::new(generate_signing_key(session_key, CLIENT_SEAL_MAGIC).as_ref()));
        }

        Ok(())
    }

    /// Returns the next sequence number for outgoing messages and increments the internal counter.
    fn our_seq_num(&mut self) -> u32 {
        let seq_num = self.our_seq_number;
        self.our_seq_number = self.our_seq_number.wrapping_add(1);

        seq_num
    }

    /// Returns the next sequence number for incoming messages and increments the internal counter.
    ///
    /// This value is used to check the sequence number of the received message.
    fn remote_seq_num(&mut self) -> u32 {
        let seq_num = self.remote_seq_number;
        self.remote_seq_number = self.remote_seq_number.wrapping_add(1);

        seq_num
    }
}

impl Default for Ntlm {
    fn default() -> Self {
        Self::with_config(Default::default())
    }
}

impl SspiImpl for Ntlm {
    type CredentialsHandle = Option<AuthIdentityBuffers>;
    type AuthenticationData = AuthIdentity;

    #[instrument(level = "trace", ret, fields(state = ?self.state), skip(self))]
    fn acquire_credentials_handle_impl(
        &mut self,
        builder: FilledAcquireCredentialsHandle<'_, Self::CredentialsHandle, Self::AuthenticationData>,
    ) -> crate::Result<AcquireCredentialsHandleResult<Self::CredentialsHandle>> {
        if builder.credential_use == CredentialUse::Outbound && builder.auth_data.is_none() {
            return Err(Error::new(
                ErrorKind::NoCredentials,
                "The client must specify the auth data",
            ));
        }

        self.identity = builder.auth_data.cloned().map(AuthIdentityBuffers::from);

        Ok(AcquireCredentialsHandleResult {
            credentials_handle: self.identity.clone(),
            expiry: None,
        })
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self, builder))]
    fn accept_security_context_impl<'a>(
        &'a mut self,
        builder: FilledAcceptSecurityContext<'a, Self::CredentialsHandle>,
    ) -> crate::Result<GeneratorAcceptSecurityContext<'a>> {
        Ok(GeneratorAcceptSecurityContext::new(move |_yield_point| async move {
            self.accept_security_context_impl(builder)
        }))
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip_all)]
    fn initialize_security_context_impl<'ctx, 'b, 'g>(
        &'ctx mut self,
        builder: &'b mut FilledInitializeSecurityContext<'ctx, 'ctx, Self::CredentialsHandle>,
    ) -> crate::Result<GeneratorInitSecurityContext<'g>>
    where
        'ctx: 'g,
        'b: 'g,
    {
        Ok(self.initialize_security_context_impl(builder).into())
    }
}

impl Ntlm {
    pub(crate) fn accept_security_context_impl(
        &mut self,
        builder: FilledAcceptSecurityContext<'_, <Self as SspiImpl>::CredentialsHandle>,
    ) -> crate::Result<AcceptSecurityContextResult> {
        self.is_client = false;

        let input = builder
            .input
            .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Input buffers must be specified"))?;
        let status = match self.state {
            NtlmState::Initial => {
                let input_token = SecurityBuffer::find_buffer(input, BufferType::Token)?;
                let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;

                self.state = NtlmState::Negotiate;
                server::read_negotiate(self, input_token.buffer.as_slice())?;

                server::write_challenge(self, &mut output_token.buffer)?
            }
            NtlmState::Authenticate => {
                let input_token = SecurityBuffer::find_buffer(input, BufferType::Token)?;

                let identity = builder.credentials_handle.cloned().flatten();
                self.allowed_identities = identity.as_ref().map(|id| vec![id.clone()]);
                self.identity = identity;

                if let Ok(sec_buffer) = SecurityBuffer::find_buffer(input, BufferType::ChannelBindings) {
                    self.channel_bindings = Some(ChannelBindings::from_bytes(&sec_buffer.buffer)?);
                }

                server::read_authenticate(self, input_token.buffer.as_slice())?
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::OutOfSequence,
                    format!("got wrong NTLM state: {:?}", self.state),
                ));
            }
        };

        Ok(AcceptSecurityContextResult {
            status,
            flags: ServerResponseFlags::empty(),
            expiry: None,
        })
    }

    pub(crate) fn initialize_security_context_impl(
        &mut self,
        builder: &mut FilledInitializeSecurityContext<'_, '_, <Self as SspiImpl>::CredentialsHandle>,
    ) -> crate::Result<InitializeSecurityContextResult> {
        self.is_client = true;

        trace!(?builder);

        let status = match self.state {
            NtlmState::Initial => {
                let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
                self.state = NtlmState::Negotiate;

                self.signing = builder.context_requirements.contains(ClientRequestFlags::INTEGRITY);
                self.sealing = builder
                    .context_requirements
                    .contains(ClientRequestFlags::CONFIDENTIALITY);

                // ISC_REQ_USE_DCE_STYLE implies full signing and sealing, matching Windows SSPI
                // behavior where DCE-style NTLM always negotiates SEAL+KEY_EXCH regardless of
                // whether INTEGRITY/CONFIDENTIALITY were explicitly requested.
                if builder.context_requirements.contains(ClientRequestFlags::USE_DCE_STYLE) {
                    self.sealing = true;
                }

                if self.sealing {
                    self.signing = true; // sealing implies signing
                }

                client::write_negotiate(self, &mut output_token.buffer)?
            }
            NtlmState::Challenge => {
                let input = builder.input.as_ref().ok_or_else(|| {
                    Error::new(
                        ErrorKind::InvalidToken,
                        "Input buffers must be specified on subsequent calls",
                    )
                })?;
                let input_token = SecurityBuffer::find_buffer(input, BufferType::Token)?;
                let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;

                // Pick up a caller-supplied channel binding (e.g. tls-server-end-point)
                // so write_authenticate can stamp it into the Type-3 message. NTLM under
                // Strict EPA (WinRM over HTTPS) needs this. The acceptor path and the
                // Kerberos client read the buffer the same way; without it the client
                // ignores the CBT buffer.
                if let Ok(sec_buffer) = SecurityBuffer::find_buffer(input, BufferType::ChannelBindings) {
                    self.channel_bindings = Some(ChannelBindings::from_bytes(&sec_buffer.buffer)?);
                }

                client::read_challenge(self, input_token.buffer.as_slice())?;

                client::write_authenticate(
                    self,
                    builder
                        .credentials_handle
                        .as_ref()
                        .expect("CredentialsHandle must be passed to the method")
                        .as_ref()
                        .expect("CredentialsHandle must be Some for the client's method"),
                    &mut output_token.buffer,
                )?
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::OutOfSequence,
                    format!("Got wrong NTLM state: {:?}", self.state),
                ));
            }
        };

        trace!(output_buffers = ?builder.output);

        Ok(InitializeSecurityContextResult {
            status,
            flags: ClientResponseFlags::empty(),
            expiry: None,
        })
    }

    fn compute_checksum(
        &mut self,
        message: &mut [SecurityBufferRef<'_>],
        sequence_number: u32,
        digest: &[u8; 16],
    ) -> crate::Result<()> {
        let checksum: [u8; SIGNATURE_CHECKSUM_SIZE] =
            if self.flags.contains(NegotiateFlags::NTLM_SSP_NEGOTIATE_KEY_EXCH) {
                self.send_sealing_key
                    .as_mut()
                    .expect("NTLM send_sealing_key must be set")
                    .process(&digest[0..SIGNATURE_CHECKSUM_SIZE])
                    .try_into()
                    .expect("checksum must be SIGNATURE_CHECKSUM_SIZE bytes long")
            } else {
                digest[0..SIGNATURE_CHECKSUM_SIZE]
                    .try_into()
                    .expect("checksum must be SIGNATURE_CHECKSUM_SIZE bytes long")
            };

        let signature_buffer = SecurityBufferRef::find_buffer_mut(message, BufferType::Token)?;
        if signature_buffer.buf_len() < SIGNATURE_SIZE {
            return Err(Error::new(ErrorKind::BufferTooSmall, "the Token buffer is too small"));
        }
        let signature = compute_signature(&checksum, sequence_number);
        signature_buffer.write_data(signature.as_slice())?;

        Ok(())
    }

    fn check_signature(&mut self, sequence_number: u32, digest: &[u8; 16], signature: &[u8]) -> crate::Result<()> {
        let checksum: [u8; SIGNATURE_CHECKSUM_SIZE] =
            if self.flags.contains(NegotiateFlags::NTLM_SSP_NEGOTIATE_KEY_EXCH) {
                self.recv_sealing_key
                    .as_mut()
                    .expect("NTLM recv_sealing_key must be set")
                    .process(&digest[0..SIGNATURE_CHECKSUM_SIZE])
                    .try_into()
                    .expect("checksum must be SIGNATURE_CHECKSUM_SIZE bytes long")
            } else {
                digest[0..SIGNATURE_CHECKSUM_SIZE]
                    .try_into()
                    .expect("checksum must be SIGNATURE_CHECKSUM_SIZE bytes long")
            };

        let expected_signature = compute_signature(&checksum, sequence_number);

        if signature != expected_signature.as_ref() {
            return Err(Error::new(
                ErrorKind::MessageAltered,
                "signature verification failed, something nasty is going on",
            ));
        }

        Ok(())
    }
}

impl Sspi for Ntlm {
    #[instrument(level = "debug", ret, fields(state = ?self.state), skip_all)]
    fn complete_auth_token(&mut self, _token: &mut [SecurityBuffer]) -> crate::Result<SecurityStatus> {
        server::complete_authenticate(self)
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self, _flags))]
    fn encrypt_message(
        &mut self,
        _flags: EncryptionFlags,
        message: &mut [SecurityBufferRef<'_>],
    ) -> crate::Result<SecurityStatus> {
        if self.send_sealing_key.is_none() {
            self.complete_auth_token(&mut [])?;
        }

        // Check if exists.
        SecurityBufferRef::find_buffer_mut(message, BufferType::Token)?;

        // Find `Data` buffers for MAC computation. Include all data buffers regardless of flags:
        // NTLM includes SECBUFFER_READONLY data in the MAC (Windows behavior), it just doesn't
        // encrypt those buffers in-place.
        let data_to_sign =
            SecurityBufferRef::buffers_of_type(message, BufferType::Data).fold(Vec::new(), |mut acc, buffer| {
                acc.extend_from_slice(buffer.data());
                acc
            });

        let sequence_number = self.our_seq_num();

        let digest = compute_digest(self.send_signing_key.as_ref(), sequence_number, &data_to_sign)?;

        // Encrypt writable Data buffers in-place. If all data buffers are SECBUFFER_READONLY,
        // skip encryption (sign-only mode). The RC4 state is not advanced for skipped buffers,
        // matching the server's DecryptMessage behavior which also skips READONLY buffers.
        if let Some(data) =
            SecurityBufferRef::buffers_of_type_and_flags_mut(message, BufferType::Data, SecurityBufferFlags::NONE)
                .next()
        {
            let encrypted_data = self.send_sealing_key.as_mut().unwrap().process(data.data());
            if encrypted_data.len() < data.buf_len() {
                return Err(Error::new(ErrorKind::BufferTooSmall, "the Data buffer is too small"));
            }
            data.write_data(&encrypted_data)?;
        }

        self.compute_checksum(message, sequence_number, &digest)?;

        Ok(SecurityStatus::Ok)
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn decrypt_message(&mut self, message: &mut [SecurityBufferRef<'_>]) -> crate::Result<DecryptionFlags> {
        if self.recv_sealing_key.is_none() {
            self.complete_auth_token(&mut [])?;
        }

        let encrypted = extract_encrypted_data(message)?;

        if encrypted.len() < 16 {
            return Err(Error::new(ErrorKind::MessageAltered, "invalid encrypted message size"));
        }

        let (signature, encrypted_message) = encrypted.split_at(16);
        let sequence_number = u32::from_le_bytes(signature[12..].try_into().expect("signature must be 16 bytes long"));

        let expected_seq_number = self.remote_seq_num();
        if sequence_number != expected_seq_number {
            return Err(Error::new(
                ErrorKind::MessageAltered,
                format!(
                    "invalid incoming message sequence number: expected {expected_seq_number} but got {sequence_number}",
                ),
            ));
        }

        let decrypted = self.recv_sealing_key.as_mut().unwrap().process(encrypted_message);

        if !decrypted.is_empty() {
            save_decrypted_data(&decrypted, message)?;
        }

        let data_to_sign =
            SecurityBufferRef::buffers_of_type(message, BufferType::Data).fold(Vec::new(), |mut acc, buffer| {
                // Find `Data` buffers for MAC computation. Include all data buffers regardless of flags:
                // NTLM includes SECBUFFER_READONLY data in the MAC (Windows behavior), it just doesn't
                // encrypt those buffers in-place.
                if buffer
                    .buffer_flags()
                    .contains(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM)
                    || buffer.buffer_flags().contains(SecurityBufferFlags::SECBUFFER_READONLY)
                {
                    acc.extend_from_slice(buffer.data());
                } else {
                    // The `Data` buffer contains encrypted data, but the checksum was calculated over the decrypted data.
                    // So, we replace encrypted data with decrypted one.
                    acc.extend_from_slice(&decrypted);
                }

                acc
            });

        let digest = compute_digest(self.recv_signing_key.as_ref(), sequence_number, &data_to_sign)?;
        self.check_signature(sequence_number, &digest, signature)?;

        Ok(DecryptionFlags::empty())
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn query_context_sizes(&mut self) -> crate::Result<ContextSizes> {
        Ok(ContextSizes {
            max_token: 2010,
            max_signature: 16,
            block: 0,
            security_trailer: 16,
        })
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn query_context_names(&mut self) -> crate::Result<ContextNames> {
        if let Some(identity_buffers) = &self.identity {
            let identity =
                AuthIdentity::try_from(identity_buffers).map_err(|e| Error::new(ErrorKind::InvalidParameter, e))?;

            Ok(ContextNames {
                username: identity.username,
            })
        } else {
            Err(Error::new(
                ErrorKind::NoCredentials,
                "Requested Names, but no credentials were provided",
            ))
        }
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn query_context_package_info(&mut self) -> crate::Result<PackageInfo> {
        crate::query_security_package_info(SecurityPackageType::Ntlm)
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn query_context_cert_trust_status(&mut self) -> crate::Result<CertTrustStatus> {
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "Certificate trust status is not supported",
        ))
    }

    #[instrument(level = "debug", fields(state = ?self.state), skip(self))]
    fn query_context_session_key(&self) -> crate::Result<crate::SessionKeys> {
        if let Some(session_key) = self.session_key {
            Ok(crate::SessionKeys {
                session_key: session_key.to_vec().into(),
            })
        } else {
            Err(Error::new(
                ErrorKind::OutOfSequence,
                "the session key is not established",
            ))
        }
    }

    fn change_password(
        &mut self,
        _: crate::builders::ChangePassword<'_>,
    ) -> crate::Result<crate::generator::GeneratorChangePassword<'_>> {
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "NTLM does not support change pasword",
        ))
    }

    fn make_signature(
        &mut self,
        _flags: u32,
        message: &mut [SecurityBufferRef<'_>],
        sequence_number: u32,
    ) -> crate::Result<()> {
        if self.send_sealing_key.is_none() {
            self.complete_auth_token(&mut [])?;
        }

        SecurityBufferRef::find_buffer(message, BufferType::Token)?; // check if exists

        let data = SecurityBufferRef::find_buffer_mut(message, BufferType::Data)?;
        let digest = compute_digest(self.send_signing_key.as_ref(), sequence_number, data.data())?;

        self.compute_checksum(message, sequence_number, &digest)?;

        Ok(())
    }

    fn verify_signature(&mut self, message: &mut [SecurityBufferRef<'_>], sequence_number: u32) -> crate::Result<u32> {
        if self.recv_sealing_key.is_none() {
            self.complete_auth_token(&mut [])?;
        }

        SecurityBufferRef::find_buffer(message, BufferType::Token)?; // check if exists

        let data = SecurityBufferRef::find_buffer(message, BufferType::Data)?;
        let digest = compute_digest(self.recv_signing_key.as_ref(), sequence_number, data.data())?;

        let signature = SecurityBufferRef::find_buffer(message, BufferType::Token)?;
        self.check_signature(sequence_number, &digest, signature.data())?;

        Ok(0)
    }
}

impl SspiEx for Ntlm {
    #[instrument(level = "trace", ret, fields(state = ?self.state), skip(self))]
    fn custom_set_auth_identity(&mut self, identity: Self::AuthenticationData) -> crate::Result<()> {
        // If `self.identity` is already set, it means that the NTLM has accepted the final authentication message,
        // and read username/domain from it. In this case, we only update the password.
        if let Some(credentials) = &mut self.identity {
            if credentials.password.as_ref().as_ref().is_empty() {
                let identity: AuthIdentityBuffers = identity.into();
                credentials.password = identity.password;
            }
        } else {
            self.identity = Some(identity.into());
        }

        self.allowed_identities = self.identity.as_ref().map(|id| vec![id.clone()]);

        Ok(())
    }

    #[instrument(level = "trace", ret, fields(state = ?self.state), skip(self))]
    fn custom_set_auth_identities(&mut self, identities: Vec<Self::AuthenticationData>) -> crate::Result<()> {
        if identities.is_empty() {
            return Err(Error::new(ErrorKind::NoCredentials, "no credentials provided"));
        }

        // Set identity from the first candidate (for wire user/domain
        // during complete_authenticate), without going through
        // custom_set_auth_identity which would also set allowed_identities.
        if let Some(credentials) = &mut self.identity {
            if credentials.password.as_ref().as_ref().is_empty() {
                let identity: AuthIdentityBuffers = identities[0].clone().into();
                credentials.password = identity.password;
            }
        } else {
            self.identity = Some(identities[0].clone().into());
        }

        self.allowed_identities = Some(identities.into_iter().map(AuthIdentityBuffers::from).collect());

        Ok(())
    }

    fn verify_mic_token(&mut self, signature: &[u8], data: &[u8], _: crate::private::Sealed) -> crate::Result<()> {
        // We reset the cipher state before and after MIC token verification.
        //
        // [3.2.5.1 NTLM RC4 Key State for MechListMIC and First Signed Message](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/f38ae8e3-847d-4829-b933-5ac1911a00ba):
        // > When NTLM is negotiated, the SPNG server MUST set OriginalHandle to ServerHandle before generating the mechListMIC,
        // > then set ServerHandle to OriginalHandle after generating the mechListMIC. This results in the RC4 key state
        // > being the same for the mechListMIC and for the first message signed by the application.
        // >
        // > Because the RC4 key state is the same for the mechListMIC and for the first message signed by the application,
        // > the SPNEGO Extension server MUST set OriginalHandle to ClientHandle before validating the mechListMIC and then
        // > set ClientHandle to OriginalHandle after validating the mechListMIC.

        if self.recv_sealing_key.is_none() {
            self.complete_auth_token(&mut [])?;
        } else {
            self.reset_cipher_state()?;
        }

        let seq_number = self.remote_seq_num();

        let digest = compute_digest(self.recv_signing_key.as_ref(), seq_number, data)?;
        self.check_signature(seq_number, &digest, signature)?;

        self.reset_cipher_state()?;

        Ok(())
    }

    fn generate_mic_token(&mut self, data: &[u8], _: crate::private::Sealed) -> crate::Result<Vec<u8>> {
        // We reset the cipher state before and after MIC token generation.
        //
        // [3.2.5.1 NTLM RC4 Key State for MechListMIC and First Signed Message](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/f38ae8e3-847d-4829-b933-5ac1911a00ba):
        // > When NTLM is negotiated, the SPNG server MUST set OriginalHandle to ServerHandle before generating the mechListMIC,
        // > then set ServerHandle to OriginalHandle after generating the mechListMIC. This results in the RC4 key state
        // > being the same for the mechListMIC and for the first message signed by the application.
        // >
        // > Because the RC4 key state is the same for the mechListMIC and for the first message signed by the application,
        // > the SPNEGO Extension server MUST set OriginalHandle to ClientHandle before validating the mechListMIC and then
        // > set ClientHandle to OriginalHandle after validating the mechListMIC.

        if self.send_sealing_key.is_none() {
            self.complete_auth_token(&mut [])?;
        } else {
            self.reset_cipher_state()?;
        }

        let seq_number = self.our_seq_num();

        let digest = compute_digest(self.send_signing_key.as_ref(), seq_number, data)?;

        let mut mic_token = vec![0; SIGNATURE_SIZE];
        let mut message = [SecurityBufferRef::token_buf(&mut mic_token)];
        self.compute_checksum(&mut message, seq_number, &digest)?;

        self.reset_cipher_state()?;

        Ok(mic_token)
    }
}

impl NegotiateMessage {
    fn new(message: Vec<u8>) -> Self {
        Self { message }
    }
}

impl ChallengeMessage {
    fn new(message: Vec<u8>, target_info: Vec<u8>, server_challenge: [u8; CHALLENGE_SIZE], timestamp: u64) -> Self {
        Self {
            message,
            target_info,
            server_challenge,
            timestamp,
        }
    }
}

impl AuthenticateMessage {
    fn new(
        message: Vec<u8>,
        mic: Option<Mic>,
        target_info: Vec<u8>,
        client_challenge: [u8; CHALLENGE_SIZE],
        encrypted_random_session_key: Option<[u8; ENCRYPTED_RANDOM_SESSION_KEY_SIZE]>,
    ) -> Self {
        Self {
            message,
            mic,
            target_info,
            client_challenge,
            encrypted_random_session_key,
        }
    }
}

impl Mic {
    fn new(value: [u8; MESSAGE_INTEGRITY_CHECK_SIZE], offset: u8) -> Self {
        Self { value, offset }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct NegotiateFlags: u32 {
        /// W-bit
        /// requests 56-bit encryption
        const NTLM_SSP_NEGOTIATE56 = 0x8000_0000;

        /// V-bit
        /// requests explicit key exchange
        const NTLM_SSP_NEGOTIATE_KEY_EXCH = 0x4000_0000;

        /// U-bit
        /// requests an 128 bit session key
        const NTLM_SSP_NEGOTIATE128 = 0x2000_0000;

        /// r1
        const NTLM_SSP_NEGOTIATE_RESERVED1  = 0x1000_0000;

        /// r2
        const NTLM_SSP_NEGOTIATE_RESERVED2 = 0x0800_0000;

        /// r3
        const NTLM_SSP_NEGOTIATE_RESERVED3 = 0x0400_0000;

        /// r6
        const NTLM_SSP_NEGOTIATE_VERSION = 0x0200_0000;

        /// r4
        const NTLM_SSP_NEGOTIATE_RESERVED4 = 0x0100_0000;

        /// S-bit
        const NTLM_SSP_NEGOTIATE_TARGET_INFO = 0x0080_0000;

        /// R
        const NTLM_SSP_NEGOTIATE_REQUEST_NON_NT_SESSION_KEY = 0x0040_0000;

        /// r5
        const NTLM_SSP_NEGOTIATE_RESERVED5 = 0x0020_0000;

        /// Q
        const NTLM_SSP_NEGOTIATE_IDENTIFY = 0x0010_0000;

        /// P-bit
        /// NTLMv2 Session Security
        const NTLM_SSP_NEGOTIATE_EXTENDED_SESSION_SECURITY = 0x0008_0000;

        /// r6
        const NTLM_SSP_NEGOTIATE_RESERVED6 = 0x0004_0000;

        /// O
        const NTLM_SSP_NEGOTIATE_TARGET_TYPE_SERVER = 0x0002_0000;

        /// N
        const NTLM_SSP_NEGOTIATE_TARGET_TYPE_DOMAIN = 0x0001_0000;

        /// M-bit
        /// requests a signature block
        const NTLM_SSP_NEGOTIATE_ALWAYS_SIGN = 0x0000_8000;

        /// r7
        const NTLM_SSP_NEGOTIATE_RESERVED7 = 0x0000_4000;

        /// L-bit
        const NTLM_SSP_NEGOTIATE_WORKSTATION_SUPPLIED = 0x0000_2000;

        /// K-bit
        const NTLM_SSP_NEGOTIATE_DOMAIN_SUPPLIED = 0x0000_1000;

        /// J
        const NTLM_SSP_NEGOTIATE_ANONYMOUS = 0x0000_0800;

        /// r8
        const NTLM_SSP_NEGOTIATE_RESERVED8 = 0x0000_0400;

        /// H-bit
        /// NTLMv1 Session Security, deprecated, insecure and not supported by us
        const NTLM_SSP_NEGOTIATE_NTLM = 0x0000_0200;

        /// r9
        const NTLM_SSP_NEGOTIATE_RESERVED9 = 0x0000_0100;

        /// G-bit
        /// LM Session Security, deprecated, insecure and not supported by us
        const NTLM_SSP_NEGOTIATE_LM_KEY = 0x0000_0080;

        /// F
        const NTLM_SSP_NEGOTIATE_DATAGRAM = 0x0000_0040;

        /// E-bit
        /// session key negotiation with message confidentiality
        const NTLM_SSP_NEGOTIATE_SEAL = 0x0000_0020;

        /// D-bit
        const NTLM_SSP_NEGOTIATE_SIGN = 0x0000_0010;

        /// r10
        const NTLM_SSP_NEGOTIATE_SIGN_RESERVED10 = 0x0000_0008;

        /// C-bit
        const NTLM_SSP_NEGOTIATE_REQUEST_TARGET = 0x0000_0004;

        /// B-bit
        const NTLM_SSP_NEGOTIATE_OEM = 0x0000_0002;

        /// A-bit
        const NTLM_SSP_NEGOTIATE_UNICODE = 0x0000_0001;
    }
}

fn compute_digest(key: &[u8], seq_num: u32, data: &[u8]) -> io::Result<[u8; 16]> {
    let mut digest_data = Vec::with_capacity(SIGNATURE_SEQ_NUM_SIZE + data.len());
    digest_data.write_u32::<LittleEndian>(seq_num)?;
    digest_data.extend_from_slice(data);

    compute_hmac_md5(key, &digest_data)
}

fn compute_signature(checksum: &[u8], seq_num: u32) -> [u8; SIGNATURE_SIZE] {
    let mut signature = [0x00; SIGNATURE_SIZE];
    signature[..SIGNATURE_VERSION_SIZE].clone_from_slice(&MESSAGES_VERSION.to_le_bytes());
    signature[SIGNATURE_VERSION_SIZE..SIGNATURE_VERSION_SIZE + SIGNATURE_CHECKSUM_SIZE].clone_from_slice(checksum);
    signature[SIGNATURE_VERSION_SIZE + SIGNATURE_CHECKSUM_SIZE..].clone_from_slice(&seq_num.to_le_bytes());

    signature
}

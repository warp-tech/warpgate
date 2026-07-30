mod cipher_block_size;
mod tls_connection;

use std::sync::{Arc, LazyLock};

use async_recursion::async_recursion;
use picky_asn1_x509::Certificate;
use rand::rngs::{StdRng, SysRng};
use rand_core::{Rng as _, SeedableRng as _};
use rustls::client::ClientConfig;
use rustls::{ClientConnection, Connection};

use self::tls_connection::{TlsConnection, danger};
use super::ts_request::NONCE_SIZE;
use super::{CredSspContext, CredSspMode, EndpointType, SspiContext, TsRequest};
use crate::credssp::sspi_cred_ssp::tls_connection::{DecryptionResult, DecryptionResultBuffers};
use crate::generator::{
    GeneratorAcceptSecurityContext, GeneratorChangePassword, GeneratorInitSecurityContext, YieldPointLocal,
};
use crate::{
    AcquireCredentialsHandleResult, BufferType, CertContext, CertEncodingType, CertTrustErrorStatus,
    CertTrustInfoStatus, CertTrustStatus, ClientRequestFlags, ClientResponseFlags, ConnectionInfo, ContextNames,
    ContextSizes, CredentialUse, Credentials, CredentialsBuffers, DataRepresentation, DecryptionFlags, EncryptionFlags,
    Error, ErrorKind, InitializeSecurityContextResult, PACKAGE_ID_NONE, PackageCapabilities, PackageInfo, Result,
    SecurityBuffer, SecurityBufferRef, SecurityPackageType, SecurityStatus, Sspi, SspiEx, SspiImpl, StreamSizes,
    builders, negotiate,
};

pub const PKG_NAME: &str = "CREDSSP";

pub static PACKAGE_INFO: LazyLock<PackageInfo> = LazyLock::new(|| PackageInfo {
    capabilities: PackageCapabilities::empty(),
    rpc_id: PACKAGE_ID_NONE,
    max_token_len: negotiate::PACKAGE_INFO.max_token_len + 1,
    name: SecurityPackageType::CredSsp,
    comment: String::from("CredSsp security package"),
});

#[derive(Debug, Clone)]
enum CredSspState {
    Tls,
    NegoToken,
    AuthInfo,
    Final,
}

#[derive(Debug)]
pub struct SspiCredSsp {
    state: CredSspState,
    cred_ssp_context: Box<CredSspContext>,
    auth_identity: Option<CredentialsBuffers>,
    // The TLS connection object will be set on the first initialize security context function call.
    // We need to specify the correct hostname which we'll know only during actual auth.
    tls_connection: Option<TlsConnection>,
    nonce: Option<[u8; NONCE_SIZE]>,
}

impl SspiCredSsp {
    pub fn new_client(sspi_context: SspiContext) -> Result<Self> {
        crate::rustls::install_default_crypto_provider_if_necessary().map_err(|()| {
            Error::new(
                ErrorKind::SecurityPackageNotFound,
                "failed to install the default crypto provider for TLS",
            )
        })?;

        let mut nonce = [0; NONCE_SIZE];
        let mut rand = StdRng::try_from_rng(&mut SysRng)?;
        rand.fill_bytes(&mut nonce);

        Ok(Self {
            state: CredSspState::Tls,
            cred_ssp_context: Box::new(CredSspContext::new(sspi_context)),
            auth_identity: None,
            tls_connection: None,
            nonce: Some(nonce),
        })
    }

    /// * `sspi_context` is a security package that will be used for authorization
    pub fn new_server(sspi_context: SspiContext) -> Result<Self> {
        crate::rustls::install_default_crypto_provider_if_necessary().map_err(|()| {
            Error::new(
                ErrorKind::SecurityPackageNotFound,
                "failed to install the default crypto provider for TLS",
            )
        })?;

        Ok(Self {
            state: CredSspState::Tls,
            cred_ssp_context: Box::new(CredSspContext::new(sspi_context)),
            auth_identity: None,
            tls_connection: None,
            // nonce for the server will be in the incoming TsRequest
            nonce: None,
        })
    }

    fn raw_peer_public_key(&mut self) -> Result<Vec<u8>> {
        let peer_certificate = self.query_context_remote_cert()?.cert;

        let raw_public_key = match peer_certificate
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
        {
            picky_asn1_x509::PublicKey::Rsa(rsa_pk) => picky_asn1_der::to_vec(&rsa_pk.0)?,
            picky_asn1_x509::PublicKey::Ec(ec) => picky_asn1_der::to_vec(&ec)?,
            picky_asn1_x509::PublicKey::Ed(ed) => picky_asn1_der::to_vec(&ed)?,
            picky_asn1_x509::PublicKey::Mldsa(mldsa) => picky_asn1_der::to_vec(&mldsa)?,
        };

        Ok(raw_public_key)
    }

    fn decrypt_and_decode_ts_request(&mut self, input: &mut [SecurityBuffer]) -> Result<TsRequest> {
        let encrypted_ts_request = SecurityBuffer::find_buffer_mut(input, BufferType::Token)?;
        let DecryptionResult::Success(DecryptionResultBuffers {
            header: _,
            decrypted: raw_ts_request,
            extra: _,
        }) = self
            .tls_connection_mut()?
            .decrypt_tls(&mut encrypted_ts_request.buffer)?
        else {
            return Err(Error::new(ErrorKind::IncompleteMessage, "Input token is too short"));
        };

        let ts_request = TsRequest::from_buffer(raw_ts_request)?;
        ts_request.check_error()?;

        Ok(ts_request)
    }

    fn tls_connection_mut(&mut self) -> Result<&mut TlsConnection> {
        self.tls_connection
            .as_mut()
            .ok_or_else(|| Error::new(ErrorKind::OutOfSequence, "TLS connection is not yet established"))
    }

    fn tls_connection(&mut self) -> Result<&TlsConnection> {
        self.tls_connection
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::OutOfSequence, "TLS connection is not yet established"))
    }
}

impl Sspi for SspiCredSsp {
    #[instrument(level = "debug", ret, fields(state = ?self.state), skip_all)]
    fn complete_auth_token(&mut self, _token: &mut [SecurityBuffer]) -> Result<SecurityStatus> {
        Ok(SecurityStatus::Ok)
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self, _flags))]
    fn encrypt_message(
        &mut self,
        _flags: EncryptionFlags,
        message: &mut [SecurityBufferRef<'_>],
    ) -> Result<SecurityStatus> {
        // CredSsp decrypt_message function just calls corresponding function from the Schannel
        // MSDN: message must contain four buffers
        // https://learn.microsoft.com/en-us/windows/win32/secauthn/decryptmessage--schannel
        if message.len() < 4 {
            return Err(Error::new(
                ErrorKind::InvalidParameter,
                "Input message must contain four buffers",
            ));
        }

        let plain_message = SecurityBufferRef::find_buffer_mut(message, BufferType::Data)?;

        let encrypted_data = self.tls_connection_mut()?.encrypt_tls(plain_message.data())?;
        let encrypted_data = encrypted_data.as_slice();

        let stream_header_buffer = SecurityBufferRef::find_buffer_mut(message, BufferType::StreamHeader)?;
        let (stream_header_data, encrypted_data) =
            encrypted_data.split_at(stream_header_buffer.buf_len().min(encrypted_data.len()));
        stream_header_buffer.write_data(stream_header_data)?;

        let data_buffer = SecurityBufferRef::find_buffer_mut(message, BufferType::Data)?;
        let (data_data, encrypted_data) = encrypted_data.split_at(data_buffer.buf_len().min(encrypted_data.len()));
        data_buffer.write_data(data_data)?;

        let stream_trailer_buffer = SecurityBufferRef::find_buffer_mut(message, BufferType::StreamTrailer)?;
        stream_trailer_buffer.write_data(encrypted_data)?;

        Ok(SecurityStatus::Ok)
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn decrypt_message(&mut self, message: &mut [SecurityBufferRef<'_>]) -> Result<DecryptionFlags> {
        // CredSsp decrypt_message function just calls corresponding function from the Schannel
        // MSDN: message must contain four buffers
        // https://learn.microsoft.com/en-us/windows/win32/secauthn/decryptmessage--schannel
        if message.len() < 4 {
            return Err(Error::new(
                ErrorKind::InvalidParameter,
                "Input message must contain four buffers",
            ));
        }

        match self
            .tls_connection_mut()?
            .decrypt_tls(SecurityBufferRef::take_buf_data_mut(message, BufferType::Data)?)?
        {
            DecryptionResult::Success(DecryptionResultBuffers {
                header,
                decrypted,
                extra,
            }) => {
                // buffers order is important. MSTSC won't work with another buffers order.
                message[0] = SecurityBufferRef::stream_header_buf(header);
                message[1] = SecurityBufferRef::data_buf(decrypted);
                // https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secbuffer
                // SECBUFFER_STREAM_TRAILER: It is not usually of interest to callers.
                //
                // So, we can just set an empty buffer here.
                message[2] = SecurityBufferRef::stream_trailer_buf(&mut []);
                message[3] = SecurityBufferRef::extra_buf(extra);

                Ok(DecryptionFlags::empty())
            }
            DecryptionResult::IncompleteMessage(needed_bytes_amount) => {
                // This behavior is not documented anywhere and was discovered during debugging.
                // Change it at your risk.
                // Additional info:
                // * https://stackoverflow.com/a/6832633/9123725
                // * https://stackoverflow.com/a/65101172

                message[0] = SecurityBufferRef::missing_buf(needed_bytes_amount);
                message[1] = SecurityBufferRef::missing_buf(needed_bytes_amount);

                Err(Error::new(ErrorKind::IncompleteMessage, "Got incomplete TLS message"))
            }
        }
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn query_context_sizes(&mut self) -> Result<ContextSizes> {
        self.cred_ssp_context.sspi_context.query_context_sizes()
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn query_context_names(&mut self) -> Result<ContextNames> {
        self.cred_ssp_context.sspi_context.query_context_names()
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn query_context_stream_sizes(&mut self) -> Result<StreamSizes> {
        self.tls_connection()?.stream_sizes()
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn query_context_package_info(&mut self) -> Result<PackageInfo> {
        crate::query_security_package_info(SecurityPackageType::CredSsp)
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn query_context_cert_trust_status(&mut self) -> Result<CertTrustStatus> {
        // The CredSSP server does not request the client's X.509 certificate (thus far, the client is anonymous).
        // we do not check certificate validity
        Ok(CertTrustStatus {
            error_status: CertTrustErrorStatus::NO_ERROR,
            info_status: CertTrustInfoStatus::IS_SELF_SIGNED,
        })
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn query_context_remote_cert(&mut self) -> Result<CertContext> {
        let certificates = self.tls_connection()?.peer_certificates()?;
        let raw_server_certificate = certificates
            .first()
            .ok_or_else(|| Error::new(ErrorKind::CertificateUnknown, "cannot acquire server certificate"))?;

        let server_certificate: Certificate = picky_asn1_der::from_bytes(raw_server_certificate)?;

        Ok(CertContext {
            encoding_type: CertEncodingType::X509AsnEncoding,
            raw_cert: raw_server_certificate.to_vec(),
            cert: server_certificate,
        })
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn query_context_negotiation_package(&mut self) -> Result<PackageInfo> {
        self.cred_ssp_context.sspi_context.query_context_package_info()
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn query_context_connection_info(&mut self) -> Result<ConnectionInfo> {
        self.tls_connection()?.connection_info()
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip_all)]
    fn change_password(
        &mut self,
        _change_password: builders::ChangePassword<'_>,
    ) -> Result<GeneratorChangePassword<'_>> {
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "ChangePassword is not supported in SspiCredSsp context",
        ))
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip_all)]
    fn make_signature(
        &mut self,
        _flags: u32,
        _message: &mut [SecurityBufferRef<'_>],
        _sequence_number: u32,
    ) -> Result<()> {
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "make_signature is not supported",
        ))
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip_all)]
    fn verify_signature(&mut self, _message: &mut [SecurityBufferRef<'_>], _sequence_number: u32) -> Result<u32> {
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "verify_signature is not supported",
        ))
    }
}

impl SspiImpl for SspiCredSsp {
    type CredentialsHandle = Option<CredentialsBuffers>;
    type AuthenticationData = Credentials;

    #[instrument(level = "trace", ret, fields(state = ?self.state), skip(self))]
    fn acquire_credentials_handle_impl(
        &mut self,
        builder: builders::FilledAcquireCredentialsHandle<'_, Self::CredentialsHandle, Self::AuthenticationData>,
    ) -> Result<AcquireCredentialsHandleResult<Self::CredentialsHandle>> {
        if builder.credential_use == CredentialUse::Outbound && builder.auth_data.is_none() {
            return Err(Error::new(
                ErrorKind::NoCredentials,
                "The client must specify the auth data",
            ));
        }

        self.auth_identity = builder
            .auth_data
            .cloned()
            .map(|auth_data| auth_data.try_into())
            .transpose()?;

        Ok(AcquireCredentialsHandleResult {
            credentials_handle: self.auth_identity.clone(),
            expiry: None,
        })
    }

    fn initialize_security_context_impl<'ctx, 'b, 'g>(
        &'ctx mut self,
        builder: &'b mut builders::FilledInitializeSecurityContext<'ctx, 'ctx, Self::CredentialsHandle>,
    ) -> Result<GeneratorInitSecurityContext<'g>>
    where
        'ctx: 'g,
        'b: 'g,
    {
        Ok(GeneratorInitSecurityContext::new(move |mut yield_point| async move {
            self.initialize_security_context_impl(&mut yield_point, builder).await
        }))
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self, builder))]
    fn accept_security_context_impl<'a>(
        &'a mut self,
        builder: builders::FilledAcceptSecurityContext<'a, Self::CredentialsHandle>,
    ) -> Result<GeneratorAcceptSecurityContext<'a>> {
        Ok(GeneratorAcceptSecurityContext::new(move |mut yield_point| async move {
            self.accept_security_context_impl(&mut yield_point, builder).await
        }))
    }
}

impl SspiCredSsp {
    pub(crate) async fn accept_security_context_impl(
        &mut self,
        _yield_point: &mut YieldPointLocal,
        _builder: builders::FilledAcceptSecurityContext<'_, <Self as SspiImpl>::CredentialsHandle>,
    ) -> Result<crate::AcceptSecurityContextResult> {
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "accept_security_context_impl is not supported in SspiCredSsp",
        ))
    }

    #[instrument(ret, level = "debug", fields(state = ?self.state), skip_all)]
    #[async_recursion]
    pub(crate) async fn initialize_security_context_impl(
        &mut self,
        yield_point: &mut YieldPointLocal,
        builder: &mut builders::FilledInitializeSecurityContext<'_, '_, <Self as SspiImpl>::CredentialsHandle>,
    ) -> Result<InitializeSecurityContextResult> {
        trace!(?builder);
        // In the CredSSP we always set DELEGATE flag
        //
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/e36b36f6-edf4-4df1-9905-9e53b7d7c7b7
        // The CredSSP Protocol enables an application to securely delegate a user's credentials from a client to a target server.
        builder.context_requirements |= ClientRequestFlags::DELEGATE;

        // The CredSSP flag should be always set in the CredSsp protocol.
        builder.context_requirements.set(ClientRequestFlags::MUTUAL_AUTH, true);

        let status = match &self.state {
            CredSspState::Tls => {
                if self.tls_connection.is_none() {
                    let (_, target_hostname) =
                        crate::utils::parse_target_name(builder.target_name.ok_or_else(|| {
                            Error::new(
                                ErrorKind::NoCredentials,
                                "Service target name (service principal name) is not provided",
                            )
                        })?)?;

                    let mut client_config = ClientConfig::builder()
                        .dangerous()
                        .with_custom_certificate_verifier(Arc::new(danger::NoCertificateVerification))
                        .with_no_client_auth();

                    client_config.key_log = Arc::new(rustls::KeyLogFile::new());

                    let config = Arc::new(client_config);

                    self.tls_connection = Some(TlsConnection::Rustls(Connection::Client(
                        ClientConnection::new(
                            config,
                            target_hostname.to_owned().try_into().map_err(|e| {
                                Error::new(
                                    ErrorKind::InvalidParameter,
                                    format!("provided target name is not valid DNS name: {e:?}"),
                                )
                            })?,
                        )
                        .map_err(|err| Error::new(ErrorKind::InternalError, err.to_string()))?,
                    )));
                }

                // input token can not present on the first call
                let input_token = builder
                    .input
                    .as_mut()
                    .and_then(|buffers| SecurityBuffer::find_buffer_mut(buffers, BufferType::Token).ok())
                    .map(|sec_buffer| sec_buffer.buffer.as_slice())
                    .unwrap_or_default();
                let (bytes_written, tls_buffer) = self.tls_connection_mut()?.process_tls_packets(input_token)?;

                if bytes_written == 0 {
                    self.state = CredSspState::NegoToken;

                    // delete the previous TLS message
                    builder.input = None;

                    return self.initialize_security_context_impl(yield_point, builder).await;
                }

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
                output_token.buffer = tls_buffer;

                SecurityStatus::ContinueNeeded
            }
            CredSspState::NegoToken => {
                // decrypt and decode TsRequest from input buffers
                let mut ts_request = builder
                    .input
                    .as_mut()
                    .map(|input| self.decrypt_and_decode_ts_request(input))
                    .unwrap_or_else(|| Ok(TsRequest::default()))?;

                self.cred_ssp_context.check_peer_version(ts_request.version)?;

                let mut input_token = vec![SecurityBuffer::new(
                    ts_request.nego_tokens.take().unwrap_or_default(),
                    BufferType::Token,
                )];

                let mut output_token = vec![SecurityBuffer::new(Vec::with_capacity(1024), BufferType::Token)];

                let mut inner_builder = self
                    .cred_ssp_context
                    .sspi_context
                    .initialize_security_context()
                    .with_credentials_handle(builder.credentials_handle.take().ok_or_else(|| {
                        Error::new(ErrorKind::WrongCredentialHandle, "credentials handle is not present")
                    })?)
                    .with_context_requirements(builder.context_requirements)
                    .with_target_data_representation(DataRepresentation::Native);
                if let Some(target_name) = &builder.target_name {
                    inner_builder = inner_builder.with_target_name(target_name);
                }
                let mut inner_builder = inner_builder
                    .with_input(&mut input_token)
                    .with_output(&mut output_token);

                let result = self
                    .cred_ssp_context
                    .sspi_context
                    .initialize_security_context_impl(yield_point, &mut inner_builder)
                    .await?;

                ts_request.nego_tokens = Some(output_token.remove(0).buffer);

                if result.status == SecurityStatus::Ok {
                    let public_key = self.raw_peer_public_key()?;

                    let peer_version = self
                        .cred_ssp_context
                        .peer_version
                        .expect("An encrypt public key client function cannot be fired without any incoming TSRequest");
                    ts_request.pub_key_auth = Some(self.cred_ssp_context.encrypt_public_key(
                        &public_key,
                        EndpointType::Client,
                        &self.nonce,
                        peer_version,
                    )?);

                    ts_request.client_nonce = self.nonce;

                    if let Some(nego_tokens) = &ts_request.nego_tokens
                        && nego_tokens.is_empty()
                    {
                        ts_request.nego_tokens = None;
                    }

                    self.state = CredSspState::AuthInfo;
                }

                let mut encoded_ts_request = Vec::new();
                ts_request.encode_ts_request(&mut encoded_ts_request)?;

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
                output_token.buffer = self.tls_connection_mut()?.encrypt_tls(&encoded_ts_request)?;

                SecurityStatus::ContinueNeeded
            }
            CredSspState::AuthInfo => {
                let mut ts_request = builder
                    .input
                    .as_mut()
                    .map(|input| self.decrypt_and_decode_ts_request(input))
                    .unwrap_or_else(|| Ok(TsRequest::default()))?;

                ts_request.nego_tokens = None;

                let pub_key_auth = ts_request
                    .pub_key_auth
                    .take()
                    .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Expected an encrypted public key"))?;
                let peer_version = self
                    .cred_ssp_context
                    .peer_version
                    .expect("An encrypt public key client function cannot be fired without any incoming TSRequest");

                let peer_public_key = self.raw_peer_public_key()?;
                self.cred_ssp_context.decrypt_public_key(
                    &peer_public_key,
                    pub_key_auth.as_ref(),
                    EndpointType::Client,
                    &self.nonce,
                    peer_version,
                )?;

                let credentials = builder
                    .credentials_handle
                    .take()
                    .and_then(|c| c.as_ref())
                    .ok_or_else(|| Error::new(ErrorKind::WrongCredentialHandle, "credentials handle is not present"))?;

                ts_request.auth_info = Some(
                    self.cred_ssp_context
                        .encrypt_ts_credentials(credentials, CredSspMode::WithCredentials)?,
                );

                let mut encoded_ts_request = Vec::new();
                ts_request.encode_ts_request(&mut encoded_ts_request)?;

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
                output_token.buffer = self.tls_connection_mut()?.encrypt_tls(&encoded_ts_request)?;

                self.state = CredSspState::Final;

                SecurityStatus::Ok
            }
            CredSspState::Final => {
                return Err(Error::new(
                    ErrorKind::OutOfSequence,
                    "Initialize security context function has been called after authorization",
                ));
            }
        };

        trace!(?builder);

        Ok(InitializeSecurityContextResult {
            status,
            flags: ClientResponseFlags::empty(),
            expiry: None,
        })
    }
}

impl SspiEx for SspiCredSsp {
    #[instrument(level = "trace", ret, fields(state = ?self.state), skip(self))]
    fn custom_set_auth_identity(&mut self, identity: Self::AuthenticationData) -> Result<()> {
        self.auth_identity = Some(identity.try_into()?);

        Ok(())
    }
}

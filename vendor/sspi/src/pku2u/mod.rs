mod cert_utils;
mod config;
mod extractors;
mod generators;
#[macro_use]
pub mod macros;
mod validate;

use std::io::Write;
use std::str::FromStr;
use std::sync::LazyLock;

pub use cert_utils::validation::validate_server_p2p_certificate;
pub use config::Pku2uConfig;
pub use extractors::{extract_pa_pk_as_rep, extract_server_nonce, extract_session_key_from_as_rep};
pub use generators::{generate_authenticator, generate_authenticator_extension, generate_client_dh_parameters};
use picky::hash::HashAlgorithm;
use picky::signature::SignatureAlgorithm;
use picky_asn1_x509::signed_data::SignedData;
use picky_krb::constants::gss_api::{AP_REQ_TOKEN_ID, AS_REQ_TOKEN_ID, AUTHENTICATOR_CHECKSUM_TYPE};
use picky_krb::constants::key_usages::{ACCEPTOR_SIGN, INITIATOR_SIGN};
use picky_krb::crypto::diffie_hellman::{DhNonce, generate_key};
use picky_krb::crypto::{ChecksumSuite, CipherSuite};
use picky_krb::gss_api::{NegTokenTarg1, WrapToken};
use picky_krb::messages::{ApRep, AsRep};
use picky_krb::negoex::data_types::MessageType;
use picky_krb::negoex::messages::{Exchange, Nego, Verify};
use picky_krb::negoex::{NegoexMessage, RANDOM_ARRAY_SIZE};
use picky_krb::pkinit::PaPkAsRep;
use rand::rngs::{StdRng, SysRng};
use rand_core::{Rng as _, SeedableRng as _};
use uuid::Uuid;
pub use validate::validate_signed_data;

use self::generators::{
    WELLKNOWN_REALM, generate_neg, generate_neg_token_init, generate_neg_token_targ, generate_pku2u_nego_req,
    generate_server_dh_parameters,
};
use crate::builders::{ChangePassword, FilledAcceptSecurityContext};
use crate::generator::{GeneratorAcceptSecurityContext, GeneratorInitSecurityContext, YieldPointLocal};
use crate::kerberos::client::extractors::extract_sub_session_key_from_ap_rep;
use crate::kerberos::client::generators::{
    ChecksumOptions, EncKey, GenerateAsReqOptions, GenerateAuthenticatorOptions, generate_ap_req, generate_as_req,
    generate_as_req_kdc_body,
};
use crate::kerberos::{DEFAULT_ENCRYPTION_TYPE, EncryptionParams, MAX_SIGNATURE, RRC, SECURITY_TRAILER};
use crate::pk_init::{
    DhParameters, GenerateAsPaDataOptions, extract_server_dh_public_key, generate_pa_datas_for_as_req,
};
use crate::pku2u::extractors::extract_krb_rep;
use crate::pku2u::generators::generate_as_req_username_from_certificate;
use crate::utils::{extract_encrypted_data, generate_random_symmetric_key, get_encryption_key, save_decrypted_data};
use crate::{
    AcceptSecurityContextResult, AcquireCredentialsHandleResult, AuthIdentity, AuthIdentityBuffers, BufferType,
    CertTrustStatus, ClientResponseFlags, ContextNames, ContextSizes, CredentialUse, DecryptionFlags, EncryptionFlags,
    Error, ErrorKind, InitializeSecurityContextResult, PACKAGE_ID_NONE, PackageCapabilities, PackageInfo, Result,
    SecurityBuffer, SecurityBufferRef, SecurityPackageType, SecurityStatus, Sspi, SspiEx, SspiImpl,
};

pub const PKG_NAME: &str = "Pku2u";

pub const AZURE_AD_DOMAIN: &str = "AzureAD";

/// [Authenticator Checksum](https://datatracker.ietf.org/doc/html/rfc4121#section-4.1.1)
const AUTHENTICATOR_DEFAULT_CHECKSUM: [u8; 24] = [
    16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 62, 64, 0, 0,
];

/// Default NEGOEX authentication scheme
pub const DEFAULT_NEGOEX_AUTH_SCHEME: &str = "0d53335c-f9ea-4d0d-b2ec-4ae3786ec308";

/// sealed = true
/// other flags = false
pub const CLIENT_WRAP_TOKEN_FLAGS: u8 = 2;
/// sealed = true
/// send by acceptor = true
/// acceptor subkey = false
pub const SERVER_WRAP_TOKEN_FLAGS: u8 = 3;

pub static PACKAGE_INFO: LazyLock<PackageInfo> = LazyLock::new(|| PackageInfo {
    capabilities: PackageCapabilities::empty(),
    rpc_id: PACKAGE_ID_NONE,
    max_token_len: 0xbb80, // 48 000 bytes: default maximum token len in Windows
    name: SecurityPackageType::Pku2u,
    comment: String::from("Pku2u Security Package"),
});

#[derive(Debug, Clone)]
pub enum Pku2uState {
    Negotiate,
    Preauthentication,
    AsExchange,
    ApExchange,
    PubKeyAuth,
    Credentials,
    Final,
}

#[derive(Debug, Clone)]
enum Pku2uMode {
    Client,
    Server,
}

#[derive(Debug, Clone)]
pub struct Pku2u {
    mode: Pku2uMode,
    config: Pku2uConfig,
    state: Pku2uState,
    encryption_params: EncryptionParams,
    auth_identity: Option<AuthIdentityBuffers>,
    conversation_id: Uuid,
    auth_scheme: Option<Uuid>,
    seq_number: u32,
    dh_parameters: DhParameters,
    // all sent and received NEGOEX messages concatenated in one vector
    // we need it for the further checksum calculation
    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-negoex/9de2cde2-bd98-40a4-9efa-0f5a1d6cc88e
    // The checksum is performed on all previous NEGOEX messages in the context negotiation.
    negoex_messages: Vec<u8>,
    // two last GSS-API messages concatenated in one vector
    // we need it for the further authenticator checksum calculation
    // https://datatracker.ietf.org/doc/html/draft-zhu-pku2u-04#section-6
    // The checksum is performed on all previous NEGOEX messages in the context negotiation.
    gss_api_messages: Vec<u8>,
    negoex_random: [u8; RANDOM_ARRAY_SIZE],
}

impl Pku2u {
    pub fn new_server_from_config(config: Pku2uConfig) -> Result<Self> {
        let mut rng = StdRng::try_from_rng(&mut SysRng)?;
        let mut negoex_random = [0; RANDOM_ARRAY_SIZE];
        rng.fill_bytes(&mut negoex_random);

        Ok(Self {
            mode: Pku2uMode::Server,
            config,
            state: Pku2uState::Preauthentication,
            encryption_params: EncryptionParams::default_for_server(),
            auth_identity: None,
            conversation_id: Uuid::default(),
            auth_scheme: Some(Uuid::from_str(DEFAULT_NEGOEX_AUTH_SCHEME).unwrap()),
            seq_number: 2,
            // https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.3
            // Contains the nonce in the pkAuthenticator field in the request if the DH keys are NOT reused,
            // 0 otherwise.
            // generate dh parameters at the start in order to not waste time during authorization
            dh_parameters: generate_server_dh_parameters(&mut rng)?,
            negoex_messages: Vec::new(),
            gss_api_messages: Vec::new(),
            negoex_random,
        })
    }

    pub fn new_client_from_config(config: Pku2uConfig) -> Result<Self> {
        let mut rand = StdRng::try_from_rng(&mut SysRng)?;
        let mut negoex_random = [0; RANDOM_ARRAY_SIZE];
        rand.fill_bytes(&mut negoex_random);

        Ok(Self {
            mode: Pku2uMode::Client,
            config,
            state: Pku2uState::Negotiate,
            encryption_params: EncryptionParams::default_for_client(),
            auth_identity: None,
            conversation_id: Uuid::new_v4(),
            auth_scheme: None,
            seq_number: 0,
            // https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.3
            // Contains the nonce in the pkAuthenticator field in the request if the DH keys are NOT reused,
            // 0 otherwise.
            // generate dh parameters at the start in order to not waste time during authorization
            dh_parameters: generate_client_dh_parameters(&mut rand),
            negoex_messages: Vec::new(),
            gss_api_messages: Vec::new(),
            negoex_random,
        })
    }

    pub fn config(&self) -> &Pku2uConfig {
        &self.config
    }

    pub fn next_seq_number(&mut self) -> u32 {
        let seq_num = self.seq_number;
        self.seq_number += 1;

        seq_num
    }
}

impl Sspi for Pku2u {
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
        trace!(encryption_params = ?self.encryption_params);

        // checks if the Token buffer present
        let _ = SecurityBufferRef::find_buffer(message, BufferType::Token)?;
        let data_buffer = SecurityBufferRef::find_buffer_mut(message, BufferType::Data)?;

        let cipher = self
            .encryption_params
            .encryption_type
            .as_ref()
            .unwrap_or(&DEFAULT_ENCRYPTION_TYPE)
            .cipher();

        let sequence_number = self.next_seq_number();

        let key = get_encryption_key(&self.encryption_params)?;
        let key_usage = self.encryption_params.sspi_encrypt_key_usage;

        let mut wrap_token = WrapToken::with_seq_number(u64::from(sequence_number));
        wrap_token.flags = match self.mode {
            Pku2uMode::Client => CLIENT_WRAP_TOKEN_FLAGS,
            Pku2uMode::Server => SERVER_WRAP_TOKEN_FLAGS,
        };

        let mut payload = data_buffer.data().to_vec();
        payload.extend_from_slice(&wrap_token.header());

        let mut checksum = cipher.encrypt(key.as_ref(), key_usage, &payload)?;
        checksum.rotate_right(RRC.into());

        wrap_token.set_rrc(RRC);
        wrap_token.set_checksum(checksum);

        let mut raw_wrap_token = Vec::with_capacity(92);
        wrap_token.encode(&mut raw_wrap_token)?;

        match self.state {
            Pku2uState::PubKeyAuth | Pku2uState::Credentials | Pku2uState::Final => {
                if raw_wrap_token.len() < SECURITY_TRAILER {
                    return Err(Error::new(ErrorKind::EncryptFailure, "Cannot encrypt the data"));
                }

                let (token, data) = raw_wrap_token.split_at(SECURITY_TRAILER);
                data_buffer.write_data(data)?;
                let token_buffer = SecurityBufferRef::find_buffer_mut(message, BufferType::Token)?;
                token_buffer.write_data(token)?;
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::OutOfSequence,
                    "Pku2u context is not established".to_owned(),
                ));
            }
        };

        Ok(SecurityStatus::Ok)
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn decrypt_message(&mut self, message: &mut [SecurityBufferRef<'_>]) -> Result<DecryptionFlags> {
        trace!(encryption_params = ?self.encryption_params);

        let encrypted = extract_encrypted_data(message)?;

        let cipher = self
            .encryption_params
            .encryption_type
            .as_ref()
            .unwrap_or(&DEFAULT_ENCRYPTION_TYPE)
            .cipher();

        let key = get_encryption_key(&self.encryption_params)?;
        let key_usage = self.encryption_params.sspi_decrypt_key_usage;

        let mut wrap_token = WrapToken::decode(encrypted.as_slice())?;
        wrap_token.checksum.rotate_left(RRC.into());

        let mut decrypted = cipher.decrypt(key.as_ref(), key_usage, &wrap_token.checksum)?;

        // remove wrap token header
        decrypted.truncate(decrypted.len() - WrapToken::header_len());

        save_decrypted_data(&decrypted, message)?;

        match self.state {
            Pku2uState::PubKeyAuth => {
                self.state = Pku2uState::Credentials;
                Ok(DecryptionFlags::empty())
            }
            Pku2uState::Credentials => {
                self.state = Pku2uState::Final;
                Ok(DecryptionFlags::empty())
            }
            _ => Ok(DecryptionFlags::empty()),
        }
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn query_context_sizes(&mut self) -> Result<ContextSizes> {
        Ok(ContextSizes {
            max_token: PACKAGE_INFO.max_token_len,
            max_signature: MAX_SIGNATURE as u32,
            block: 0,
            security_trailer: SECURITY_TRAILER as u32,
        })
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn query_context_names(&mut self) -> Result<ContextNames> {
        if let Some(identity_buffers) = &self.auth_identity {
            let identity =
                AuthIdentity::try_from(identity_buffers).map_err(|e| Error::new(ErrorKind::InvalidParameter, e))?;

            Ok(ContextNames {
                username: identity.username,
            })
        } else {
            Err(Error::new(
                ErrorKind::NoCredentials,
                String::from("Requested Names, but no credentials were provided"),
            ))
        }
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn query_context_package_info(&mut self) -> Result<PackageInfo> {
        crate::query_security_package_info(SecurityPackageType::Pku2u)
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn query_context_cert_trust_status(&mut self) -> Result<CertTrustStatus> {
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "Certificate trust status is not supported".to_owned(),
        ))
    }

    #[instrument(level = "debug", fields(state = ?self.state), skip(self))]
    fn query_context_session_key(&self) -> Result<crate::SessionKeys> {
        let session_key = get_encryption_key(&self.encryption_params)?;

        Ok(crate::SessionKeys {
            session_key: session_key.clone(),
        })
    }

    fn change_password(&mut self, _: ChangePassword<'_>) -> Result<crate::generator::GeneratorChangePassword<'_>> {
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "Pku2u does not support change pasword",
        ))
    }

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

    fn verify_signature(&mut self, _message: &mut [SecurityBufferRef<'_>], _sequence_number: u32) -> Result<u32> {
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "verify_signature is not supported",
        ))
    }
}

impl SspiImpl for Pku2u {
    type CredentialsHandle = Option<AuthIdentityBuffers>;

    type AuthenticationData = AuthIdentity;

    #[instrument(level = "trace", ret, fields(state = ?self.state), skip(self))]
    fn acquire_credentials_handle_impl(
        &mut self,
        builder: crate::builders::FilledAcquireCredentialsHandle<'_, Self::CredentialsHandle, Self::AuthenticationData>,
    ) -> Result<AcquireCredentialsHandleResult<Self::CredentialsHandle>> {
        if builder.credential_use == CredentialUse::Outbound && builder.auth_data.is_none() {
            return Err(Error::new(
                ErrorKind::NoCredentials,
                String::from("The client must specify the auth data"),
            ));
        }

        self.auth_identity = builder.auth_data.cloned().map(AuthIdentityBuffers::from);

        Ok(AcquireCredentialsHandleResult {
            credentials_handle: self.auth_identity.clone(),
            expiry: None,
        })
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self, builder))]
    fn accept_security_context_impl<'a>(
        &'a mut self,
        builder: FilledAcceptSecurityContext<'a, Self::CredentialsHandle>,
    ) -> Result<GeneratorAcceptSecurityContext<'a>> {
        Ok(GeneratorAcceptSecurityContext::new(move |mut yield_point| async move {
            self.accept_security_context_impl(&mut yield_point, builder).await
        }))
    }

    fn initialize_security_context_impl<'ctx, 'b, 'g>(
        &'ctx mut self,
        builder: &'b mut crate::builders::FilledInitializeSecurityContext<'ctx, 'ctx, Self::CredentialsHandle>,
    ) -> Result<GeneratorInitSecurityContext<'g>>
    where
        'ctx: 'g,
        'b: 'g,
    {
        Ok(self.initialize_security_context_impl(builder).into())
    }
}

impl Pku2u {
    pub(crate) async fn accept_security_context_impl(
        &mut self,
        _yield_point: &mut YieldPointLocal,
        _builder: FilledAcceptSecurityContext<'_, <Self as SspiImpl>::CredentialsHandle>,
    ) -> Result<AcceptSecurityContextResult> {
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "accept_security_context_impl is not implemented yet",
        ))
    }

    #[instrument(ret, level = "debug", fields(state = ?self.state), skip_all)]
    pub(crate) fn initialize_security_context_impl(
        &mut self,
        builder: &mut crate::builders::FilledInitializeSecurityContext<'_, '_, <Self as SspiImpl>::CredentialsHandle>,
    ) -> Result<InitializeSecurityContextResult> {
        trace!(?builder);

        let status = match self.state {
            Pku2uState::Negotiate => {
                let auth_scheme = Uuid::from_str(DEFAULT_NEGOEX_AUTH_SCHEME).unwrap();

                let mut mech_token = Vec::new();

                let snames = check_if_empty!(builder.target_name, "service target name is not provided")
                    .split('/')
                    .collect::<Vec<_>>();
                debug!(names = ?snames, "Service principal names");

                let nego = Nego::new(
                    MessageType::InitiatorNego,
                    self.conversation_id,
                    self.next_seq_number(),
                    self.negoex_random,
                    vec![auth_scheme],
                    vec![],
                );
                nego.encode(&mut mech_token)?;

                let exchange = Exchange::new(
                    MessageType::InitiatorMetaData,
                    self.conversation_id,
                    self.next_seq_number(),
                    auth_scheme,
                    picky_asn1_der::to_vec(&generate_pku2u_nego_req(&snames, &self.config)?)?,
                );
                exchange.encode(&mut mech_token)?;

                self.negoex_messages.extend_from_slice(&mech_token);

                let encoded_neg_token_init = picky_asn1_der::to_vec(&generate_neg_token_init(mech_token)?)?;

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
                output_token.buffer.write_all(&encoded_neg_token_init)?;

                self.state = Pku2uState::Preauthentication;

                SecurityStatus::ContinueNeeded
            }
            Pku2uState::Preauthentication => {
                let input = builder
                    .input
                    .as_ref()
                    .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Input buffers must be specified"))?;
                let input_token = SecurityBuffer::find_buffer(input, BufferType::Token)?;

                let neg_token_targ: NegTokenTarg1 = picky_asn1_der::from_bytes(&input_token.buffer)?;
                let buffer = neg_token_targ
                    .0
                    .response_token
                    .0
                    .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Missing response_token in NegTokenTarg"))?
                    .0
                    .0;

                self.negoex_messages.extend_from_slice(&buffer);

                let acceptor_nego = Nego::decode(&buffer)?;
                trace!(?acceptor_nego, "NEGOEX ACCEPTOR NEGOTIATE");

                check_conversation_id!(acceptor_nego.header.conversation_id, self.conversation_id);
                check_sequence_number!(acceptor_nego.header.sequence_num, self.next_seq_number());

                // We support only one auth scheme. So the server must choose it otherwise it's an invalid behaviour
                if let Some(auth_scheme) = acceptor_nego.auth_schemes.first() {
                    if *auth_scheme == Uuid::from_str(DEFAULT_NEGOEX_AUTH_SCHEME).unwrap() {
                        self.auth_scheme = Some(*auth_scheme);
                    } else {
                        return Err(Error::new(
                            ErrorKind::InvalidToken,
                            format!(
                                "The server selected unsupported auth scheme {auth_scheme:?}. The only one supported auth scheme: {DEFAULT_NEGOEX_AUTH_SCHEME}"
                            ),
                        ));
                    }
                } else {
                    return Err(Error::new(
                        ErrorKind::InvalidToken,
                        "Server didn't send any auth scheme",
                    ));
                }

                if buffer.len() < acceptor_nego.header.header_len as usize {
                    return Err(Error::new(ErrorKind::InvalidToken, "NEGOEX buffer is too short"));
                }

                let acceptor_exchange_data = &buffer[(acceptor_nego.header.message_len as usize)..];
                let acceptor_exchange = Exchange::decode(acceptor_exchange_data)?;
                trace!(?acceptor_exchange, "NEGOEX ACCEPTOR EXCHANGE");

                check_conversation_id!(acceptor_exchange.header.conversation_id, self.conversation_id);
                check_sequence_number!(acceptor_exchange.header.sequence_num, self.next_seq_number());
                check_auth_scheme!(acceptor_exchange.auth_scheme, self.auth_scheme);

                let mut mech_token = Vec::new();

                let snames = check_if_empty!(builder.target_name, "service target name is not provided")
                    .split('/')
                    .collect::<Vec<_>>();
                debug!(names = ?snames, "Service principal names");

                let next_seq_number = self.next_seq_number();
                let kdc_req_body = generate_as_req_kdc_body(&GenerateAsReqOptions {
                    realm: WELLKNOWN_REALM,
                    username: &generate_as_req_username_from_certificate(&self.config.p2p_certificate)?,
                    cname_type: 0x80,
                    snames: &snames,
                    // we don't need the nonce in Pku2u
                    nonce: &[0],
                    hostname: &self.config.client_hostname,
                    context_requirements: builder.context_requirements,
                })?;
                let private_key = self.config.private_key.clone();
                let pa_datas = generate_pa_datas_for_as_req(&mut GenerateAsPaDataOptions {
                    p2p_cert: self.config.p2p_certificate.clone(),
                    kdc_req_body: &kdc_req_body,
                    dh_parameters: self.dh_parameters.clone(),
                    sign_data: Box::new(move |data_to_sign| {
                        SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA1)
                            .sign(data_to_sign, private_key.as_ref())
                            .map_err(|err| {
                                Error::new(
                                    ErrorKind::InternalError,
                                    format!("Cannot calculate signer info signature: {err:?}"),
                                )
                            })
                    }),
                    with_pre_auth: true,
                    authenticator_nonce: Default::default(),
                })?;
                let as_req = generate_as_req(pa_datas, kdc_req_body);

                let exchange_data = picky_asn1_der::to_vec(&generate_neg(as_req, AS_REQ_TOKEN_ID))?;
                self.gss_api_messages.extend_from_slice(&exchange_data);

                let exchange = Exchange::new(
                    MessageType::ApRequest,
                    self.conversation_id,
                    next_seq_number,
                    check_if_empty!(self.auth_scheme, "auth scheme is not set"),
                    exchange_data,
                );
                exchange.encode(&mut mech_token)?;

                self.negoex_messages.extend_from_slice(&mech_token);

                let response_token = picky_asn1_der::to_vec(&generate_neg_token_targ(mech_token)?)?;

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
                output_token.buffer.write_all(&response_token)?;

                self.state = Pku2uState::AsExchange;

                SecurityStatus::ContinueNeeded
            }
            Pku2uState::AsExchange => {
                let input = builder
                    .input
                    .as_ref()
                    .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Input buffers must be specified"))?;
                let input_token = SecurityBuffer::find_buffer(input, BufferType::Token)?;

                let neg_token_targ: NegTokenTarg1 = picky_asn1_der::from_bytes(&input_token.buffer)?;
                let buffer = neg_token_targ
                    .0
                    .response_token
                    .0
                    .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Missing response_token in NegTokenTarg"))?
                    .0
                    .0;

                self.negoex_messages.extend_from_slice(&buffer);

                let acceptor_exchange = Exchange::decode(&buffer)?;
                trace!(?acceptor_exchange, "NEGOEX ACCEPTOR EXCHANGE MESSAGE");

                check_conversation_id!(acceptor_exchange.header.conversation_id, self.conversation_id);
                check_sequence_number!(acceptor_exchange.header.sequence_num, self.next_seq_number());
                check_auth_scheme!(acceptor_exchange.auth_scheme, self.auth_scheme);

                self.gss_api_messages.extend_from_slice(&acceptor_exchange.exchange);

                let (as_rep, _): (AsRep, _) = extract_krb_rep(&acceptor_exchange.exchange)?;

                let dh_rep_info = match extract_pa_pk_as_rep(&as_rep)? {
                    PaPkAsRep::DhInfo(dh) => dh.0,
                    PaPkAsRep::EncKeyPack(_) => {
                        return Err(Error::new(
                            ErrorKind::OperationNotSupported,
                            "encKeyPack is not supported for the PA-PK-AS-REP",
                        ));
                    }
                };

                let server_nonce = extract_server_nonce(&dh_rep_info)?;
                self.dh_parameters.server_nonce = Some(server_nonce);

                let signed_data: SignedData = picky_asn1_der::from_bytes(&dh_rep_info.dh_signed_data.0)?;

                let rsa_public_key = validate_server_p2p_certificate(&signed_data)?;
                validate_signed_data(&signed_data, &rsa_public_key)?;

                let public_key = extract_server_dh_public_key(&signed_data)?;
                self.dh_parameters.other_public_key = Some(public_key);

                self.encryption_params.encryption_type =
                    Some(CipherSuite::try_from(as_rep.0.enc_part.0.etype.0.0.as_slice())?);

                let session_key = generate_key(
                    check_if_empty!(self.dh_parameters.other_public_key.as_ref(), "dh public key is not set"),
                    &self.dh_parameters.private_key,
                    &self.dh_parameters.modulus,
                    Some(DhNonce {
                        client_nonce: check_if_empty!(
                            self.dh_parameters.client_nonce.as_ref(),
                            "dh client none is not set"
                        ),
                        server_nonce: check_if_empty!(
                            self.dh_parameters.server_nonce.as_ref(),
                            "dh server nonce is not set"
                        ),
                    }),
                    check_if_empty!(
                        self.encryption_params.encryption_type.as_ref(),
                        "encryption type is not set"
                    )
                    .cipher()
                    .as_ref(),
                )?;
                trace!(?session_key, "Session key generated from DH components");

                let session_key = extract_session_key_from_as_rep(&as_rep, &session_key, &self.encryption_params)?;
                self.encryption_params.session_key = Some(session_key);

                let exchange_seq_number = self.next_seq_number();
                let verify_seq_number = self.next_seq_number();

                let enc_type = self
                    .encryption_params
                    .encryption_type
                    .as_ref()
                    .unwrap_or(&DEFAULT_ENCRYPTION_TYPE);
                let mut rand = StdRng::try_from_rng(&mut SysRng)?;
                let authenticator_sub_key = generate_random_symmetric_key(enc_type, &mut rand);

                let authenticator = generate_authenticator(GenerateAuthenticatorOptions {
                    kdc_rep: &as_rep.0,
                    seq_num: Some(exchange_seq_number),
                    sub_key: Some(EncKey {
                        key_type: enc_type.clone(),
                        key_value: authenticator_sub_key.clone(),
                    }),
                    checksum: Some(ChecksumOptions {
                        checksum_type: AUTHENTICATOR_CHECKSUM_TYPE.to_vec(),
                        checksum_value: AUTHENTICATOR_DEFAULT_CHECKSUM.into(),
                    }),
                    channel_bindings: None,
                    extensions: vec![generate_authenticator_extension(
                        &authenticator_sub_key,
                        &self.gss_api_messages,
                    )?],
                })?;

                let ap_req = generate_ap_req(
                    as_rep.0.ticket.0,
                    check_if_empty!(self.encryption_params.session_key.as_ref(), "session key is not set"),
                    &authenticator,
                    &self.encryption_params,
                    builder.context_requirements.into(),
                )?;

                let mut mech_token = Vec::new();

                let exchange = Exchange::new(
                    MessageType::ApRequest,
                    self.conversation_id,
                    exchange_seq_number,
                    check_if_empty!(self.auth_scheme, "auth_scheme is not set"),
                    picky_asn1_der::to_vec(&generate_neg(ap_req, AP_REQ_TOKEN_ID))?,
                );
                exchange.encode(&mut mech_token)?;

                exchange.encode(&mut self.negoex_messages)?;

                let verify = Verify::new(
                    MessageType::Verify,
                    self.conversation_id,
                    verify_seq_number,
                    check_if_empty!(self.auth_scheme, "auth_scheme is not set"),
                    ChecksumSuite::HmacSha196Aes256.into(),
                    ChecksumSuite::HmacSha196Aes256.hasher().checksum(
                        &authenticator_sub_key,
                        INITIATOR_SIGN,
                        &self.negoex_messages,
                    )?,
                );
                verify.encode(&mut mech_token)?;

                verify.encode(&mut self.negoex_messages)?;

                let encoded_neg_token_targ = picky_asn1_der::to_vec(&generate_neg_token_targ(mech_token)?)?;

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
                output_token.buffer.write_all(&encoded_neg_token_targ)?;

                self.state = Pku2uState::ApExchange;

                SecurityStatus::ContinueNeeded
            }
            Pku2uState::ApExchange => {
                let input = builder
                    .input
                    .as_ref()
                    .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Input buffers must be specified"))?;
                let input_token = SecurityBuffer::find_buffer(input, BufferType::Token)?;

                let neg_token_targ: NegTokenTarg1 = picky_asn1_der::from_bytes(&input_token.buffer)?;

                let buffer = neg_token_targ
                    .0
                    .response_token
                    .0
                    .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Missing response_token in NegTokenTarg"))?
                    .0
                    .0;

                let acceptor_exchange = Exchange::decode(&buffer)?;
                trace!(?acceptor_exchange, "NEGOEX ACCEPTOR EXCHANGE MESSAGE");

                check_conversation_id!(acceptor_exchange.header.conversation_id, self.conversation_id);
                check_sequence_number!(acceptor_exchange.header.sequence_num, self.next_seq_number());
                check_auth_scheme!(acceptor_exchange.auth_scheme, self.auth_scheme);

                if buffer.len() < acceptor_exchange.header.header_len as usize {
                    return Err(Error::new(ErrorKind::InvalidToken, "NEGOEX buffer is too short"));
                }

                self.negoex_messages
                    .extend_from_slice(&buffer[0..(acceptor_exchange.header.message_len as usize)]);

                let acceptor_verify_data = &buffer[(acceptor_exchange.header.message_len as usize)..];
                let acceptor_verify = Verify::decode(acceptor_verify_data)?;
                trace!(?acceptor_exchange, "NEGOEX ACCEPTOR VERIFY MESSAGE");

                check_conversation_id!(acceptor_verify.header.conversation_id, self.conversation_id);
                check_sequence_number!(acceptor_verify.header.sequence_num, self.next_seq_number());
                check_auth_scheme!(acceptor_verify.auth_scheme, self.auth_scheme);

                let (ap_rep, _): (ApRep, _) = extract_krb_rep(&acceptor_exchange.exchange)?;

                let sub_session_key = extract_sub_session_key_from_ap_rep(
                    &ap_rep,
                    check_if_empty!(self.encryption_params.session_key.as_ref(), "session key is not set"),
                    &self.encryption_params,
                )?;

                self.encryption_params.sub_session_key = Some(sub_session_key);

                let acceptor_checksum = ChecksumSuite::try_from(acceptor_verify.checksum.checksum_type as usize)?
                    .hasher()
                    .checksum(
                        check_if_empty!(
                            self.encryption_params.sub_session_key.as_ref(),
                            "sub-session key is not set"
                        )
                        .as_ref(),
                        ACCEPTOR_SIGN,
                        &self.negoex_messages,
                    )?;
                if acceptor_verify.checksum.checksum_value != acceptor_checksum {
                    return Err(Error::new(
                        ErrorKind::MessageAltered,
                        "bad verify message signature from server",
                    ));
                }

                self.state = Pku2uState::PubKeyAuth;

                SecurityStatus::Ok
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::OutOfSequence,
                    format!("Got wrong PKU2U state: {:?}", self.state),
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
}

impl SspiEx for Pku2u {
    #[instrument(level = "trace", ret, fields(state = ?self.state), skip(self))]
    fn custom_set_auth_identity(&mut self, identity: Self::AuthenticationData) -> Result<()> {
        self.auth_identity = Some(identity.into());

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::rand_core::TryRng;
    use picky::key::PrivateKey;
    use picky_asn1_x509::Certificate;
    use picky_krb::constants::key_usages::{ACCEPTOR_SEAL, INITIATOR_SEAL};
    use picky_krb::crypto::CipherSuite;
    use picky_krb::negoex::RANDOM_ARRAY_SIZE;
    use rand::rngs::{StdRng, SysRng};
    use rand_core::{Rng as _, SeedableRng as _};
    use uuid::Uuid;

    use super::Pku2uMode;
    use super::generators::{generate_client_dh_parameters, generate_server_dh_parameters};
    use crate::kerberos::EncryptionParams;
    use crate::{EncryptionFlags, Pku2u, Pku2uConfig, Pku2uState, SecurityBufferRef, Sspi};

    #[test]
    fn stream_buffer_decryption() {
        let session_key = vec![
            137, 60, 120, 245, 164, 179, 76, 200, 242, 96, 57, 174, 111, 209, 90, 76, 58, 117, 55, 138, 81, 75, 110,
            235, 80, 228, 14, 238, 76, 128, 139, 81,
        ];
        let sub_session_key = vec![
            35, 147, 211, 63, 83, 48, 241, 34, 97, 95, 27, 106, 195, 18, 95, 91, 17, 45, 187, 6, 26, 195, 16, 108, 123,
            119, 121, 155, 58, 142, 204, 74,
        ];

        let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();

        let p2p_certificate: Certificate = picky_asn1_der::from_bytes(&[
            48, 130, 3, 213, 48, 130, 2, 189, 160, 3, 2, 1, 2, 2, 16, 32, 99, 134, 91, 60, 164, 166, 93, 186, 47, 71,
            107, 255, 241, 24, 166, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 48, 77, 49, 75, 48, 73, 6,
            3, 85, 4, 3, 30, 66, 0, 77, 0, 83, 0, 45, 0, 79, 0, 114, 0, 103, 0, 97, 0, 110, 0, 105, 0, 122, 0, 97, 0,
            116, 0, 105, 0, 111, 0, 110, 0, 45, 0, 80, 0, 50, 0, 80, 0, 45, 0, 65, 0, 99, 0, 99, 0, 101, 0, 115, 0,
            115, 0, 32, 0, 91, 0, 50, 0, 48, 0, 50, 0, 50, 0, 93, 48, 30, 23, 13, 50, 51, 48, 49, 50, 57, 49, 53, 52,
            57, 52, 57, 90, 23, 13, 50, 51, 48, 49, 50, 57, 49, 54, 53, 52, 52, 57, 90, 48, 129, 142, 49, 52, 48, 50,
            6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 36, 97, 57, 50, 53, 50, 52, 52, 56, 45, 57, 97, 98,
            55, 45, 52, 57, 98, 48, 45, 98, 98, 53, 99, 45, 102, 50, 102, 57, 50, 51, 99, 56, 52, 54, 55, 50, 49, 61,
            48, 59, 6, 3, 85, 4, 3, 12, 52, 83, 45, 49, 45, 49, 50, 45, 49, 45, 51, 56, 48, 51, 49, 54, 49, 53, 57, 51,
            45, 49, 51, 51, 49, 50, 56, 56, 57, 56, 50, 45, 50, 48, 56, 52, 57, 49, 53, 56, 52, 51, 45, 51, 50, 50, 57,
            49, 49, 53, 52, 57, 56, 49, 23, 48, 21, 6, 3, 85, 4, 3, 12, 14, 115, 57, 64, 100, 97, 116, 97, 97, 110,
            115, 46, 99, 111, 109, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1,
            15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 213, 241, 189, 199, 35, 187, 172, 209, 113, 53, 145, 42, 93, 142,
            53, 223, 26, 208, 110, 226, 178, 54, 187, 237, 181, 246, 230, 65, 42, 101, 36, 177, 121, 74, 97, 222, 146,
            163, 254, 112, 155, 150, 227, 182, 123, 122, 251, 64, 119, 186, 229, 68, 157, 67, 211, 189, 241, 217, 197,
            194, 143, 86, 210, 86, 178, 232, 140, 59, 99, 9, 98, 8, 164, 181, 4, 194, 5, 101, 191, 137, 140, 13, 158,
            67, 216, 195, 67, 112, 162, 234, 81, 168, 198, 255, 40, 90, 165, 5, 155, 231, 80, 238, 124, 43, 98, 117,
            181, 159, 195, 246, 146, 183, 221, 215, 129, 237, 67, 119, 100, 159, 35, 246, 189, 204, 50, 29, 25, 214,
            121, 69, 120, 253, 143, 248, 219, 162, 32, 205, 111, 13, 76, 123, 158, 242, 60, 0, 233, 159, 17, 143, 199,
            243, 230, 213, 14, 193, 148, 12, 27, 11, 7, 90, 140, 253, 72, 229, 24, 69, 40, 59, 2, 243, 194, 41, 248,
            204, 92, 102, 189, 220, 19, 185, 227, 113, 192, 162, 86, 132, 88, 233, 191, 131, 215, 219, 5, 63, 163, 34,
            55, 9, 209, 94, 255, 37, 32, 165, 163, 167, 133, 49, 105, 19, 85, 147, 227, 77, 189, 125, 140, 171, 127,
            121, 249, 217, 216, 226, 253, 190, 105, 234, 99, 129, 100, 135, 231, 3, 237, 88, 81, 102, 67, 17, 147, 84,
            233, 75, 124, 179, 16, 160, 203, 202, 196, 235, 191, 209, 2, 3, 1, 0, 1, 163, 111, 48, 109, 48, 14, 6, 3,
            85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 5, 160, 48, 41, 6, 3, 85, 29, 17, 4, 34, 48, 32, 160, 30, 6, 10, 43, 6,
            1, 4, 1, 130, 55, 20, 2, 3, 160, 16, 12, 14, 115, 57, 64, 100, 97, 116, 97, 97, 110, 115, 46, 99, 111, 109,
            48, 19, 6, 3, 85, 29, 37, 4, 12, 48, 10, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 48, 27, 6, 9, 43, 6, 1, 4, 1, 130,
            55, 21, 10, 4, 14, 48, 12, 48, 10, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13,
            1, 1, 11, 5, 0, 3, 130, 1, 1, 0, 162, 35, 243, 146, 152, 98, 219, 208, 111, 136, 212, 0, 12, 134, 196, 6,
            96, 113, 172, 17, 243, 26, 152, 107, 97, 89, 98, 235, 162, 130, 189, 228, 248, 44, 19, 41, 203, 8, 185, 83,
            207, 142, 69, 242, 172, 137, 162, 78, 54, 219, 47, 213, 113, 120, 143, 177, 44, 242, 7, 79, 88, 71, 26,
            134, 120, 77, 93, 81, 134, 253, 155, 50, 160, 79, 113, 196, 96, 53, 87, 132, 132, 117, 9, 202, 38, 15, 47,
            4, 247, 57, 153, 145, 211, 181, 46, 92, 232, 219, 186, 226, 12, 7, 52, 61, 104, 55, 136, 170, 53, 57, 95,
            224, 35, 39, 192, 47, 11, 75, 37, 117, 205, 1, 76, 242, 4, 96, 203, 50, 254, 239, 253, 27, 23, 73, 159,
            110, 232, 164, 119, 55, 207, 77, 66, 95, 23, 202, 149, 245, 235, 57, 80, 50, 171, 183, 15, 27, 223, 7, 32,
            155, 101, 139, 95, 167, 214, 90, 58, 199, 250, 127, 131, 12, 97, 61, 212, 12, 10, 245, 34, 136, 11, 215,
            25, 168, 55, 120, 187, 5, 219, 220, 205, 45, 242, 237, 227, 43, 43, 164, 247, 181, 194, 251, 14, 153, 222,
            33, 157, 8, 228, 144, 87, 207, 135, 243, 223, 233, 114, 139, 94, 122, 228, 80, 237, 90, 53, 83, 60, 251,
            11, 179, 147, 227, 101, 85, 96, 80, 44, 176, 158, 85, 102, 31, 228, 24, 117, 230, 26, 202, 127, 121, 177,
            26, 62, 17, 96, 9,
        ])
        .unwrap();
        let private_key = PrivateKey::from_pem_str(
            "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDV8b3HI7us0XE1
kSpdjjXfGtBu4rI2u+219uZBKmUksXlKYd6So/5wm5bjtnt6+0B3uuVEnUPTvfHZ
xcKPVtJWsuiMO2MJYgiktQTCBWW/iYwNnkPYw0NwoupRqMb/KFqlBZvnUO58K2J1
tZ/D9pK33deB7UN3ZJ8j9r3MMh0Z1nlFeP2P+NuiIM1vDUx7nvI8AOmfEY/H8+bV
DsGUDBsLB1qM/UjlGEUoOwLzwin4zFxmvdwTueNxwKJWhFjpv4PX2wU/oyI3CdFe
/yUgpaOnhTFpE1WT4029fYyrf3n52dji/b5p6mOBZIfnA+1YUWZDEZNU6Ut8sxCg
y8rE67/RAgMBAAECggEAERzG6zjGeCpAfeJgmx8W3AOPDG+BhbM+bkGTZT743Bh9
9R8i6GPJpEQtq4UbF1klbO48DGLv2+3jfGG/ECwHovuoch8F6ug2fMYl3UcFPm7I
DwbLsnjb2hSN3X48fIhDx9NNBxGIIdJui6+9WbVNQvuxkyjhLpmTyRKhV8XiYgCK
OkfCfBWOt/WTGdtuwPtDnvtZOA8Qm3L9Yf0BuqLQAqNZ6fihhwfi1bwLwzRTzC3x
rAfxCMv4dLdYCTee9/6fUWGwJ4SKYqlolVbcZmpFJ7/ByRzfgq0etVJJxKIDOZ8y
ba/bw8eLypdo4I9SSch/5x/WAS45bMarX4nmJKwUyQKBgQDxCHKmUdwuz1SDhYX/
H/Si87uZ31Hs/Spjp/mUumwuEgtkmm2hlgtQXmbYnc47nIQqWOu/L0Z9//2D5WHU
lhYk6S8xAN3dKyGPrYKaBzrh5FCzolprz0YK/N1do9Yu0hkshs73isMbpVHPTI9l
WuzDqsqfz27VS4XovZJQfjL2+wKBgQDjOq5l5rFkLbeHxEoIFoMdEQnRrr1bXkrj
Vf0QWN2fi4Y8/RVLUVNifkjoo4Aj3D7sgyT8ItCDyXtj9Rt5swKUW+rywgI44Fr2
DuOAyAXhzFd7GLw0HnE9jeKMQyeXW5igAppXWOMgS6eAo25vIIRL4UBaIC4/WVCz
jJ/aprkaowKBgQDR46ZauJwA0yBoKySlJkGUiKPLeVFRCqAYCdTnM3MypxnusB9Z
f1w4zwvGA5zsAf6BFc+sO1GqNPmhGmUXht6fo8Mpa/THPGDMSa6ZzEP1Iyk3U+Bj
UypONSXa/elr+h5bzMR7gQUnlM1ps+SGwSe9t4McqLh92ncwVawMlehxcwKBgBcG
jj+TNeyR2WQvltTk+xpJ7LXLwDJvBqWsw/0RFDwjllG9z5eXQRzc8SRp1QVNPy8W
RvwpxvljxFYns0YMxrkj61X4JOOAkJcYgSM+oaH04/R8WC3r28vCAe/2qh9jT77/
JIavYiyWnf2iEgG+yMkrpSq80hLnSQ84s8YjWOSDAoGBAOaVvL6VVq2BawI+Qt3s
9DlgTNtzpiJJCmUfwNd2yOPQJVq5trdA0DZeCQEc/psPWXBoyT01ptgcGHP+C/Da
xFnLp2UBrhxA9GYrpJ5i0onRmexQnTVSl5DDq07s+3dbr9YAKjrg9IDZYqLbdwP1
1pNtUBlMx+0X6wxVjMYulkRH
-----END PRIVATE KEY-----",
        )
        .unwrap();

        let mut negoex_random = [0; RANDOM_ARRAY_SIZE];
        rng.fill_bytes(&mut negoex_random);

        let mut pku2u_server = Pku2u {
            mode: Pku2uMode::Server,
            config: Pku2uConfig {
                p2p_certificate: p2p_certificate.clone(),
                private_key: private_key.clone().into(),
                client_hostname: "hostname".into(),
            },
            state: Pku2uState::Final,
            encryption_params: EncryptionParams {
                encryption_type: Some(CipherSuite::Aes256CtsHmacSha196),
                session_key: Some(session_key.clone().into()),
                sub_session_key: Some(sub_session_key.clone().into()),
                sspi_encrypt_key_usage: INITIATOR_SEAL,
                sspi_decrypt_key_usage: ACCEPTOR_SEAL,
                ec: 0,
            },
            auth_identity: None,
            conversation_id: Uuid::new_v4(),
            auth_scheme: None,
            seq_number: 0,
            dh_parameters: generate_server_dh_parameters(&mut rng).unwrap(),
            negoex_messages: Vec::new(),
            gss_api_messages: Vec::new(),
            negoex_random,
        };

        let mut negoex_random = [0; RANDOM_ARRAY_SIZE];
        rng.try_fill_bytes(&mut negoex_random).unwrap();

        let mut pku2u_client = Pku2u {
            mode: Pku2uMode::Client,
            config: Pku2uConfig {
                p2p_certificate,
                private_key: private_key.into(),
                client_hostname: "hostname".into(),
            },
            state: Pku2uState::Final,
            encryption_params: EncryptionParams {
                encryption_type: Some(CipherSuite::Aes256CtsHmacSha196),
                session_key: Some(session_key.into()),
                sub_session_key: Some(sub_session_key.into()),
                sspi_encrypt_key_usage: ACCEPTOR_SEAL,
                sspi_decrypt_key_usage: INITIATOR_SEAL,
                ec: 0,
            },
            auth_identity: None,
            conversation_id: Uuid::new_v4(),
            auth_scheme: None,
            seq_number: 0,
            dh_parameters: generate_client_dh_parameters(&mut rng),
            negoex_messages: Vec::new(),
            gss_api_messages: Vec::new(),
            negoex_random,
        };

        let plain_message = b"some plain message";

        let mut token = [0; 1024];
        let mut data = plain_message.to_vec();
        let mut message = [
            SecurityBufferRef::token_buf(token.as_mut_slice()),
            SecurityBufferRef::data_buf(data.as_mut_slice()),
        ];

        pku2u_server
            .encrypt_message(EncryptionFlags::empty(), &mut message)
            .unwrap();

        let mut buffer = message[0].data().to_vec();
        buffer.extend_from_slice(message[1].data());

        let mut message = [
            SecurityBufferRef::stream_buf(&mut buffer),
            SecurityBufferRef::data_buf(&mut []),
        ];

        pku2u_client.decrypt_message(&mut message).unwrap();

        assert_eq!(message[1].data(), plain_message);
    }
}

pub(crate) mod client;
mod config;
mod extractors;
mod generators;
pub(crate) mod server;

use std::fmt::Debug;
use std::mem;
use std::net::IpAddr;
use std::sync::LazyLock;

pub use config::{NegotiateConfig, ProtocolConfig};
use picky::oids;
use picky_krb::gss_api::MechType;
use widestring::Utf16String;

use crate::builders::{EmptyAcceptSecurityContext, FilledAcceptSecurityContext, FilledInitializeSecurityContext};
use crate::generator::{
    GeneratorAcceptSecurityContext, GeneratorChangePassword, GeneratorInitSecurityContext, YieldPointLocal,
};
use crate::kdc::detect_kdc_url;
use crate::kerberos::client::principal::{get_client_principal_name, get_client_principal_realm};
use crate::ntlm::NtlmConfig;
#[allow(unused)]
use crate::utils::is_azure_ad_domain;
use crate::{
    AcceptSecurityContextResult, AcquireCredentialsHandleResult, AuthIdentity, BufferType, CertTrustStatus,
    ContextNames, ContextSizes, CredentialUse, Credentials, CredentialsBuffers, DecryptionFlags, Error, ErrorKind,
    InitializeSecurityContextResult, Kerberos, KerberosConfig, Ntlm, PACKAGE_ID_NONE, PackageCapabilities, PackageInfo,
    Pku2u, Result, SecurityBuffer, SecurityBufferRef, SecurityPackageType, SecurityStatus, Sspi, SspiEx, SspiImpl,
    builders, kerberos, ntlm, pku2u,
};

pub const PKG_NAME: &str = "Negotiate";
const GUEST_USERNAME: &str = "/GUEST";

pub static PACKAGE_INFO: LazyLock<PackageInfo> = LazyLock::new(|| PackageInfo {
    capabilities: PackageCapabilities::empty(),
    rpc_id: PACKAGE_ID_NONE,
    max_token_len: 0xbb80, // 48 000 bytes: default maximum token len in Windows
    name: SecurityPackageType::Negotiate,
    comment: String::from("Microsoft Package Negotiator"),
});

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum NegotiatedProtocol {
    Pku2u(Pku2u),
    Kerberos(Kerberos),
    Ntlm(Ntlm),
}

impl NegotiatedProtocol {
    pub fn protocol_name(&self) -> &str {
        match self {
            NegotiatedProtocol::Pku2u(_) => pku2u::PKG_NAME,
            NegotiatedProtocol::Kerberos(_) => kerberos::PKG_NAME,
            NegotiatedProtocol::Ntlm(_) => ntlm::PKG_NAME,
        }
    }

    pub fn verify_mic_token(&mut self, token: &[u8], data: &[u8], sealed: crate::private::Sealed) -> Result<()> {
        match self {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.verify_mic_token(token, data, sealed),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.verify_mic_token(token, data, sealed),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.verify_mic_token(token, data, sealed),
        }
    }

    pub fn generate_mic_token(&mut self, data: &[u8], sealed: crate::private::Sealed) -> Result<Vec<u8>> {
        match self {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.generate_mic_token(data, sealed),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.generate_mic_token(data, sealed),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.generate_mic_token(data, sealed),
        }
    }

    pub fn is_kerberos(&self) -> bool {
        matches!(self, NegotiatedProtocol::Kerberos(_))
    }

    pub fn is_ntlm(&self) -> bool {
        matches!(self, NegotiatedProtocol::Ntlm(_))
    }

    async fn initialize_security_context<'a>(
        &'a mut self,
        auth_identity: Option<&CredentialsBuffers>,
        yield_point: &mut YieldPointLocal,
        builder: &'a mut FilledInitializeSecurityContext<'_, '_, <Negotiate as SspiImpl>::CredentialsHandle>,
    ) -> Result<InitializeSecurityContextResult> {
        match self {
            NegotiatedProtocol::Pku2u(pku2u) => {
                let mut credentials_handle = auth_identity.and_then(|c| c.to_auth_identity());
                let mut transformed_builder = builder.full_transform(Some(&mut credentials_handle));

                let result = pku2u.initialize_security_context_impl(&mut transformed_builder)?;

                builder.output = mem::take(&mut transformed_builder.output);

                Ok(result)
            }
            NegotiatedProtocol::Kerberos(kerberos) => {
                kerberos.initialize_security_context_impl(yield_point, builder).await
            }
            NegotiatedProtocol::Ntlm(ntlm) => {
                let mut credentials_handle = auth_identity.and_then(|c| c.to_auth_identity());
                let mut transformed_builder = builder.full_transform(Some(&mut credentials_handle));

                let result = ntlm.initialize_security_context_impl(&mut transformed_builder)?;

                builder.output = mem::take(&mut transformed_builder.output);

                Ok(result)
            }
        }
    }

    async fn accept_security_context(
        &mut self,
        yield_point: &mut YieldPointLocal,
        builder: &mut FilledAcceptSecurityContext<'_, <Negotiate as SspiImpl>::CredentialsHandle>,
    ) -> Result<AcceptSecurityContextResult> {
        let input = builder
            .input
            .as_mut()
            .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "input buffers must be specified"))?;

        let mut input_tokens = input.to_vec();
        let mut output_tokens = builder.output.to_vec();

        let mut creds_handle = builder.credentials_handle.as_ref().and_then(|creds| (*creds).clone());
        let result = match self {
            NegotiatedProtocol::Pku2u(pku2u) => {
                let mut creds_handle = creds_handle.and_then(|creds_handle| creds_handle.into_auth_identity());
                let new_builder: FilledAcceptSecurityContext<'_, Option<crate::AuthIdentityBuffers>> =
                    EmptyAcceptSecurityContext::new()
                        .with_context_requirements(builder.context_requirements)
                        .with_target_data_representation(builder.target_data_representation)
                        .with_input(&mut input_tokens)
                        .with_output(&mut output_tokens)
                        .with_credentials_handle(&mut creds_handle);
                pku2u.accept_security_context_impl(yield_point, new_builder).await?
            }
            NegotiatedProtocol::Kerberos(kerberos) => {
                let new_builder = EmptyAcceptSecurityContext::new()
                    .with_context_requirements(builder.context_requirements)
                    .with_target_data_representation(builder.target_data_representation)
                    .with_input(&mut input_tokens)
                    .with_output(&mut output_tokens)
                    .with_credentials_handle(&mut creds_handle);
                kerberos.accept_security_context_impl(yield_point, new_builder).await?
            }
            NegotiatedProtocol::Ntlm(ntlm) => {
                let mut creds_handle = creds_handle.and_then(|creds_handle| creds_handle.into_auth_identity());
                let new_builder = EmptyAcceptSecurityContext::new()
                    .with_credentials_handle(&mut creds_handle)
                    .with_context_requirements(builder.context_requirements)
                    .with_target_data_representation(builder.target_data_representation)
                    .with_input(&mut input_tokens)
                    .with_output(&mut output_tokens);
                ntlm.accept_security_context_impl(new_builder)?
            }
        };

        let output_token = SecurityBuffer::find_buffer_mut(&mut output_tokens, BufferType::Token)?;
        let ot = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
        ot.buffer = mem::take(&mut output_token.buffer);

        Ok(result)
    }

    fn query_context_names(&mut self) -> Result<ContextNames> {
        match self {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.query_context_names(),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.query_context_names(),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.query_context_names(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
enum NegotiateState {
    #[default]
    Initial,
    InProgress,
    VerifyMic,
    Ok,
}

#[derive(Clone, Debug, PartialEq)]
enum NegotiateMode {
    Client,
    Server(Vec<AuthIdentity>),
}

impl NegotiateMode {
    /// Returns true if the mode is [NegotiateMode::Client].
    fn is_client(&self) -> bool {
        self == &NegotiateMode::Client
    }
}

#[derive(Clone, Debug)]
pub struct Negotiate {
    state: NegotiateState,
    protocol: NegotiatedProtocol,
    package_list: PackageListConfig,
    auth_identity: Option<CredentialsBuffers>,
    client_computer_name: String,
    mode: NegotiateMode,
    /// Encoded [MechTypeList]. Used for `mechListMIC` token verification.
    mech_types: Vec<u8>,
    mic_verified: bool,
    /// Indicates whether `mechListMIC` token verification is needed or not.
    ///
    /// According to [RFC 4178: 5. Processing of mechListMIC](https://www.rfc-editor.org/rfc/rfc4178.html#section-5), the `mechListMIC` is optional:
    /// > if the accepted mechanism is the most preferred mechanism of both the initiator and the acceptor,
    /// > then the MIC token exchange is OPTIONAL.
    mic_needed: bool,
}

#[derive(Clone, Copy, Debug)]
struct PackageListConfig {
    ntlm: bool,
    kerberos: bool,
    pku2u: bool,
}

impl PackageListConfig {
    fn parse(package_list: &Option<String>) -> PackageListConfig {
        let mut ntlm: bool = true;
        let mut kerberos: bool = true;
        let mut pku2u: bool = true;

        if let Some(package_list) = &package_list {
            let mut use_default_packages_configuration = true;

            for package in package_list.split(',') {
                let (package_name, enabled) = if let Some(package_name) = package.strip_prefix('!') {
                    (package_name.to_lowercase(), false)
                } else {
                    // If client requested at least one package, then we need to disable the default packages configuration.
                    if use_default_packages_configuration {
                        ntlm = false;
                        kerberos = false;
                        pku2u = false;

                        use_default_packages_configuration = false;
                    }

                    let package_name = package.to_lowercase();
                    (package_name, true)
                };

                match package_name.as_str() {
                    "ntlm" => ntlm = enabled,
                    "kerberos" => kerberos = enabled,
                    "pku2u" => pku2u = enabled,
                    _ => warn!("unexpected package name: {}", &package_name),
                }
            }
        }

        PackageListConfig { ntlm, kerberos, pku2u }
    }
}

impl Negotiate {
    pub fn new_client(config: NegotiateConfig) -> Result<Self> {
        Self::new(config, NegotiateMode::Client)
    }

    pub fn new_server(config: NegotiateConfig, auth_data: Vec<AuthIdentity>) -> Result<Self> {
        Self::new(config, NegotiateMode::Server(auth_data))
    }

    fn new(config: NegotiateConfig, mode: NegotiateMode) -> Result<Self> {
        let mut protocol = config.protocol_config.new_instance()?;

        let package_list = PackageListConfig::parse(&config.package_list);
        if let Some(filtered_protocol) =
            Self::filter_protocol(&protocol, package_list, &config.client_computer_name, mode.is_client())?
        {
            protocol = filtered_protocol;
        }

        Ok(Negotiate {
            state: Default::default(),
            protocol,
            package_list,
            auth_identity: None,
            client_computer_name: config.client_computer_name,
            mode,
            mech_types: Default::default(),
            mic_verified: false,
            mic_needed: true,
        })
    }

    #[cfg(feature = "__test-data")]
    pub fn mic_needed(&self) -> bool {
        self.mic_needed
    }

    fn protocol_name(&self) -> &str {
        self.protocol.protocol_name()
    }

    fn set_auth_identity(&mut self) -> Result<()> {
        let NegotiateMode::Server(auth_data) = &self.mode else {
            return Err(Error::new(
                ErrorKind::InternalError,
                "set_auth_identity must be called only on server side",
            ));
        };

        let ContextNames { username } = self.protocol.query_context_names()?;

        let candidates: Vec<Credentials> = auth_data
            .iter()
            .filter(|auth_data| {
                trace!("Comparing usernames: {:?} with {:?}", auth_data.username, username);

                // Usernames match only when they share the same format and the same components.
                // `eq_ignore_ascii_case` is format-aware, so it is safe to fold the UPN suffix and the
                // NetBIOS domain into a single "domain" comparison here: a UPN and a down-level logon
                // name are distinct identities and never compare equal, which means the qualifier being
                // compared always has one unambiguous meaning (a UPN suffix is only ever matched against
                // a UPN suffix, a NetBIOS domain only ever against a NetBIOS domain).
                auth_data.username.eq_ignore_ascii_case(&username)
            })
            .cloned()
            .map(Credentials::from)
            .collect();

        if candidates.is_empty() {
            return Err(Error::new(
                ErrorKind::NoCredentials,
                "user credentials are not found on the server side",
            ));
        }

        self.custom_set_auth_identities(candidates)
    }

    #[instrument(ret, level = "debug", fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn negotiate_protocol_by_mech_type(&mut self, mech_type: &MechType, username: Option<&Utf16String>) -> Result<()> {
        let enabled_packages = self.package_list;

        if mech_type == &oids::ms_krb5() || mech_type == &oids::krb5() {
            if !enabled_packages.kerberos {
                return Err(Error::new(
                    ErrorKind::InvalidToken,
                    "Kerberos mechanism was selected by the server but is disabled in package_list",
                ));
            }

            // We disable NTLM completely when the target server has selected Kerberos.
            self.package_list.ntlm = false;

            if self.protocol_name() != kerberos::PKG_NAME {
                let kerberos = Kerberos::new_client_from_config(KerberosConfig {
                    client_computer_name: self.client_computer_name.clone(),
                    kdc_url: None,
                })?;
                self.protocol = NegotiatedProtocol::Kerberos(kerberos);

                // When the server changes the protocol from the most preferred for the client to
                // any other mechanism type, then `mechListMIC` exchange is required.
                //
                // [RFC 4178 5. Processing of mechListMIC](https://www.rfc-editor.org/rfc/rfc4178.html#section-5):
                // > if the accepted mechanism is the most preferred mechanism of both the initiator and the acceptor,
                // > then the MIC token exchange is OPTIONAL.
                // > In all other cases, MIC tokens MUST be exchanged after the mechanism context is fully established.
                // > ...Note that the MIC token exchange is required if a mechanism other than
                // > the initiator's first choice is chosen.
                self.mic_needed = true;
                self.mic_verified = false;
            }

            return Ok(());
        }

        if mech_type == &oids::ntlm_ssp() {
            if !enabled_packages.ntlm {
                return Err(Error::new(
                    ErrorKind::InvalidToken,
                    "NTLM mechanism was selected by the server but is disabled in package_list",
                ));
            }

            // We disable Kerberos completely when the target server has selected NTLM.
            self.package_list.kerberos = false;

            if self.protocol_name() != ntlm::PKG_NAME {
                self.protocol =
                    NegotiatedProtocol::Ntlm(Ntlm::with_config(NtlmConfig::new(self.client_computer_name.clone())));
            }

            if let Some(user) = username
                && user.to_string().eq_ignore_ascii_case(GUEST_USERNAME)
            {
                // Do not require `mechListMIC` exchange when the user tries to log on under the guest account.
                self.mic_needed = false;
            } else {
                // [MS-SPNG](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/f377a379-c24f-4a0f-a3eb-0d835389e28a):
                // > If NTLM authentication is most preferred by the client and the server, and the client includes a MIC
                // > in AUTHENTICATE_MESSAGE ([MS-NLMP] section 2.2.1.3), then the mechListMIC field becomes
                // > mandatory in order for the authentication to succeed.
                //
                // We always include NTLM MIC token inside AUTHENTICATE_MESSAGE. So, we need to perform
                // SPNEGO `mechListMIC` exchange.
                self.mic_needed = true;
                self.mic_verified = false;
            }

            return Ok(());
        }

        let s: String = (&mech_type.0).into();
        Err(Error::new(
            ErrorKind::InvalidToken,
            format!("unsupported mech_type: {s}"),
        ))
    }

    // negotiates the authorization protocol based on the username and the domain
    // Decision rules:
    // 1) if `self.protocol` is not NTLM then we've already negotiated a suitable protocol. Nothing to do.
    // 2) if the provided domain is Azure AD domain then it'll use Pku2u
    // 3) if the provided username is FQDN and we can resolve KDC then it'll use Kerberos
    // 4) if SSPI_KDC_URL_ENV is set then it'll also use Kerberos
    // 5) in any other cases, it'll use NTLM
    #[instrument(ret, level = "debug", fields(protocol = self.protocol.protocol_name()), skip(self))]
    fn negotiate_protocol(&mut self, username: &str, domain: &str) -> Result<()> {
        let enabled_packages = self.package_list;

        if let NegotiatedProtocol::Ntlm(_) = &self.protocol {
            #[cfg(target_os = "windows")]
            if enabled_packages.pku2u && is_azure_ad_domain(domain) {
                use super::pku2u::Pku2uConfig;

                debug!("Negotiate: try Pku2u");

                self.protocol = NegotiatedProtocol::Pku2u(Pku2u::new_client_from_config(
                    Pku2uConfig::default_client_config(self.client_computer_name.clone())?,
                )?);
            }

            if enabled_packages.kerberos
                && let Some(host) = detect_kdc_url(&get_client_principal_realm(username, domain))
            {
                debug!("Negotiate: try Kerberos");

                self.protocol = NegotiatedProtocol::Kerberos(Kerberos::new_client_from_config(KerberosConfig {
                    kdc_url: Some(host),
                    client_computer_name: self.client_computer_name.clone(),
                })?);
            }
        }

        if let Some(filtered_protocol) = Self::filter_protocol(
            &self.protocol,
            self.package_list,
            &self.client_computer_name,
            self.mode.is_client(),
        )? {
            self.protocol = filtered_protocol;
        }

        Ok(())
    }

    fn filter_protocol(
        negotiated_protocol: &NegotiatedProtocol,
        package_list: PackageListConfig,
        client_computer_name: &str,
        is_client: bool,
    ) -> Result<Option<NegotiatedProtocol>> {
        let mut filtered_protocol = None;
        let PackageListConfig {
            ntlm: is_ntlm,
            kerberos: is_kerberos,
            pku2u: is_pku2u,
        } = package_list;

        if !is_ntlm && !is_kerberos && !is_pku2u {
            return Err(Error::new(
                ErrorKind::NoCredentials,
                "all security packages are disabled or invalid",
            ));
        }

        match &negotiated_protocol {
            NegotiatedProtocol::Pku2u(pku2u) => {
                if !is_pku2u {
                    let ntlm_config = NtlmConfig::new(pku2u.config().client_hostname.clone());
                    filtered_protocol = Some(NegotiatedProtocol::Ntlm(Ntlm::with_config(ntlm_config)));
                }
            }
            NegotiatedProtocol::Kerberos(kerberos) => {
                if !is_kerberos {
                    let ntlm_config = NtlmConfig::new(kerberos.config().client_computer_name.clone());
                    filtered_protocol = Some(NegotiatedProtocol::Ntlm(Ntlm::with_config(ntlm_config)));
                }
            }
            NegotiatedProtocol::Ntlm(_) => {
                if !is_ntlm {
                    let config = KerberosConfig {
                        client_computer_name: client_computer_name.to_owned(),
                        kdc_url: None,
                    };

                    if is_client {
                        let kerberos_client = Kerberos::new_client_from_config(config)?;
                        filtered_protocol = Some(NegotiatedProtocol::Kerberos(kerberos_client));
                    } else {
                        // Aborting because we need an additional data (ServerProperties object) to create the server-side Kerberos instance.
                        error!(
                            ?package_list,
                            "NTLM protocol has been negotiated but it is disabled in package_list."
                        );

                        return Err(Error::new(
                            ErrorKind::InternalError,
                            "NTLM protocol has been negotiated but it is disabled in package_list",
                        ));
                    }
                }
            }
        }

        Ok(filtered_protocol)
    }

    pub fn negotiated_protocol(&self) -> &NegotiatedProtocol {
        &self.protocol
    }

    fn is_protocol_ntlm(&self) -> bool {
        matches!(&self.protocol, NegotiatedProtocol::Ntlm(_))
    }

    fn can_downgrade_ntlm(&self) -> bool {
        self.package_list.ntlm
    }

    fn is_target_name_ip_address(address: &str) -> bool {
        let stripped_address = address.split('/').next_back().unwrap_or(address);
        stripped_address.parse::<IpAddr>().is_ok()
    }

    fn check_target_name_for_ntlm_downgrade(&mut self, target_name: &str) {
        let should_downgrade = Self::is_target_name_ip_address(target_name);
        let can_downgrade = self.can_downgrade_ntlm();

        if can_downgrade && should_downgrade {
            // Disable Kerberos and Pku2u when downgrading to NTLM, as they are not suitable because of the target name format.
            self.package_list.kerberos = false;
            self.package_list.pku2u = false;

            if !self.is_protocol_ntlm() {
                let ntlm_config = NtlmConfig::new(self.client_computer_name.clone());
                self.protocol = NegotiatedProtocol::Ntlm(Ntlm::with_config(ntlm_config));
            }
        }
    }

    /// Fallback to NTLM protocol.
    ///
    /// Returns true if the fallback was successful, false if NTLM is disabled and fallback is not possible.
    fn fallback_to_ntlm(&mut self) -> bool {
        if !self.can_downgrade_ntlm() {
            return false;
        }

        let ntlm_config = NtlmConfig::new(self.client_computer_name.clone());
        self.protocol = NegotiatedProtocol::Ntlm(Ntlm::with_config(ntlm_config));
        // We need to disable Kerberos completely after falling back to NTLM.
        self.package_list.kerberos = false;

        true
    }

    fn verify_mic_token(&mut self, mic: Option<&[u8]>) -> Result<()> {
        if let Some(mic) = mic {
            self.protocol
                .verify_mic_token(mic, &self.mech_types, crate::private::Sealed)?;

            self.mic_verified = true;
        }

        Ok(())
    }
}

impl<'a> Negotiate {
    pub(crate) async fn accept_security_context_impl(
        &'a mut self,
        yield_point: &mut YieldPointLocal,
        builder: FilledAcceptSecurityContext<'a, <Self as SspiImpl>::CredentialsHandle>,
    ) -> Result<AcceptSecurityContextResult> {
        server::accept_security_context(self, yield_point, builder).await
    }

    pub(crate) async fn initialize_security_context_impl(
        &'a mut self,
        yield_point: &mut YieldPointLocal,
        builder: &'a mut FilledInitializeSecurityContext<'_, '_, <Self as SspiImpl>::CredentialsHandle>,
    ) -> Result<InitializeSecurityContextResult> {
        client::initialize_security_context(self, yield_point, builder).await
    }
}

impl SspiEx for Negotiate {
    #[instrument(ret, level = "debug", fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn custom_set_auth_identity(&mut self, identity: Self::AuthenticationData) -> Result<()> {
        self.auth_identity = Some(identity.clone().try_into().unwrap());

        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => {
                pku2u.custom_set_auth_identity(identity.auth_identity().ok_or_else(|| {
                    Error::new(
                        ErrorKind::IncompleteCredentials,
                        "Provided credentials are not password-based",
                    )
                })?)
            }
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.custom_set_auth_identity(identity),
            NegotiatedProtocol::Ntlm(ntlm) => {
                ntlm.custom_set_auth_identity(identity.auth_identity().ok_or_else(|| {
                    Error::new(
                        ErrorKind::IncompleteCredentials,
                        "Provided credentials are not password-based",
                    )
                })?)
            }
        }
    }

    fn custom_set_auth_identities(&mut self, identities: Vec<Self::AuthenticationData>) -> Result<()> {
        if let Some(first) = identities.first() {
            self.auth_identity = Some(first.clone().try_into().map_err(|_| {
                Error::new(
                    ErrorKind::IncompleteCredentials,
                    "provided credentials are not password-based",
                )
            })?);
        }

        match &mut self.protocol {
            NegotiatedProtocol::Ntlm(ntlm) => {
                // NOTE: non-AuthIdentity credentials (e.g. SmartCard) are silently
                // dropped here. Multi-credential only applies to password-based auth.
                let auth_identities: Vec<_> = identities.into_iter().filter_map(|c| c.auth_identity()).collect();
                ntlm.custom_set_auth_identities(auth_identities)
            }
            _ => match identities.into_iter().next() {
                Some(identity) => self.custom_set_auth_identity(identity),
                None => Err(Error::new(ErrorKind::NoCredentials, "no credentials provided")),
            },
        }
    }
}

impl Sspi for Negotiate {
    #[instrument(ret, level = "debug", fields(protocol = self.protocol.protocol_name()), skip(self))]
    fn complete_auth_token(&mut self, token: &mut [SecurityBuffer]) -> Result<SecurityStatus> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.complete_auth_token(token),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.complete_auth_token(token),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.complete_auth_token(token),
        }
    }

    #[instrument(ret, level = "debug", fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn encrypt_message(
        &mut self,
        flags: crate::EncryptionFlags,
        message: &mut [SecurityBufferRef<'_>],
    ) -> Result<SecurityStatus> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.encrypt_message(flags, message),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.encrypt_message(flags, message),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.encrypt_message(flags, message),
        }
    }

    #[instrument(ret, level = "debug", fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn decrypt_message(&mut self, message: &mut [SecurityBufferRef<'_>]) -> Result<DecryptionFlags> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.decrypt_message(message),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.decrypt_message(message),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.decrypt_message(message),
        }
    }

    #[instrument(ret, level = "debug", fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn query_context_sizes(&mut self) -> Result<ContextSizes> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.query_context_sizes(),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.query_context_sizes(),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.query_context_sizes(),
        }
    }

    #[instrument(ret, level = "debug", fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn query_context_names(&mut self) -> Result<ContextNames> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.query_context_names(),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.query_context_names(),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.query_context_names(),
        }
    }

    #[instrument(ret, level = "debug", fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn query_context_package_info(&mut self) -> Result<PackageInfo> {
        crate::query_security_package_info(SecurityPackageType::Negotiate)
    }

    #[instrument(ret, level = "debug", fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn query_context_negotiation_package(&mut self) -> Result<PackageInfo> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.query_context_package_info(),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.query_context_package_info(),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.query_context_package_info(),
        }
    }

    #[instrument(ret, level = "debug", fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn query_context_cert_trust_status(&mut self) -> Result<CertTrustStatus> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.query_context_cert_trust_status(),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.query_context_cert_trust_status(),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.query_context_cert_trust_status(),
        }
    }

    #[instrument(fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn query_context_session_key(&self) -> Result<crate::SessionKeys> {
        match &self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.query_context_session_key(),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.query_context_session_key(),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.query_context_session_key(),
        }
    }

    fn change_password<'a>(
        &'a mut self,
        change_password: builders::ChangePassword<'a>,
    ) -> Result<GeneratorChangePassword<'a>> {
        Ok(GeneratorChangePassword::new(move |mut yield_point| async move {
            self.change_password(&mut yield_point, change_password).await
        }))
    }

    fn make_signature(
        &mut self,
        flags: u32,
        message: &mut [SecurityBufferRef<'_>],
        sequence_number: u32,
    ) -> Result<()> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.make_signature(flags, message, sequence_number),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.make_signature(flags, message, sequence_number),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.make_signature(flags, message, sequence_number),
        }
    }

    fn verify_signature(&mut self, message: &mut [SecurityBufferRef<'_>], sequence_number: u32) -> Result<u32> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.verify_signature(message, sequence_number),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.verify_signature(message, sequence_number),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.verify_signature(message, sequence_number),
        }
    }
}

impl SspiImpl for Negotiate {
    type CredentialsHandle = Option<CredentialsBuffers>;
    type AuthenticationData = Credentials;

    #[instrument(ret, level = "debug", fields(protocol = self.protocol.protocol_name()), skip_all)]
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

        if let Some(Credentials::AuthIdentity(identity)) = builder.auth_data {
            let account_name = identity.username.account_name();
            // `realm_domain` is the per-format "authority" (UPN suffix or NetBIOS domain) used purely
            // as a best-effort realm/Azure-AD hint for protocol negotiation, not as an identity.
            let domain_name = get_client_principal_name(&identity.username).realm_domain;
            self.negotiate_protocol(account_name, domain_name)?;
        }

        self.auth_identity = builder
            .auth_data
            .cloned()
            .map(|auth_data| auth_data.try_into())
            .transpose()?;

        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => {
                let auth_identity = if let Some(Credentials::AuthIdentity(identity)) = builder.auth_data {
                    identity
                } else {
                    return Err(Error::new(
                        ErrorKind::NoCredentials,
                        "Auth identity is not provided for the Pku2u",
                    ));
                };
                let new_builder = builder.full_transform(Some(auth_identity));
                new_builder.execute(pku2u)?;
            }
            NegotiatedProtocol::Kerberos(kerberos) => {
                kerberos.acquire_credentials_handle_impl(builder)?;
            }
            NegotiatedProtocol::Ntlm(ntlm) => {
                let auth_identity = if builder.credential_use == CredentialUse::Outbound {
                    if let Some(Credentials::AuthIdentity(identity)) = builder.auth_data {
                        Some(identity)
                    } else {
                        return Err(Error::new(
                            ErrorKind::NoCredentials,
                            "Auth identity is not provided for the Ntlm",
                        ));
                    }
                } else {
                    None
                };
                let new_builder = builder.full_transform(auth_identity);
                new_builder.execute(ntlm)?;
            }
        };

        Ok(AcquireCredentialsHandleResult {
            credentials_handle: self.auth_identity.clone(),
            expiry: None,
        })
    }

    #[instrument(ret, level = "debug", fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn accept_security_context_impl<'a>(
        &'a mut self,
        builder: FilledAcceptSecurityContext<'a, Self::CredentialsHandle>,
    ) -> Result<GeneratorAcceptSecurityContext<'a>> {
        Ok(GeneratorAcceptSecurityContext::new(move |mut yield_point| async move {
            server::accept_security_context(self, &mut yield_point, builder).await
        }))
    }

    fn initialize_security_context_impl<'ctx, 'b, 'g>(
        &'ctx mut self,
        builder: &'b mut FilledInitializeSecurityContext<'ctx, 'ctx, Self::CredentialsHandle>,
    ) -> Result<GeneratorInitSecurityContext<'g>>
    where
        'ctx: 'g,
        'b: 'g,
    {
        Ok(GeneratorInitSecurityContext::new(move |mut yield_point| async move {
            client::initialize_security_context(self, &mut yield_point, builder).await
        }))
    }
}

impl<'a> Negotiate {
    #[instrument(ret, level = "debug", fields(protocol = self.protocol.protocol_name()), skip_all)]
    pub(crate) async fn change_password(
        &'a mut self,
        yield_point: &mut YieldPointLocal,
        change_password: builders::ChangePassword<'a>,
    ) -> Result<()> {
        self.negotiate_protocol(&change_password.account_name, &change_password.domain_name)?;

        match &mut self.protocol {
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.change_password(yield_point, change_password).await,
            _ => Err(Error::new(
                ErrorKind::UnsupportedFunction,
                "cannot change password for this protocol",
            )),
        }
    }
}

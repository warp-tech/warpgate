//! sspi-rs is a Rust implementation of [Security Support Provider Interface (SSPI)](https://docs.microsoft.com/en-us/windows/win32/rpc/security-support-provider-interface-sspi-).
//! It ships with platform-independent implementations of [Security Support Providers (SSP)](https://docs.microsoft.com/en-us/windows/win32/rpc/security-support-providers-ssps-),
//! and is able to utilize native Microsoft libraries when ran under Windows.
//!
//! The purpose of sspi-rs is to clean the original interface from cluttering and provide users with Rust-friendly SSPs for execution under Linux or any other platform that is
//! able to compile Rust.
//!
//! # Getting started
//!
//! Here is a quick example how to start working with the crate. This is the first stage of the client-server authentication performed on the client side.
//!
//! ```rust
//! use sspi::Sspi;
//! use sspi::Username;
//! use sspi::Ntlm;
//! use sspi::builders::EmptyInitializeSecurityContext;
//! use sspi::SspiImpl;
//!
//! let mut ntlm = Ntlm::new();
//!
//! let identity = sspi::AuthIdentity {
//!     username: Username::parse("user").unwrap(),
//!     password: "password".to_string().into(),
//! };
//!
//! let mut acq_creds_handle_result = ntlm
//!     .acquire_credentials_handle()
//!     .with_credential_use(sspi::CredentialUse::Outbound)
//!     .with_auth_data(&identity)
//!     .execute(&mut ntlm)
//!     .expect("AcquireCredentialsHandle resulted in error");
//!
//! let mut output = vec![sspi::SecurityBuffer::new(
//!     Vec::new(),
//!     sspi::BufferType::Token,
//! )];
//!
//! let mut builder = ntlm.initialize_security_context()
//!     .with_credentials_handle(&mut acq_creds_handle_result.credentials_handle)
//!     .with_context_requirements(
//!         sspi::ClientRequestFlags::CONFIDENTIALITY | sspi::ClientRequestFlags::ALLOCATE_MEMORY
//!     )
//!     .with_target_data_representation(sspi::DataRepresentation::Native)
//!     .with_output(&mut output);
//!
//! let result = ntlm.initialize_security_context_impl(&mut builder)
//!     .expect("InitializeSecurityContext resulted in error")
//!     .resolve_to_result()
//!     .expect("InitializeSecurityContext resulted in error");
//!
//! println!("Initialized security context with result status: {:?}", result.status);
//! ```

#[macro_use]
extern crate tracing;

pub mod builders;
pub mod channel_bindings;
pub mod credssp;
pub mod generator;
pub mod kerberos;
pub mod negotiate;
pub mod network_client;
pub mod ntlm;
mod pk_init;
pub mod pku2u;
pub mod utf16string;

mod auth_identity;
mod ber;
mod crypto;
mod dns;
mod kdc;
mod krb;
mod rustls;
mod secret;
mod security_buffer;
mod smartcard;
mod utils;

#[cfg(all(feature = "tsssp", not(target_os = "windows")))]
compile_error!("tsssp feature should be used only on Windows");

use std::{error, fmt, io, result, str, string};

use bitflags::bitflags;
#[cfg(feature = "tsssp")]
use credssp::sspi_cred_ssp;
pub use generator::NetworkRequest;
use generator::{GeneratorAcceptSecurityContext, GeneratorChangePassword, GeneratorInitSecurityContext};
pub use network_client::NetworkProtocol;
use num_derive::{FromPrimitive, ToPrimitive};
use picky_asn1::restricted_string::CharSetError;
use picky_asn1_der::Asn1DerError;
use picky_asn1_x509::Certificate;
use picky_krb::gss_api::GssApiMessageError;
use picky_krb::messages::KrbError;
#[cfg(feature = "__rustls-used")]
pub use rustls::install_default_crypto_provider_if_necessary;
pub use security_buffer::SecurityBufferRef;
pub use utf16string::{
    NonEmpty, U16CStr, U16CString, U16CStringExt, Utf16Str, Utf16String, Utf16StringExt, ZeroizedUtf16String,
};
use utils::map_keb_error_code_to_sspi_error;
pub use utils::modpow;

pub use self::auth_identity::{
    AuthIdentity, AuthIdentityBuffers, Credentials, CredentialsBuffers, DownLevelLogonNameParts, KeytabIdentity,
    UserNameFormat, UserPrincipalNameParts, Username, UsernameParts,
};
#[cfg(feature = "scard")]
pub use self::auth_identity::{CertificateRaw, SmartCardIdentity, SmartCardIdentityBuffers, SmartCardType};
pub use self::builders::{
    AcceptSecurityContextResult, AcquireCredentialsHandleResult, InitializeSecurityContextResult,
};
use self::builders::{
    ChangePassword, FilledAcceptSecurityContext, FilledAcquireCredentialsHandle, FilledInitializeSecurityContext,
};
pub use self::kdc::{detect_kdc_host, detect_kdc_url};
pub use self::kerberos::config::{KerberosConfig, KerberosServerConfig};
pub use self::kerberos::{KERBEROS_VERSION, Kerberos, KerberosState};
#[cfg(feature = "__test-data")]
pub use self::negotiate::client::FALLBACK_ERROR_KINDS;
pub use self::negotiate::{Negotiate, NegotiateConfig, NegotiatedProtocol};
pub use self::ntlm::Ntlm;
pub use self::ntlm::hash::{NTLM_HASH_PREFIX, NtlmHash, NtlmHashError};
pub use self::pku2u::{Pku2u, Pku2uConfig, Pku2uState};
pub use self::secret::Secret;
use crate::builders::{
    EmptyAcceptSecurityContext, EmptyAcquireCredentialsHandle, EmptyInitializeSecurityContext,
    InitializeSecurityContext,
};

/// Representation of SSPI-related result operation. Makes it easier to return a `Result` with SSPI-related `Error`.
pub type Result<T> = result::Result<T, Error>;
pub type Luid = u64;

const PACKAGE_ID_NONE: u16 = 0xFFFF;

/// Retrieves information about a specified security package. This information includes credentials and contexts.
///
/// # Returns
///
/// * `PackageInfo` containing the information about the security principal upon success
/// * `Error` on error
///
/// # Example
///
/// ```
/// let package_info = sspi::query_security_package_info(sspi::SecurityPackageType::Ntlm)
///     .unwrap();
/// println!("Package info:");
/// println!("Name: {:?}", package_info.name);
/// println!("Comment: {}", package_info.comment);
/// ```
///
/// # MSDN
///
/// * [QuerySecurityPackageInfoW function](https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-querysecuritypackageinfow)
pub fn query_security_package_info(package_type: SecurityPackageType) -> Result<PackageInfo> {
    match package_type {
        SecurityPackageType::Ntlm => Ok(ntlm::PACKAGE_INFO.clone()),
        SecurityPackageType::Kerberos => Ok(kerberos::PACKAGE_INFO.clone()),
        SecurityPackageType::Negotiate => Ok(negotiate::PACKAGE_INFO.clone()),
        SecurityPackageType::Pku2u => Ok(pku2u::PACKAGE_INFO.clone()),
        #[cfg(feature = "tsssp")]
        SecurityPackageType::CredSsp => Ok(sspi_cred_ssp::PACKAGE_INFO.clone()),
        SecurityPackageType::Other(s) => Err(Error::new(
            ErrorKind::Unknown,
            format!("queried info about unknown package: {s:?}"),
        )),
    }
}

/// Returns an array of `PackageInfo` structures that provide information about the security packages available to the client.
///
/// # Returns
///
/// * `Vec` of `PackageInfo` structures upon success
/// * `Error` on error
///
/// # Example
///
/// ```
/// let packages = sspi::enumerate_security_packages().unwrap();
///
/// println!("Available packages:");
/// for ssp in packages {
///     println!("{:?}", ssp.name);
/// }
/// ```
///
/// # MSDN
///
/// * [EnumerateSecurityPackagesW function](https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-enumeratesecuritypackagesw)
pub fn enumerate_security_packages() -> Result<Vec<PackageInfo>> {
    Ok(vec![
        negotiate::PACKAGE_INFO.clone(),
        kerberos::PACKAGE_INFO.clone(),
        pku2u::PACKAGE_INFO.clone(),
        ntlm::PACKAGE_INFO.clone(),
        #[cfg(feature = "tsssp")]
        sspi_cred_ssp::PACKAGE_INFO.clone(),
    ])
}

/// This trait provides interface for all available SSPI functions. The `acquire_credentials_handle`,
/// `initialize_security_context`, and `accept_security_context` methods return Builders that make it
/// easier to assemble the list of arguments for the function and then execute it.
///
/// # MSDN
///
/// * [SSPI.h](https://docs.microsoft.com/en-us/windows/win32/api/sspi/)
pub trait Sspi
where
    Self: Sized + SspiImpl,
{
    /// Acquires a handle to preexisting credentials of a security principal. The preexisting credentials are
    /// available only for `sspi::winapi` module. This handle is required by the `initialize_security_context`
    /// and `accept_security_context` functions. These can be either preexisting credentials, which are
    /// established through a system logon, or the caller can provide alternative credentials. Alternative
    /// credentials are always required to specify when using platform independent SSPs.
    ///
    /// # Returns
    ///
    /// * `AcquireCredentialsHandle` builder
    ///
    /// # Requirements for execution
    ///
    /// These methods are required to be called before calling the `execute` method of the `AcquireCredentialsHandle` builder:
    /// * [`with_credential_use`](builders/struct.AcquireCredentialsHandle.html#method.with_credential_use)
    ///
    /// # Example
    ///
    /// ```
    /// use sspi::Sspi;
    /// use sspi::Username;
    ///
    /// let mut ntlm = sspi::Ntlm::new();
    ///
    /// let identity = sspi::AuthIdentity {
    ///     username: Username::parse("user").unwrap(),
    ///     password: "password".to_string().into(),
    /// };
    ///
    /// #[allow(unused_variables)]
    /// let result = ntlm
    ///     .acquire_credentials_handle()
    ///     .with_credential_use(sspi::CredentialUse::Outbound)
    ///     .with_auth_data(&identity)
    ///     .execute(&mut ntlm)
    ///     .unwrap();
    /// ```
    ///
    /// # MSDN
    ///
    /// * [AcquireCredentialshandleW function](https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-acquirecredentialshandlew)
    fn acquire_credentials_handle<'a>(
        &mut self,
    ) -> EmptyAcquireCredentialsHandle<'a, Self::CredentialsHandle, Self::AuthenticationData> {
        EmptyAcquireCredentialsHandle::new()
    }

    /// Initiates the client side, outbound security context from a credential handle.
    /// The function is used to build a security context between the client application and a remote peer. The function returns a token
    /// that the client must pass to the remote peer, which the peer in turn submits to the local security implementation through the
    /// `accept_security_context` call.
    ///
    /// # Returns
    ///
    /// * `InitializeSecurityContext` builder
    ///
    /// # Requirements for execution
    ///
    /// These methods are required to be called before calling the `execute` method
    /// * [`with_credentials_handle`](builders/struct.InitializeSecurityContext.html#method.with_credentials_handle)
    /// * [`with_context_requirements`](builders/struct.InitializeSecurityContext.html#method.with_context_requirements)
    /// * [`with_target_data_representation`](builders/struct.InitializeSecurityContext.html#method.with_target_data_representation)
    /// * [`with_output`](builders/struct.InitializeSecurityContext.html#method.with_output)
    ///
    /// # Example
    ///
    /// ```
    /// use sspi::Sspi;
    /// use sspi::Username;
    /// use sspi::builders::EmptyInitializeSecurityContext;
    /// use sspi::SspiImpl;
    ///
    /// let mut ntlm = sspi::Ntlm::new();
    ///
    /// let identity = sspi::AuthIdentity {
    ///     username: Username::new(&whoami::username().unwrap(), Some(&whoami::hostname().unwrap())).unwrap(),
    ///     password: String::from("password").into(),
    /// };
    ///
    /// let mut acq_cred_result = ntlm
    ///     .acquire_credentials_handle()
    ///     .with_credential_use(sspi::CredentialUse::Outbound)
    ///     .with_auth_data(&identity)
    ///     .execute(&mut ntlm)
    ///     .unwrap();
    ///
    /// let mut credentials_handle = acq_cred_result.credentials_handle;
    ///
    /// let mut output_buffer = vec![sspi::SecurityBuffer::new(Vec::new(), sspi::BufferType::Token)];
    ///
    /// #[allow(unused_variables)]
    /// let mut builder = ntlm.initialize_security_context()
    ///     .with_credentials_handle(&mut credentials_handle)
    ///     .with_context_requirements(
    ///         sspi::ClientRequestFlags::CONFIDENTIALITY | sspi::ClientRequestFlags::ALLOCATE_MEMORY,
    ///     )
    ///     .with_target_data_representation(sspi::DataRepresentation::Native)
    ///     .with_output(&mut output_buffer);
    ///
    /// let result = ntlm.initialize_security_context_impl(&mut builder)
    ///         .unwrap()
    ///         .resolve_to_result()
    ///         .unwrap();
    /// ```
    ///
    /// # MSDN
    ///
    /// * [InitializeSecurityContextW function](https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-initializesecuritycontextw)
    fn initialize_security_context<'a, 'output>(
        &mut self,
    ) -> EmptyInitializeSecurityContext<'a, 'output, Self::CredentialsHandle> {
        InitializeSecurityContext::new()
    }

    /// Lets the server component of a transport application establish a security context between the server and a remote client.
    /// The remote client calls the `initialize_security_context` function to start the process of establishing a security context.
    /// The server can require one or more reply tokens from the remote client to complete establishing the security context.
    ///
    /// # Returns
    ///
    /// * `AcceptSecurityContext` builder
    ///
    /// # Requirements for execution
    ///
    /// These methods are required to be called before calling the `execute` method of the `AcceptSecurityContext` builder:
    /// * [`with_credentials_handle`](builders/struct.AcceptSecurityContext.html#method.with_credentials_handle)
    /// * [`with_context_requirements`](builders/struct.AcceptSecurityContext.html#method.with_context_requirements)
    /// * [`with_target_data_representation`](builders/struct.AcceptSecurityContext.html#method.with_target_data_representation)
    /// * [`with_output`](builders/struct.AcceptSecurityContext.html#method.with_output)
    ///
    /// # Example
    ///
    /// ```
    /// use sspi::Sspi;
    /// use sspi::Username;
    /// use sspi::builders::EmptyInitializeSecurityContext;
    /// use sspi::SspiImpl;
    ///
    /// let mut client_ntlm = sspi::Ntlm::new();
    ///
    /// let identity = sspi::AuthIdentity {
    ///     username: Username::parse("user").unwrap(),
    ///     password: "password".to_string().into(),
    /// };
    ///
    /// let mut client_acq_cred_result = client_ntlm
    ///     .acquire_credentials_handle()
    ///     .with_credential_use(sspi::CredentialUse::Outbound)
    ///     .with_auth_data(&identity)
    ///     .execute(&mut client_ntlm)
    ///     .unwrap();
    ///
    /// let mut client_output_buffer = vec![sspi::SecurityBuffer::new(Vec::new(), sspi::BufferType::Token)];
    ///
    /// let mut builder = client_ntlm.initialize_security_context()
    ///     .with_credentials_handle(&mut client_acq_cred_result.credentials_handle)
    ///     .with_context_requirements(
    ///         sspi::ClientRequestFlags::CONFIDENTIALITY | sspi::ClientRequestFlags::ALLOCATE_MEMORY,
    ///     )
    ///     .with_target_data_representation(sspi::DataRepresentation::Native)
    ///     .with_target_name("user")
    ///     .with_output(&mut client_output_buffer);
    ///
    /// let _result = client_ntlm.initialize_security_context_impl(&mut builder)
    ///         .unwrap()
    ///         .resolve_to_result()
    ///         .unwrap();
    ///
    /// let mut ntlm = sspi::Ntlm::new();
    /// let mut output_buffer = vec![sspi::SecurityBuffer::new(Vec::new(), sspi::BufferType::Token)];
    ///
    /// let mut server_acq_cred_result = ntlm
    ///     .acquire_credentials_handle()
    ///     .with_credential_use(sspi::CredentialUse::Inbound)
    ///     .with_auth_data(&identity)
    ///     .execute(&mut ntlm)
    ///     .unwrap();
    ///
    /// let mut credentials_handle = server_acq_cred_result.credentials_handle;
    ///
    /// #[allow(unused_variables)]
    /// let result = ntlm
    ///     .accept_security_context()
    ///     .with_credentials_handle(&mut credentials_handle)
    ///     .with_context_requirements(sspi::ServerRequestFlags::ALLOCATE_MEMORY)
    ///     .with_target_data_representation(sspi::DataRepresentation::Native)
    ///     .with_input(&mut client_output_buffer)
    ///     .with_output(&mut output_buffer)
    ///     .execute(&mut ntlm)
    ///     .unwrap();
    /// ```
    ///
    /// # MSDN
    ///
    /// * [AcceptSecurityContext function](https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-acceptsecuritycontext)
    fn accept_security_context<'a>(&mut self) -> EmptyAcceptSecurityContext<'a, Self::CredentialsHandle> {
        EmptyAcceptSecurityContext::new()
    }

    /// Completes an authentication token. This function is used by protocols, such as DCE,
    /// that need to revise the security information after the transport application has updated some message parameters.
    ///
    /// # Parameters
    ///
    /// * `token`: `SecurityBufferRef` that contains the buffer descriptor for the entire message
    ///
    /// # Returns
    ///
    /// * `SspiOk` on success
    /// * `Error` on error
    ///
    /// # Example
    ///
    /// ```
    /// use sspi::Sspi;
    /// use sspi::Username;
    /// use sspi::builders::EmptyInitializeSecurityContext;
    /// use sspi::SspiImpl;
    ///
    /// let mut client_ntlm = sspi::Ntlm::new();
    /// let mut ntlm = sspi::Ntlm::new();
    ///
    /// let mut client_output_buffer = vec![sspi::SecurityBuffer::new(Vec::new(), sspi::BufferType::Token)];
    /// let mut output_buffer = vec![sspi::SecurityBuffer::new(Vec::new(), sspi::BufferType::Token)];
    ///
    /// let identity = sspi::AuthIdentity {
    ///     username: Username::parse("user").unwrap(),
    ///     password: "password".to_string().into(),
    /// };
    ///
    /// let mut client_acq_cred_result = client_ntlm
    ///     .acquire_credentials_handle()
    ///     .with_credential_use(sspi::CredentialUse::Outbound)
    ///     .with_auth_data(&identity)
    ///     .execute(&mut ntlm)
    ///     .unwrap();
    ///
    /// let mut server_acq_cred_result = ntlm
    ///     .acquire_credentials_handle()
    ///     .with_credential_use(sspi::CredentialUse::Inbound)
    ///     .with_auth_data(&identity)
    ///     .execute(&mut ntlm)
    ///     .unwrap();
    ///
    /// loop {
    ///     client_output_buffer[0].buffer.clear();
    ///
    ///     let mut builder = client_ntlm.initialize_security_context()
    ///         .with_credentials_handle(&mut client_acq_cred_result.credentials_handle)
    ///         .with_context_requirements(
    ///             sspi::ClientRequestFlags::CONFIDENTIALITY | sspi::ClientRequestFlags::ALLOCATE_MEMORY,
    ///         )
    ///         .with_target_data_representation(sspi::DataRepresentation::Native)
    ///         .with_target_name("user")
    ///         .with_input(&mut output_buffer)
    ///         .with_output(&mut client_output_buffer);
    ///
    ///     let _client_result = client_ntlm.initialize_security_context_impl(&mut builder)
    ///         .unwrap()
    ///         .resolve_to_result()
    ///         .unwrap();
    ///
    ///     let builder = ntlm
    ///         .accept_security_context()
    ///         .with_credentials_handle(&mut server_acq_cred_result.credentials_handle)
    ///         .with_context_requirements(sspi::ServerRequestFlags::ALLOCATE_MEMORY)
    ///         .with_target_data_representation(sspi::DataRepresentation::Native)
    ///         .with_input(&mut client_output_buffer)
    ///         .with_output(&mut output_buffer);
    ///     let server_result = ntlm.accept_security_context_impl(builder)
    ///         .unwrap()
    ///         .resolve_to_result()
    ///         .unwrap();
    ///
    ///     if server_result.status == sspi::SecurityStatus::CompleteAndContinue
    ///         || server_result.status == sspi::SecurityStatus::CompleteNeeded
    ///     {
    ///         break;
    ///     }
    /// }
    ///
    /// #[allow(unused_variables)]
    /// let result = ntlm
    ///     .complete_auth_token(&mut output_buffer)
    ///     .unwrap();
    /// ```
    ///
    /// # MSDN
    ///
    /// * [CompleteAuthToken function](https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-completeauthtoken)
    fn complete_auth_token(&mut self, token: &mut [SecurityBuffer]) -> Result<SecurityStatus>;

    /// Encrypts a message to provide privacy. The function allows the application to choose among cryptographic algorithms supported by the chosen mechanism.
    /// Some packages do not have messages to be encrypted or decrypted but rather provide an integrity hash that can be checked.
    ///
    /// # Parameters
    ///
    /// * `flags`: package-specific flags that indicate the quality of protection. A security package can use this parameter to enable the selection of cryptographic algorithms
    /// * `message`: on input, the structure accepts one or more `SecurityBufferRef` structures that can be of type `BufferType::Data`.
    ///   That buffer contains the message to be encrypted. The message is encrypted in place, overwriting the original contents of the structure.
    /// * `sequence_number`: the sequence number that the transport application assigned to the message. If the transport application does not maintain sequence numbers, this parameter must be zero
    ///
    /// # Example
    ///
    /// ```
    /// use sspi::Sspi;
    /// use sspi::Username;
    /// use sspi::builders::EmptyInitializeSecurityContext;
    /// use sspi::SspiImpl;
    ///
    /// let mut client_ntlm = sspi::Ntlm::new();
    /// let mut ntlm = sspi::Ntlm::new();
    ///
    /// let mut client_output_buffer = vec![sspi::SecurityBuffer::new(Vec::new(), sspi::BufferType::Token)];
    /// let mut server_output_buffer = vec![sspi::SecurityBuffer::new(Vec::new(), sspi::BufferType::Token)];
    ///
    /// let identity = sspi::AuthIdentity {
    ///     username: Username::parse("user").unwrap(),
    ///     password: "password".to_string().into(),
    /// };
    ///
    /// let mut client_acq_cred_result = client_ntlm
    ///     .acquire_credentials_handle()
    ///     .with_credential_use(sspi::CredentialUse::Outbound)
    ///     .with_auth_data(&identity)
    ///     .execute(&mut client_ntlm)
    ///     .unwrap();
    ///
    /// let mut server_acq_cred_result = ntlm
    ///     .acquire_credentials_handle()
    ///     .with_credential_use(sspi::CredentialUse::Inbound)
    ///     .with_auth_data(&identity)
    ///     .execute(&mut ntlm)
    ///     .unwrap();
    ///
    /// loop {
    ///     client_output_buffer[0].buffer.clear();
    ///
    ///     let mut builder = client_ntlm.initialize_security_context()
    ///         .with_credentials_handle(&mut client_acq_cred_result.credentials_handle)
    ///         .with_context_requirements(
    ///             sspi::ClientRequestFlags::CONFIDENTIALITY | sspi::ClientRequestFlags::ALLOCATE_MEMORY,
    ///         )
    ///         .with_target_data_representation(sspi::DataRepresentation::Native)
    ///         .with_target_name("user")
    ///         .with_input(&mut server_output_buffer)
    ///         .with_output(&mut client_output_buffer);
    ///
    ///     let _client_result = client_ntlm.initialize_security_context_impl(&mut builder)
    ///         .unwrap()
    ///         .resolve_to_result()
    ///         .unwrap();
    ///
    ///     let builder = ntlm
    ///         .accept_security_context()
    ///         .with_credentials_handle(&mut server_acq_cred_result.credentials_handle)
    ///         .with_context_requirements(sspi::ServerRequestFlags::ALLOCATE_MEMORY)
    ///         .with_target_data_representation(sspi::DataRepresentation::Native)
    ///         .with_input(&mut client_output_buffer)
    ///         .with_output(&mut server_output_buffer);
    ///     let server_result = ntlm.accept_security_context_impl(builder)
    ///         .unwrap()
    ///         .resolve_to_result()
    ///         .unwrap();
    ///
    ///     if server_result.status == sspi::SecurityStatus::CompleteAndContinue
    ///         || server_result.status == sspi::SecurityStatus::CompleteNeeded
    ///     {
    ///         break;
    ///     }
    /// }
    ///
    /// let _result = ntlm
    ///     .complete_auth_token(&mut server_output_buffer)
    ///     .unwrap();
    ///
    /// let mut token = [0; 128];
    /// let mut data = "This is a message".as_bytes().to_vec();
    /// let mut msg_buffer = vec![
    ///     sspi::SecurityBufferRef::token_buf(token.as_mut_slice()),
    ///     sspi::SecurityBufferRef::data_buf(data.as_mut_slice()),
    /// ];
    ///
    /// println!("Unencrypted: {:?}", msg_buffer[1].data());
    ///
    /// # #[allow(unused_variables)]
    /// let result = ntlm
    ///     .encrypt_message(sspi::EncryptionFlags::empty(), &mut msg_buffer).unwrap();
    ///
    /// println!("Encrypted: {:?}", msg_buffer[1].data());
    /// ```
    ///
    /// # Returns
    ///
    /// * `SspiOk` on success
    /// * `Error` on error
    ///
    /// # MSDN
    ///
    /// * [EncryptMessage function](https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-encryptmessage)
    fn encrypt_message(
        &mut self,
        flags: EncryptionFlags,
        message: &mut [SecurityBufferRef<'_>],
    ) -> Result<SecurityStatus>;

    /// Generates a cryptographic checksum of the message, and also includes sequencing information to prevent message loss or insertion.
    /// The function allows the application to choose between several cryptographic algorithms, if supported by the chosen mechanism.
    ///
    /// # Parameters
    /// * `flags`: package-specific flags that indicate the quality of protection. A security package can use this parameter to enable the selection of cryptographic algorithms
    /// * `message`: On input, the structure references one or more `SecurityBufferRef` structures of type `BufferType::Data` that contain the message to be signed,
    ///   and a `SecurityBufferRef` of type `BufferType::Token` that receives the signature.
    /// * `sequence_number`: the sequence number that the transport application assigned to the message. If the transport application does not maintain sequence numbers, this parameter must be zero
    ///
    /// # Returns
    /// * `SspiOk` on success
    /// * `Error` on error
    ///
    /// # Example
    ///
    /// ```
    /// use sspi::Sspi;
    /// use sspi::Username;
    /// use sspi::builders::EmptyInitializeSecurityContext;
    /// use sspi::SspiImpl;
    ///
    /// let mut client_ntlm = sspi::Ntlm::new();
    /// let mut ntlm = sspi::Ntlm::new();
    ///
    /// let mut client_output_buffer = vec![sspi::SecurityBuffer::new(Vec::new(), sspi::BufferType::Token)];
    /// let mut server_output_buffer = vec![sspi::SecurityBuffer::new(Vec::new(), sspi::BufferType::Token)];
    ///
    /// let identity = sspi::AuthIdentity {
    ///     username: Username::parse("user").unwrap(),
    ///     password: "password".to_string().into(),
    /// };
    ///
    /// let mut client_acq_cred_result = client_ntlm
    ///     .acquire_credentials_handle()
    ///     .with_credential_use(sspi::CredentialUse::Outbound)
    ///     .with_auth_data(&identity)
    ///     .execute(&mut client_ntlm)
    ///     .unwrap();
    ///
    /// let mut server_acq_cred_result = ntlm
    ///     .acquire_credentials_handle()
    ///     .with_credential_use(sspi::CredentialUse::Inbound)
    ///     .with_auth_data(&identity)
    ///     .execute(&mut ntlm)
    ///     .unwrap();
    ///
    /// loop {
    ///     client_output_buffer[0].buffer.clear();
    ///
    ///     let mut builder = client_ntlm.initialize_security_context()
    ///         .with_credentials_handle(&mut client_acq_cred_result.credentials_handle)
    ///         .with_context_requirements(
    ///             sspi::ClientRequestFlags::CONFIDENTIALITY | sspi::ClientRequestFlags::ALLOCATE_MEMORY,
    ///         )
    ///         .with_target_data_representation(sspi::DataRepresentation::Native)
    ///         .with_target_name("user")
    ///         .with_input(&mut server_output_buffer)
    ///         .with_output(&mut client_output_buffer);
    ///
    ///     let _client_result = client_ntlm.initialize_security_context_impl(&mut builder)
    ///         .unwrap()
    ///         .resolve_to_result()
    ///         .unwrap();
    ///
    ///     let builder = ntlm
    ///         .accept_security_context()
    ///         .with_credentials_handle(&mut server_acq_cred_result.credentials_handle)
    ///         .with_context_requirements(sspi::ServerRequestFlags::ALLOCATE_MEMORY)
    ///         .with_target_data_representation(sspi::DataRepresentation::Native)
    ///         .with_input(&mut client_output_buffer)
    ///         .with_output(&mut server_output_buffer);
    ///     let server_result = ntlm.accept_security_context_impl(builder)
    ///         .unwrap()
    ///         .resolve_to_result()
    ///         .unwrap();
    ///
    ///     if server_result.status == sspi::SecurityStatus::CompleteAndContinue
    ///         || server_result.status == sspi::SecurityStatus::CompleteNeeded
    ///     {
    ///         break;
    ///     }
    /// }
    ///
    /// let _result = ntlm
    ///     .complete_auth_token(&mut server_output_buffer)
    ///     .unwrap();
    ///
    /// let mut token = [0; 128];
    /// let mut data = "This is a message to be signed".as_bytes().to_vec();
    /// let mut msg_buffer = vec![
    ///     sspi::SecurityBufferRef::token_buf(token.as_mut_slice()),
    ///     sspi::SecurityBufferRef::data_buf(data.as_mut_slice()),
    /// ];
    ///
    /// println!("Input data: {:?}", msg_buffer[1].data());
    ///
    /// #[allow(unused_variables)]
    /// let result = ntlm
    ///     .make_signature(0, &mut msg_buffer, 0).unwrap();
    ///
    /// println!("Data signature: {:?}", msg_buffer[0].data());
    /// ```
    ///
    /// # MSDN
    /// * [MakeSignature function](https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-makesignature)
    fn make_signature(&mut self, flags: u32, message: &mut [SecurityBufferRef<'_>], sequence_number: u32)
    -> Result<()>;

    /// Verifies that a message signed by using the `make_signature` function was received in the correct sequence and has not been modified.
    ///
    /// # Parameters
    /// * `message`: On input, the structure references one or more `SecurityBufferRef` structures of type `BufferType::Data` that contain the message to be verified,
    ///   and a `SecurityBufferRef` of type `BufferType::Token` that contains the signature.
    /// * `sequence_number`: the sequence number that the transport application assigned to the message. If the transport application does not maintain sequence numbers, this parameter must be zero
    ///
    /// # Returns
    /// * `u32` package-specific flags that indicate the quality of protection.
    /// * `Error` on error
    ///
    /// # Example
    ///
    /// ```
    /// use sspi::Sspi;
    /// use sspi::Username;
    /// use sspi::builders::EmptyInitializeSecurityContext;
    /// use sspi::SspiImpl;
    ///
    /// let mut ntlm = sspi::Ntlm::new();
    /// let mut server_ntlm = sspi::Ntlm::new();
    ///
    /// let mut client_output_buffer = vec![sspi::SecurityBuffer::new(Vec::new(), sspi::BufferType::Token)];
    /// let mut server_output_buffer = vec![sspi::SecurityBuffer::new(Vec::new(), sspi::BufferType::Token)];
    ///
    /// let identity = sspi::AuthIdentity {
    ///     username: Username::parse("user").unwrap(),
    ///     password: "password".to_string().into(),
    /// };
    ///
    /// let mut client_acq_cred_result = ntlm
    ///     .acquire_credentials_handle()
    ///     .with_credential_use(sspi::CredentialUse::Outbound)
    ///     .with_auth_data(&identity)
    ///     .execute(&mut ntlm)
    ///     .unwrap();
    ///
    /// let mut server_acq_cred_result = server_ntlm
    ///     .acquire_credentials_handle()
    ///     .with_credential_use(sspi::CredentialUse::Inbound)
    ///     .with_auth_data(&identity)
    ///     .execute(&mut server_ntlm)
    ///     .unwrap();
    ///
    /// loop {
    ///     client_output_buffer[0].buffer.clear();
    ///
    ///     let mut builder = ntlm.initialize_security_context()
    ///         .with_credentials_handle(&mut client_acq_cred_result.credentials_handle)
    ///         .with_context_requirements(
    ///             sspi::ClientRequestFlags::CONFIDENTIALITY | sspi::ClientRequestFlags::ALLOCATE_MEMORY,
    ///         )
    ///         .with_target_data_representation(sspi::DataRepresentation::Native)
    ///         .with_target_name("user")
    ///         .with_input(&mut server_output_buffer)
    ///         .with_output(&mut client_output_buffer);
    ///
    ///     let _client_result = ntlm.initialize_security_context_impl(&mut builder)
    ///         .unwrap()
    ///         .resolve_to_result()
    ///         .unwrap();
    ///
    ///     let builder = server_ntlm
    ///         .accept_security_context()
    ///         .with_credentials_handle(&mut server_acq_cred_result.credentials_handle)
    ///         .with_context_requirements(sspi::ServerRequestFlags::ALLOCATE_MEMORY)
    ///         .with_target_data_representation(sspi::DataRepresentation::Native)
    ///         .with_input(&mut client_output_buffer)
    ///         .with_output(&mut server_output_buffer);
    ///     let server_result = server_ntlm.accept_security_context_impl(builder)
    ///         .unwrap()
    ///         .resolve_to_result()
    ///         .unwrap();
    ///
    ///     if server_result.status == sspi::SecurityStatus::CompleteAndContinue
    ///         || server_result.status == sspi::SecurityStatus::CompleteNeeded
    ///     {
    ///         break;
    ///     }
    /// }
    ///
    /// let _result = server_ntlm
    ///     .complete_auth_token(&mut server_output_buffer)
    ///     .unwrap();
    ///
    /// let mut token = [0; 128];
    /// let mut data = "This is a message".as_bytes().to_vec();
    /// let mut msg = [
    ///     sspi::SecurityBufferRef::token_buf(token.as_mut_slice()),
    ///     sspi::SecurityBufferRef::data_buf(data.as_mut_slice()),
    /// ];
    ///
    /// let _result = server_ntlm
    ///     .make_signature(0, &mut msg, 0).unwrap();
    ///
    /// let [mut token, mut data] = msg;
    ///
    /// let mut msg_buffer = vec![
    ///     sspi::SecurityBufferRef::token_buf(token.take_data()),
    ///     sspi::SecurityBufferRef::data_buf(data.take_data()),
    /// ];
    ///
    /// #[allow(unused_variables)]
    /// let signature_flags = ntlm
    ///     .verify_signature(&mut msg_buffer, 0)
    ///     .unwrap();
    ///
    /// println!("Signature calculated and verified.");
    /// ```
    ///
    /// # MSDN
    /// * [VerifySignature function](https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-verifysignature)
    fn verify_signature(&mut self, message: &mut [SecurityBufferRef<'_>], sequence_number: u32) -> Result<u32>;

    /// Decrypts a message. Some packages do not encrypt and decrypt messages but rather perform and check an integrity hash.
    ///
    /// # Parameters
    ///
    /// * `message`: on input, the structure references one or more `SecurityBufferRef` structures.
    ///   At least one of these must be of type `BufferType::Data`.
    ///   That buffer contains the encrypted message. The encrypted message is decrypted in place, overwriting the original contents of its buffer
    /// * `sequence_number`: the sequence number that the transport application assigned to the message. If the transport application does not maintain sequence numbers, this parameter must be zero
    ///
    /// # Returns
    ///
    /// * `DecryptionFlags` upon success
    /// * `Error` on error
    ///
    /// # Example
    ///
    /// ```
    /// use sspi::Sspi;
    /// use sspi::Username;
    /// use sspi::builders::EmptyInitializeSecurityContext;
    /// use sspi::SspiImpl;
    ///
    /// let mut ntlm = sspi::Ntlm::new();
    /// let mut server_ntlm = sspi::Ntlm::new();
    ///
    /// let mut client_output_buffer = vec![sspi::SecurityBuffer::new(Vec::new(), sspi::BufferType::Token)];
    /// let mut server_output_buffer = vec![sspi::SecurityBuffer::new(Vec::new(), sspi::BufferType::Token)];
    ///
    /// let identity = sspi::AuthIdentity {
    ///     username: Username::parse("user").unwrap(),
    ///     password: "password".to_string().into(),
    /// };
    ///
    /// let mut client_acq_cred_result = ntlm
    ///     .acquire_credentials_handle()
    ///     .with_credential_use(sspi::CredentialUse::Outbound)
    ///     .with_auth_data(&identity)
    ///     .execute(&mut ntlm)
    ///     .unwrap();
    ///
    /// let mut server_acq_cred_result = server_ntlm
    ///     .acquire_credentials_handle()
    ///     .with_credential_use(sspi::CredentialUse::Inbound)
    ///     .with_auth_data(&identity)
    ///     .execute(&mut server_ntlm)
    ///     .unwrap();
    ///
    /// loop {
    ///     client_output_buffer[0].buffer.clear();
    ///
    ///     let mut builder = ntlm.initialize_security_context()
    ///         .with_credentials_handle(&mut client_acq_cred_result.credentials_handle)
    ///         .with_context_requirements(
    ///             sspi::ClientRequestFlags::CONFIDENTIALITY | sspi::ClientRequestFlags::ALLOCATE_MEMORY,
    ///         )
    ///         .with_target_data_representation(sspi::DataRepresentation::Native)
    ///         .with_target_name("user")
    ///         .with_input(&mut server_output_buffer)
    ///         .with_output(&mut client_output_buffer);
    ///
    ///     let _client_result = ntlm.initialize_security_context_impl(&mut builder)
    ///         .unwrap()
    ///         .resolve_to_result()
    ///         .unwrap();
    ///
    ///     let builder = server_ntlm
    ///         .accept_security_context()
    ///         .with_credentials_handle(&mut server_acq_cred_result.credentials_handle)
    ///         .with_context_requirements(sspi::ServerRequestFlags::ALLOCATE_MEMORY)
    ///         .with_target_data_representation(sspi::DataRepresentation::Native)
    ///         .with_input(&mut client_output_buffer)
    ///         .with_output(&mut server_output_buffer);
    ///     let server_result = server_ntlm.accept_security_context_impl(builder)
    ///         .unwrap()
    ///         .resolve_to_result()
    ///         .unwrap();
    ///
    ///     if server_result.status == sspi::SecurityStatus::CompleteAndContinue
    ///         || server_result.status == sspi::SecurityStatus::CompleteNeeded
    ///     {
    ///         break;
    ///     }
    /// }
    ///
    /// let _result = server_ntlm
    ///     .complete_auth_token(&mut server_output_buffer)
    ///     .unwrap();
    ///
    /// let mut token = [0; 128];
    /// let mut data = "This is a message".as_bytes().to_vec();
    /// let mut msg = [
    ///     sspi::SecurityBufferRef::token_buf(token.as_mut_slice()),
    ///     sspi::SecurityBufferRef::data_buf(data.as_mut_slice()),
    /// ];
    ///
    /// let _result = server_ntlm
    ///     .encrypt_message(sspi::EncryptionFlags::empty(), &mut msg).unwrap();
    ///
    /// let [mut token, mut data] = msg;
    ///
    /// let mut msg_buffer = vec![
    ///     sspi::SecurityBufferRef::token_buf(token.take_data()),
    ///     sspi::SecurityBufferRef::data_buf(data.take_data()),
    /// ];
    ///
    /// #[allow(unused_variables)]
    /// let encryption_flags = ntlm
    ///     .decrypt_message(&mut msg_buffer)
    ///     .unwrap();
    ///
    /// println!("Decrypted message: {:?}", msg_buffer[1].data());
    /// ```
    ///
    /// # MSDN
    ///
    /// * [DecryptMessage function](https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-decryptmessage)
    fn decrypt_message(&mut self, message: &mut [SecurityBufferRef<'_>]) -> Result<DecryptionFlags>;

    /// Retrieves information about the bounds of sizes of authentication information of the current security principal.
    ///
    /// # Returns
    ///
    /// * `ContextSizes` upon success
    /// * `Error` on error
    ///
    /// # Example
    ///
    /// ```
    /// use sspi::Sspi;
    /// let mut ntlm = sspi::Ntlm::new();
    /// let sizes = ntlm.query_context_sizes().unwrap();
    /// println!("Max token: {}", sizes.max_token);
    /// println!("Max signature: {}", sizes.max_signature);
    /// println!("Block: {}", sizes.block);
    /// println!("Security trailer: {}", sizes.security_trailer);
    /// ```
    ///
    /// # MSDN
    ///
    /// * [QueryCredentialsAttributesW function](https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-querycredentialsattributesw)
    fn query_context_sizes(&mut self) -> Result<ContextSizes>;

    /// Retrieves the username of the credential associated to the context.
    ///
    /// # Returns
    ///
    /// * `ContextNames` upon success
    /// * `Error` on error
    ///
    /// # Example
    ///
    /// ```
    /// use sspi::Sspi;
    /// use sspi::Username;
    ///
    /// let mut ntlm = sspi::Ntlm::new();
    /// let identity = sspi::AuthIdentity {
    ///     username: Username::parse("user").unwrap(),
    ///     password: "password".to_string().into(),
    /// };
    ///
    /// let _acq_cred_result = ntlm
    ///     .acquire_credentials_handle()
    ///     .with_credential_use(sspi::CredentialUse::Inbound)
    ///     .with_auth_data(&identity)
    ///     .execute(&mut ntlm).unwrap();
    ///
    /// let names = ntlm.query_context_names().unwrap();
    /// println!("Username: {:?}", names.username.account_name());
    /// println!("Parts: {:?}", names.username.parts());
    /// ```
    ///
    /// # MSDN
    ///
    /// * [QuerySecurityPackageInfoW function](https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-querysecuritypackageinfow)
    fn query_context_names(&mut self) -> Result<ContextNames>;

    /// Queries the sizes of the various parts of a stream used in the per-message functions. This function is implemented only for CredSSP security package.
    ///
    /// # MSDN
    ///
    /// * [QuerySecurityPackageInfoW function (`ulAttribute` parameter)](https://learn.microsoft.com/en-us/windows/win32/secauthn/querycontextattributes--schannel)
    fn query_context_stream_sizes(&mut self) -> Result<StreamSizes> {
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "query_context_stream_sizes is not supported",
        ))
    }

    /// Retrieves information about the specified security package. This information includes the bounds of sizes of authentication information, credentials, and contexts.
    ///
    /// # Returns
    ///
    /// * `PackageInfo` containing the information about the package
    /// * `Error` on error
    ///
    /// # Example
    ///
    /// ```
    /// use sspi::Sspi;
    /// let mut ntlm = sspi::Ntlm::new();
    /// let info = ntlm.query_context_package_info().unwrap();
    /// println!("Package name: {:?}", info.name);
    /// ```
    ///
    /// # MSDN
    ///
    /// * [QuerySecurityPackageInfoW function](https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-querysecuritypackageinfow)
    fn query_context_package_info(&mut self) -> Result<PackageInfo>;

    /// Retrieves the trust information of the certificate.
    ///
    /// # Returns
    ///
    /// * `CertTrustStatus` on success
    ///
    /// # Example
    ///
    /// ```
    /// use sspi::Sspi;
    /// let mut ntlm = sspi::Ntlm::new();
    /// let cert_info = ntlm.query_context_package_info().unwrap();
    /// ```
    ///
    /// # MSDN
    ///
    /// * [QueryContextAttributes (CredSSP) function (`ulAttribute` parameter)](https://docs.microsoft.com/en-us/windows/win32/secauthn/querycontextattributes--credssp)
    fn query_context_cert_trust_status(&mut self) -> Result<CertTrustStatus>;

    /// Retrieves the information about the end certificate supplied by the server. This function is implemented only for CredSSP security package.
    ///
    /// # Returns
    ///
    /// * `CertContext` on success
    ///
    /// # MSDN
    ///
    /// * [QueryContextAttributes (CredSSP) function (`ulAttribute` parameter)](https://docs.microsoft.com/en-us/windows/win32/secauthn/querycontextattributes--credssp)
    fn query_context_remote_cert(&mut self) -> Result<CertContext> {
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "query_remote_cert_context is not supported",
        ))
    }

    /// Retrieves the information about the negotiated security package. This function is implemented only for CredSSP security package.
    ///
    /// # Returns
    ///
    /// * `PackageInfo` on success
    ///
    /// # MSDN
    ///
    /// * [QueryContextAttributes (CredSSP) function (`ulAttribute` parameter)](https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-querycontextattributesw)
    fn query_context_negotiation_package(&mut self) -> Result<PackageInfo> {
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "query_context_negotiation_package is not supported",
        ))
    }

    /// Returns detailed information on the established connection. This function is implemented only for CredSSP security package.
    ///
    /// # Returns
    ///
    /// * `ConnectionInfo` on success
    ///
    /// # MSDN
    ///
    /// * [QueryContextAttributes (CredSSP) function (`ulAttribute` parameter)](https://docs.microsoft.com/en-us/windows/win32/secauthn/querycontextattributes--credssp)
    fn query_context_connection_info(&mut self) -> Result<ConnectionInfo> {
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "query_context_connection_info is not supported",
        ))
    }

    /// Returns information about the session key used for the security context.
    ///
    /// # Returns
    ///
    /// * `SessionKeys` on success
    ///
    /// # MSDN
    ///
    /// * [QueryContextAttributes function (`ulAttribute` parameter)](https://docs.microsoft.com/en-us/windows/win32/secauthn/querycontextattributes--general)
    fn query_context_session_key(&self) -> Result<SessionKeys> {
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "query_context_session_key is not supported",
        ))
    }

    /// Changes the password for a Windows domain account.
    ///
    /// # Returns
    ///
    /// * `()` on success
    ///
    /// # Example
    ///
    /// ```ignore
    /// use sspi::{Sspi, ChangePasswordBuilder};
    /// let mut ntlm = sspi::Ntlm::new();
    /// let mut output = [];
    /// let cert_info = ntlm.query_context_package_info().unwrap();
    /// let change_password = ChangePasswordBuilder::new()
    ///     .with_domain_name("domain".into())
    ///     .with_account_name("username".into())
    ///     .with_old_password("old_password".into())
    ///     .with_old_password("new_password".into())
    ///     .with_output(&mut output)
    ///     .build()
    ///     .unwrap();
    /// ntlm.change_password(change_password).unwrap();
    /// ```
    ///
    /// # MSDN
    ///
    /// * [ChangeAccountPasswordW function](https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-changeaccountpasswordw)
    fn change_password<'a>(&'a mut self, change_password: ChangePassword<'a>) -> Result<GeneratorChangePassword<'a>>;
}

/// Protocol used to establish connection.
///
/// # MSDN
///
/// [SecPkgContext_ConnectionInfo (`dwProtocol` field)](https://learn.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-secpkgcontext_connectioninfo)
#[derive(Debug, Clone, Eq, PartialEq, FromPrimitive, ToPrimitive)]
pub enum ConnectionProtocol {
    SpProtTls1Client = 0x80,
    SpProtTls1Server = 0x40,
    SpProtSsl3Client = 0x20,
    SpProtSsl3Server = 0x10,
    SpProtTls1_1Client = 0x200,
    SpProtTls1_1Server = 0x100,
    SpProtTls1_2Client = 0x800,
    SpProtTls1_2Server = 0x400,
    SpProtTls1_3Client = 0x00002000,
    SpProtTls1_3Server = 0x00001000,
    SpProtPct1Client = 0x2,
    SpProtPct1Server = 0x1,
    SpProtSsl2Client = 0x8,
    SpProtSsl2Server = 0x4,
}

/// Algorithm identifier for the bulk encryption cipher used by the connection.
///
/// # MSDN
///
/// [SecPkgContext_ConnectionInfo (`aiCipher` field)](https://learn.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-secpkgcontext_connectioninfo)
#[derive(Debug, Clone, Eq, PartialEq, FromPrimitive, ToPrimitive)]
pub enum ConnectionCipher {
    Calg3des = 26115,
    CalgAes128 = 26126,
    CalgAes256 = 26128,
    CalgDes = 26113,
    CalgRc2 = 26114,
    CalgRc4 = 26625,
    NoEncryption = 0,
}

/// ALG_ID indicating the hash used for generating Message Authentication Codes (MACs).
///
/// # MSDN
///
/// [SecPkgContext_ConnectionInfo (`aiHash` field)](https://learn.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-secpkgcontext_connectioninfo)
#[derive(Debug, Clone, Eq, PartialEq, FromPrimitive, ToPrimitive)]
pub enum ConnectionHash {
    CalgMd5 = 32771,
    CalgSha = 32772,
}

/// ALG_ID indicating the key exchange algorithm used to generate the shared master secret.
///
/// # MSDN
///
/// [SecPkgContext_ConnectionInfo (`aiExch` field)](https://learn.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-secpkgcontext_connectioninfo)
#[derive(Debug, Clone, Eq, PartialEq, FromPrimitive, ToPrimitive)]
pub enum ConnectionKeyExchange {
    CalgRsaKeyx = 41984,
    CalgDhEphem = 43522,
}

/// Type of certificate encoding used.
///
/// # MSDN
///
/// [CERT_CONTEXT (`dwCertEncodingType` field)](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_context)
#[derive(Debug, Clone, Eq, PartialEq, FromPrimitive, ToPrimitive)]
pub enum CertEncodingType {
    Pkcs7AsnEncoding = 65536,
    X509AsnEncoding = 1,
}

/// The CERT_CONTEXT structure contains both the encoded and decoded representations of a certificate.
///
/// # MSDN
///
/// [CERT_CONTEXT](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_context)
#[derive(Debug, Clone, PartialEq)]
pub struct CertContext {
    pub encoding_type: CertEncodingType,
    pub raw_cert: Vec<u8>,
    pub cert: Certificate,
}

/// This structure contains protocol and cipher information.
///
/// # MSDN
///
/// [SecPkgContext_ConnectionInfo](https://learn.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-secpkgcontext_connectioninfo)
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ConnectionInfo {
    pub protocol: ConnectionProtocol,
    pub cipher: ConnectionCipher,
    pub cipher_strength: u32,
    pub hash: ConnectionHash,
    pub hash_strength: u32,
    pub key_exchange: ConnectionKeyExchange,
    pub exchange_strength: u32,
}

/// Trait for performing authentication on the client or server side
pub trait SspiImpl {
    /// Represents raw data for authentication
    type CredentialsHandle;
    /// Represents authentication data prepared for the authentication process
    type AuthenticationData;

    fn acquire_credentials_handle_impl(
        &mut self,
        builder: FilledAcquireCredentialsHandle<'_, Self::CredentialsHandle, Self::AuthenticationData>,
    ) -> Result<AcquireCredentialsHandleResult<Self::CredentialsHandle>>;

    fn initialize_security_context_impl<'ctx, 'b, 'g>(
        &'ctx mut self,
        builder: &'b mut FilledInitializeSecurityContext<'ctx, 'ctx, Self::CredentialsHandle>,
    ) -> Result<GeneratorInitSecurityContext<'g>>
    where
        'ctx: 'g,
        'b: 'g;

    fn accept_security_context_impl<'a>(
        &'a mut self,
        builder: FilledAcceptSecurityContext<'a, Self::CredentialsHandle>,
    ) -> Result<GeneratorAcceptSecurityContext<'a>>;
}

mod private {
    pub struct Sealed;
}

pub trait SspiEx
where
    Self: Sized + SspiImpl,
{
    fn custom_set_auth_identity(&mut self, identity: Self::AuthenticationData) -> Result<()>;

    /// Set multiple candidate credentials for server-side verification.
    ///
    /// During NTLM authentication, the server will try each candidate to find
    /// one whose password matches the client's challenge-response.
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
    /// The default implementation uses only the first credential.
    fn custom_set_auth_identities(&mut self, identities: Vec<Self::AuthenticationData>) -> Result<()> {
        match identities.into_iter().next() {
            Some(identity) => self.custom_set_auth_identity(identity),
            None => Err(Error::new(ErrorKind::NoCredentials, "no credentials provided")),
        }
    }

    /// Verifies a MIC (Message Integrity Code) token for the specified message data.
    ///
    /// This method is used only by the Negotiate security package (SPNEGO protocol implementation)
    /// to verify the `mechListMIC` token during the authentication process.
    fn verify_mic_token(&mut self, _token: &[u8], _data: &[u8], _: private::Sealed) -> Result<()> {
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "verify_mic_token is not supported",
        ))
    }

    /// Generates a MIC (Message Integrity Code) token for the specified message data.
    ///
    /// This method is used only by the Negotiate security package (SPNEGO protocol implementation)
    /// to generate `mechListMIC` token during the authentication process.
    fn generate_mic_token(&mut self, _token: &[u8], _: private::Sealed) -> Result<Vec<u8>> {
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "generate_mic_token is not supported",
        ))
    }
}

pub type SspiPackage<'a, CredsHandle, AuthData> =
    &'a mut dyn SspiImpl<CredentialsHandle = CredsHandle, AuthenticationData = AuthData>;

bitflags! {
    /// Indicate the quality of protection. Used in the `encrypt_message` method.
    ///
    /// # MSDN
    ///
    /// * [EncryptMessage function (`fQOP` parameter)](https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-encryptmessage)
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct EncryptionFlags: u32 {
        const WRAP_OOB_DATA = 0x4000_0000;
        const WRAP_NO_ENCRYPT = 0x8000_0001;
    }
}

bitflags! {
    /// Indicate the quality of protection. Returned by the `decrypt_message` method.
    ///
    /// # MSDN
    ///
    /// * [DecryptMessage function (`pfQOP` parameter)](https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-decryptmessage)
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct DecryptionFlags: u32 {
        const SIGN_ONLY = 0x8000_0000;
        const WRAP_NO_ENCRYPT = 0x8000_0001;
    }
}

bitflags! {
    /// Indicate requests for the context. Not all packages can support all requirements. Bit flags can be combined by using bitwise-OR operations.
    ///
    /// # MSDN
    ///
    /// * [Context Requirements](https://docs.microsoft.com/en-us/windows/win32/secauthn/context-requirements)
    /// * [InitializeSecurityContextW function (fContextReq parameter)](https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-initializesecuritycontextw)
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ClientRequestFlags: u32 {
        /// The server can use the context to authenticate to other servers as the client.
        /// The `MUTUAL_AUTH` flag must be set for this flag to work. Valid for Kerberos. Ignore this flag for constrained delegation.
        const DELEGATE = 0x1;
        /// The mutual authentication policy of the service will be satisfied.
        const MUTUAL_AUTH = 0x2;
        /// Detect replayed messages that have been encoded by using the `encrypt_message` or `make_signature` (TBI) functions.
        const REPLAY_DETECT = 0x4;
        /// Detect messages received out of sequence.
        const SEQUENCE_DETECT = 0x8;
        /// Encrypt messages by using the `encrypt_message` function.
        const CONFIDENTIALITY = 0x10;
        /// A new session key must be negotiated. This value is supported only by the Kerberos security package.
        const USE_SESSION_KEY = 0x20;
        const PROMPT_FOR_CREDS = 0x40;
        /// Schannel must not attempt to supply credentials for the client automatically.
        const USE_SUPPLIED_CREDS = 0x80;
        /// The security package allocates output buffers for you.
        const ALLOCATE_MEMORY = 0x100;
        const USE_DCE_STYLE = 0x200;
        const DATAGRAM = 0x400;
        /// The security context will not handle formatting messages. This value is the default for the Kerberos, Negotiate, and NTLM security packages.
        const CONNECTION = 0x800;
        const CALL_LEVEL = 0x1000;
        const FRAGMENT_SUPPLIED = 0x2000;
        /// When errors occur, the remote party will be notified.
        const EXTENDED_ERROR = 0x4000;
        /// Support a stream-oriented connection.
        const STREAM = 0x8000;
        /// Sign messages and verify signatures by using the `encrypt_message` and `make_signature` (TBI) functions.
        const INTEGRITY = 0x0001_0000;
        const IDENTIFY = 0x0002_0000;
        const NULL_SESSION = 0x0004_0000;
        /// Schannel must not authenticate the server automatically.
        const MANUAL_CRED_VALIDATION = 0x0008_0000;
        const RESERVED1 = 0x0010_0000;
        const FRAGMENT_TO_FIT = 0x0020_0000;
        const FORWARD_CREDENTIALS = 0x0040_0000;
        /// If this flag is set, the `Integrity` flag is ignored. This value is supported only by the Negotiate and Kerberos security packages.
        const NO_INTEGRITY = 0x0080_0000;
        const USE_HTTP_STYLE = 0x100_0000;
        const UNVERIFIED_TARGET_NAME = 0x2000_0000;
        const CONFIDENTIALITY_ONLY = 0x4000_0000;
    }
}

bitflags! {
    /// Specify the attributes required by the server to establish the context. Bit flags can be combined by using bitwise-OR operations.
    ///
    /// # MSDN
    ///
    /// * [Context Requirements](https://docs.microsoft.com/en-us/windows/win32/secauthn/context-requirements)
    /// * [AcceptSecurityContext function function (fContextReq parameter)](https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-acceptsecuritycontext?redirectedfrom=MSDN)
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ServerRequestFlags: u32 {
        /// The server is allowed to impersonate the client. Ignore this flag for [constrained delegation](https://docs.microsoft.com/windows/desktop/SecGloss/c-gly).
        const DELEGATE = 0x1;
        const MUTUAL_AUTH = 0x2;
        /// Detect replayed packets.
        const REPLAY_DETECT = 0x4;
        /// Detect messages received out of sequence.
        const SEQUENCE_DETECT = 0x8;
        const CONFIDENTIALITY = 0x10;
        const USE_SESSION_KEY = 0x20;
        const SESSION_TICKET = 0x40;
        /// Credential Security Support Provider (CredSSP) will allocate output buffers.
        const ALLOCATE_MEMORY = 0x100;
        const USE_DCE_STYLE = 0x200;
        const DATAGRAM = 0x400;
        /// The security context will not handle formatting messages.
        const CONNECTION = 0x800;
        const CALL_LEVEL = 0x1000;
        const FRAGMENT_SUPPLIED = 0x2000;
        /// When errors occur, the remote party will be notified.
        const EXTENDED_ERROR = 0x8000;
        /// Support a stream-oriented connection.
        const STREAM = 0x0001_0000;
        const INTEGRITY = 0x0002_0000;
        const LICENSING = 0x0004_0000;
        const IDENTIFY = 0x0008_0000;
        const ALLOW_NULL_SESSION = 0x0010_0000;
        const ALLOW_NON_USER_LOGONS = 0x0020_0000;
        const ALLOW_CONTEXT_REPLAY = 0x0040_0000;
        const FRAGMENT_TO_FIT = 0x80_0000;
        const NO_TOKEN = 0x100_0000;
        const PROXY_BINDINGS = 0x400_0000;
        const ALLOW_MISSING_BINDINGS = 0x1000_0000;
    }
}

bitflags! {
    /// Indicate the attributes of the established context.
    ///
    /// # MSDN
    ///
    /// * [Context Requirements](https://docs.microsoft.com/en-us/windows/win32/secauthn/context-requirements)
    /// * [InitializeSecurityContextW function (pfContextAttr parameter)](https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-initializesecuritycontextw)
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ClientResponseFlags: u32 {
        /// The server can use the context to authenticate to other servers as the client.
        /// The `MUTUAL_AUTH` flag must be set for this flag to work. Valid for Kerberos. Ignore this flag for constrained delegation.
        const DELEGATE = 0x1;
        /// The mutual authentication policy of the service will be satisfied.
        const MUTUAL_AUTH = 0x2;
        /// Detect replayed messages that have been encoded by using the `encrypt_message` or `make_signature` (TBI) functions.
        const REPLAY_DETECT = 0x4;
        /// Detect messages received out of sequence.
        const SEQUENCE_DETECT = 0x8;
        /// Encrypt messages by using the `encrypt_message` function.
        const CONFIDENTIALITY = 0x10;
        /// A new session key must be negotiated. This value is supported only by the Kerberos security package.
        const USE_SESSION_KEY = 0x20;
        const USED_COLLECTED_CREDS = 0x40;
        /// Schannel must not attempt to supply credentials for the client automatically.
        const USED_SUPPLIED_CREDS = 0x80;
        /// The security package allocates output buffers for you.
        const ALLOCATED_MEMORY = 0x100;
        const USED_DCE_STYLE = 0x200;
        const DATAGRAM = 0x400;
        /// The security context will not handle formatting messages. This value is the default for the Kerberos, Negotiate, and NTLM security packages.
        const CONNECTION = 0x800;
        const INTERMEDIATE_RETURN = 0x1000;
        const CALL_LEVEL = 0x2000;
        /// When errors occur, the remote party will be notified.
        const EXTENDED_ERROR = 0x4000;
        /// Support a stream-oriented connection.
        const STREAM = 0x8000;
        /// Sign messages and verify signatures by using the `encrypt_message` and `make_signature` (TBI) functions.
        const INTEGRITY = 0x0001_0000;
        const IDENTIFY = 0x0002_0000;
        const NULL_SESSION = 0x0004_0000;
        /// Schannel must not authenticate the server automatically.
        const MANUAL_CRED_VALIDATION = 0x0008_0000;
        const RESERVED1 = 0x10_0000;
        const FRAGMENT_ONLY = 0x0020_0000;
        const FORWARD_CREDENTIALS = 0x0040_0000;
        const USED_HTTP_STYLE = 0x100_0000;
        const NO_ADDITIONAL_TOKEN = 0x200_0000;
        const REAUTHENTICATION = 0x800_0000;
        const CONFIDENTIALITY_ONLY = 0x4000_0000;
    }
}

bitflags! {
    /// Indicate the attributes of the established context.
    ///
    /// # MSDN
    ///
    /// * [Context Requirements](https://docs.microsoft.com/en-us/windows/win32/secauthn/context-requirements)
    /// * [AcceptSecurityContext function function (pfContextAttr parameter)](https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-acceptsecuritycontext?redirectedfrom=MSDN)
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ServerResponseFlags: u32 {
        /// The server is allowed to impersonate the client. Ignore this flag for [constrained delegation](https://docs.microsoft.com/windows/desktop/SecGloss/c-gly).
        const DELEGATE = 0x1;
        const MUTUAL_AUTH = 0x2;
        /// Detect replayed packets.
        const REPLAY_DETECT = 0x4;
        /// Detect messages received out of sequence.
        const SEQUENCE_DETECT = 0x8;
        const CONFIDENTIALITY = 0x10;
        const USE_SESSION_KEY = 0x20;
        const SESSION_TICKET = 0x40;
        /// Credential Security Support Provider (CredSSP) will allocate output buffers.
        const ALLOCATED_MEMORY = 0x100;
        const USED_DCE_STYLE = 0x200;
        const DATAGRAM = 0x400;
        /// The security context will not handle formatting messages.
        const CONNECTION = 0x800;
        const CALL_LEVEL = 0x2000;
        const THIRD_LEG_FAILED = 0x4000;
        /// When errors occur, the remote party will be notified.
        const EXTENDED_ERROR = 0x8000;
        /// Support a stream-oriented connection.
        const STREAM = 0x0001_0000;
        const INTEGRITY = 0x0002_0000;
        const LICENSING = 0x0004_0000;
        const IDENTIFY = 0x0008_0000;
        const NULL_SESSION = 0x0010_0000;
        const ALLOW_NON_USER_LOGONS = 0x0020_0000;
        const ALLOW_CONTEXT_REPLAY = 0x0040_0000;
        const FRAGMENT_ONLY = 0x0080_0000;
        const NO_TOKEN = 0x100_0000;
        const NO_ADDITIONAL_TOKEN = 0x200_0000;
    }
}

/// The data representation, such as byte ordering, on the target.
///
/// # MSDN
///
/// * [AcceptSecurityContext function (TargetDataRep parameter)](https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-acceptsecuritycontext)
#[derive(Debug, Copy, Clone, Eq, PartialEq, FromPrimitive, ToPrimitive)]
pub enum DataRepresentation {
    Network = 0,
    Native = 0x10,
}

/// Describes a buffer allocated by a transport application to pass to a security package.
///
/// # MSDN
///
/// * [SecBuffer structure](https://docs.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secbuffer)
#[derive(Clone)]
pub struct SecurityBuffer {
    pub buffer: Vec<u8>,
    pub buffer_type: SecurityBufferType,
}

impl fmt::Debug for SecurityBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SecurityBufferRef {{ buffer_type: {:?}, buffer: 0x",
            self.buffer_type
        )?;
        self.buffer.iter().try_for_each(|byte| write!(f, "{byte:02X}"))?;
        write!(f, " }}")?;

        Ok(())
    }
}

impl SecurityBuffer {
    pub fn new(buffer: Vec<u8>, buffer_type: BufferType) -> Self {
        Self {
            buffer,
            buffer_type: SecurityBufferType {
                buffer_type,
                buffer_flags: SecurityBufferFlags::NONE,
            },
        }
    }

    pub fn find_buffer(buffers: &[SecurityBuffer], buffer_type: BufferType) -> Result<&SecurityBuffer> {
        buffers
            .iter()
            .find(|b| b.buffer_type.buffer_type == buffer_type)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidToken,
                    format!("no buffer was provided with type {buffer_type:?}"),
                )
            })
    }

    pub fn find_buffer_mut(buffers: &mut [SecurityBuffer], buffer_type: BufferType) -> Result<&mut SecurityBuffer> {
        buffers
            .iter_mut()
            .find(|b| b.buffer_type.buffer_type == buffer_type)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidToken,
                    format!("no buffer was provided with type {buffer_type:?}"),
                )
            })
    }
}

/// Bit flags that indicate the type of buffer.
///
/// # MSDN
///
/// * [SecBuffer structure (BufferType parameter)](https://docs.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secbuffer)
#[repr(u32)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Default, FromPrimitive, ToPrimitive)]
pub enum BufferType {
    #[default]
    Empty = 0,
    /// The buffer contains common data. The security package can read and write this data, for example, to encrypt some or all of it.
    Data = 1,
    /// The buffer contains the security token portion of the message. This is read-only for input parameters or read/write for output parameters.
    Token = 2,
    TransportToPackageParameters = 3,
    /// The security package uses this value to indicate the number of missing bytes in a particular message.
    Missing = 4,
    /// The security package uses this value to indicate the number of extra or unprocessed bytes in a message.
    Extra = 5,
    /// The buffer contains a protocol-specific trailer for a particular record. It is not usually of interest to callers.
    StreamTrailer = 6,
    /// The buffer contains a protocol-specific header for a particular record. It is not usually of interest to callers.
    StreamHeader = 7,
    NegotiationInfo = 8,
    Padding = 9,
    Stream = 10,
    ObjectIdsList = 11,
    ObjectIdsListSignature = 12,
    /// This flag is reserved. Do not use it.
    Target = 13,
    /// The buffer contains channel binding information.
    ChannelBindings = 14,
    /// The buffer contains a [DOMAIN_PASSWORD_INFORMATION](https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-domain_password_information) structure.
    ChangePasswordResponse = 15,
    /// The buffer specifies the [service principal name (SPN)](https://docs.microsoft.com/en-us/windows/win32/secgloss/s-gly) of the target.
    TargetHost = 16,
    /// The buffer contains an alert message.
    Alert = 17,
    /// The buffer contains a list of application protocol IDs, one list per application protocol negotiation extension type to be enabled.
    ApplicationProtocol = 18,
    /// The buffer contains a bitmask for a `ReadOnly` buffer.
    AttributeMark = 0xF000_0000,
    /// The buffer is read-only with no checksum. This flag is intended for sending header information to the security package for computing the checksum.
    /// The package can read this buffer, but cannot modify it.
    ReadOnly = 0x8000_0000,
    /// The buffer is read-only with a checksum.
    ReadOnlyWithChecksum = 0x1000_0000,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
    /// Security buffer flags.
    ///
    /// [`SecBuffer` structure (sspi.h)](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secbuffer).
    pub struct SecurityBufferFlags: u32 {
        /// There is no flags for the buffer.
        const NONE = 0x0;
        /// The buffer is read-only with no checksum. This flag is intended for sending header information to the security package for
        /// computing the checksum. The package can read this buffer, but cannot modify it.
        const SECBUFFER_READONLY = 0x80000000;
        /// The buffer is read-only with a checksum.
        const SECBUFFER_READONLY_WITH_CHECKSUM = 0x10000000;
    }
}

/// Security buffer type.
///
/// Contains the actual security buffer type and its flags.
#[derive(Clone, Copy, Eq, PartialEq, Default)]
pub struct SecurityBufferType {
    /// Security buffer type.
    pub buffer_type: BufferType,
    /// Security buffer flags.
    pub buffer_flags: SecurityBufferFlags,
}

impl SecurityBufferType {
    /// The buffer contains a bitmask for a `SECBUFFER_READONLY_WITH_CHECKSUM` buffer.
    ///
    /// [`SecBuffer` structure (sspi.h)](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secbuffer)
    pub const SECBUFFER_ATTRMASK: u32 = 0xf0000000;
}

impl TryFrom<u32> for SecurityBufferType {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        use num_traits::cast::FromPrimitive;

        let buffer_type = value & !Self::SECBUFFER_ATTRMASK;
        let buffer_type = BufferType::from_u32(buffer_type).ok_or_else(|| {
            Error::new(
                ErrorKind::InternalError,
                format!("u32({buffer_type}) to UnflaggedSecurityBuffer conversion error"),
            )
        })?;

        let buffer_flags = value & Self::SECBUFFER_ATTRMASK;
        let buffer_flags = SecurityBufferFlags::from_bits(buffer_flags).ok_or_else(|| {
            Error::new(
                ErrorKind::InternalError,
                format!("invalid SecurityBufferFlags: {buffer_flags}"),
            )
        })?;

        Ok(Self {
            buffer_type,
            buffer_flags,
        })
    }
}

impl From<SecurityBufferType> for u32 {
    fn from(value: SecurityBufferType) -> u32 {
        use num_traits::cast::ToPrimitive;

        value.buffer_type.to_u32().unwrap() | value.buffer_flags.bits()
    }
}

impl fmt::Debug for SecurityBufferType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("({:?}, {:?})", self.buffer_type, self.buffer_flags))
    }
}

/// A flag that indicates how the credentials are used.
///
/// # MSDN
///
/// * [AcquireCredentialsHandleW function (fCredentialUse parameter)](https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-acquirecredentialshandlew)
#[derive(Debug, Copy, Clone, Eq, PartialEq, FromPrimitive, ToPrimitive)]
pub enum CredentialUse {
    Inbound = 1,
    Outbound = 2,
    Both = 3,
    Default = 4,
}

/// Represents the security principal in use.
#[derive(Debug, Clone)]
pub enum SecurityPackageType {
    Ntlm,
    Kerberos,
    Negotiate,
    Pku2u,
    #[cfg(feature = "tsssp")]
    CredSsp,
    Other(String),
}

impl AsRef<str> for SecurityPackageType {
    fn as_ref(&self) -> &str {
        match self {
            SecurityPackageType::Ntlm => ntlm::PKG_NAME,
            SecurityPackageType::Kerberos => kerberos::PKG_NAME,
            SecurityPackageType::Negotiate => negotiate::PKG_NAME,
            SecurityPackageType::Pku2u => pku2u::PKG_NAME,
            #[cfg(feature = "tsssp")]
            SecurityPackageType::CredSsp => sspi_cred_ssp::PKG_NAME,
            SecurityPackageType::Other(name) => name.as_str(),
        }
    }
}

impl fmt::Display for SecurityPackageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityPackageType::Ntlm => write!(f, "{}", ntlm::PKG_NAME),
            SecurityPackageType::Kerberos => write!(f, "{}", kerberos::PKG_NAME),
            SecurityPackageType::Negotiate => write!(f, "{}", negotiate::PKG_NAME),
            SecurityPackageType::Pku2u => write!(f, "{}", pku2u::PKG_NAME),
            #[cfg(feature = "tsssp")]
            SecurityPackageType::CredSsp => write!(f, "{}", sspi_cred_ssp::PKG_NAME),
            SecurityPackageType::Other(name) => write!(f, "{name}"),
        }
    }
}

impl str::FromStr for SecurityPackageType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            ntlm::PKG_NAME => Ok(SecurityPackageType::Ntlm),
            kerberos::PKG_NAME => Ok(SecurityPackageType::Kerberos),
            negotiate::PKG_NAME => Ok(SecurityPackageType::Negotiate),
            pku2u::PKG_NAME => Ok(SecurityPackageType::Pku2u),
            #[cfg(feature = "tsssp")]
            sspi_cred_ssp::PKG_NAME => Ok(SecurityPackageType::CredSsp),
            s => Ok(SecurityPackageType::Other(s.to_string())),
        }
    }
}

/// General security principal information
///
/// Provides general information about a security package, such as its name and capabilities. Returned by `query_security_package_info`.
///
/// # MSDN
///
/// * [SecPkgInfoW structure](https://docs.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkginfow)
#[derive(Debug, Clone)]
pub struct PackageInfo {
    pub capabilities: PackageCapabilities,
    pub rpc_id: u16,
    pub max_token_len: u32,
    pub name: SecurityPackageType,
    pub comment: String,
}

bitflags! {
    /// Set of bit flags that describes the capabilities of the security package. It is possible to combine them.
    ///
    /// # MSDN
    ///
    /// * [SecPkgInfoW structure (`fCapabilities` parameter)](https://docs.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkginfow)
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct PackageCapabilities: u32 {
        /// The security package supports the `make_signature` (TBI) and `verify_signature` (TBI) functions.
        const INTEGRITY = 0x1;
        /// The security package supports the `encrypt_message` and `decrypt_message` functions.
        const PRIVACY = 0x2;
        /// The package is interested only in the security-token portion of messages, and will ignore any other buffers. This is a performance-related issue.
        const TOKEN_ONLY = 0x4;
        /// Supports [datagram](https://docs.microsoft.com/en-us/windows/win32/secgloss/d-gly)-style authentication.
        /// For more information, see [SSPI Context Semantics](https://docs.microsoft.com/en-us/windows/win32/secauthn/sspi-context-semantics).
        const DATAGRAM = 0x8;
        /// Supports connection-oriented style authentication. For more information, see [SSPI Context Semantics](https://docs.microsoft.com/en-us/windows/win32/secauthn/sspi-context-semantics).
        const CONNECTION = 0x10;
        /// Multiple legs are required for authentication.
        const MULTI_REQUIRED = 0x20;
        /// Server authentication support is not provided.
        const CLIENT_ONLY = 0x40;
        /// Supports extended error handling. For more information, see [Extended Error Information](https://docs.microsoft.com/en-us/windows/win32/secauthn/extended-error-information).
        const EXTENDED_ERROR = 0x80;
        /// Supports Windows impersonation in server contexts.
        const IMPERSONATION = 0x100;
        /// Understands Windows principal and target names.
        const ACCEPT_WIN32_NAME = 0x200;
        /// Supports stream semantics. For more information, see [SSPI Context Semantics](https://docs.microsoft.com/en-us/windows/win32/secauthn/sspi-context-semantics).
        const STREAM = 0x400;
        /// Can be used by the [Microsoft Negotiate](https://docs.microsoft.com/windows/desktop/SecAuthN/microsoft-negotiate) security package.
        const NEGOTIABLE = 0x800;
        /// Supports GSS compatibility.
        const GSS_COMPATIBLE = 0x1000;
        /// Supports [LsaLogonUser](https://docs.microsoft.com/windows/desktop/api/ntsecapi/nf-ntsecapi-lsalogonuser).
        const LOGON = 0x2000;
        /// Token buffers are in ASCII characters format.
        const ASCII_BUFFERS = 0x4000;
        /// Supports separating large tokens into smaller buffers so that applications can make repeated calls to
        /// `initialize_security_context` and `accept_security_context` with the smaller buffers to complete authentication.
        const FRAGMENT = 0x8000;
        /// Supports mutual authentication.
        const MUTUAL_AUTH = 0x1_0000;
        /// Supports delegation.
        const DELEGATION = 0x2_0000;
        /// The security package supports using a checksum instead of in-place encryption when calling the `encrypt_message` function.
        const READONLY_WITH_CHECKSUM = 0x4_0000;
        /// Supports callers with restricted tokens.
        const RESTRICTED_TOKENS = 0x8_0000;
        /// The security package extends the [Microsoft Negotiate](https://docs.microsoft.com/windows/desktop/SecAuthN/microsoft-negotiate) security package.
        /// There can be at most one package of this type.
        const NEGO_EXTENDER = 0x10_0000;
        /// This package is negotiated by the package of type `NEGO_EXTENDER`.
        const NEGOTIABLE2 = 0x20_0000;
        /// This package receives all calls from app container apps.
        const APP_CONTAINER_PASSTHROUGH = 0x40_0000;
        /// This package receives calls from app container apps if one of the following checks succeeds:
        /// * Caller has default credentials capability
        /// * The target is a proxy server
        /// * The caller has supplied credentials
        const APP_CONTAINER_CHECKS = 0x80_0000;
    }
}

/// Indicates the sizes of the various parts of a stream for use with the message support functions.
/// `query_context_stream_sizes` function returns this structure.
///
/// # MSDN
///
/// * [SecPkgContext_StreamSizes](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkgcontext_streamsizes)
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StreamSizes {
    pub header: u32,
    pub trailer: u32,
    pub max_message: u32,
    pub buffers: u32,
    pub block_size: u32,
}

/// Indicates the sizes of important structures used in the message support functions.
/// `query_context_sizes` function returns this structure.
///
/// # MSDN
///
/// * [SecPkgContext_Sizes structure](https://docs.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkgcontext_sizes)
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ContextSizes {
    pub max_token: u32,
    pub max_signature: u32,
    pub block: u32,
    pub security_trailer: u32,
}

/// Contains trust information about a certificate in a certificate chain,
/// summary trust information about a simple chain of certificates, or summary information about an array of simple chains.
/// `query_context_cert_trust_status` function returns this structure.
///
/// # MSDN
///
/// * [CERT_TRUST_STATUS structure](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_trust_status)
#[derive(Debug, Clone)]
pub struct CertTrustStatus {
    pub error_status: CertTrustErrorStatus,
    pub info_status: CertTrustInfoStatus,
}

bitflags! {
    /// Flags representing the error status codes used in `CertTrustStatus`.
    ///
    /// # MSDN
    ///
    /// * [CERT_TRUST_STATUS structure](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_trust_status)
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct CertTrustErrorStatus: u32 {
        /// No error found for this certificate or chain.
        const NO_ERROR = 0x0;
        /// This certificate or one of the certificates in the certificate chain is not time valid.
        const IS_NOT_TIME_VALID = 0x1;
        const IS_NOT_TIME_NESTED = 0x2;
        /// Trust for this certificate or one of the certificates in the certificate chain has been revoked.
        const IS_REVOKED = 0x4;
        /// The certificate or one of the certificates in the certificate chain does not have a valid signature.
        const IS_NOT_SIGNATURE_VALID = 0x8;
        /// The certificate or certificate chain is not valid for its proposed usage.
        const IS_NOT_VALID_FOR_USAGE = 0x10;
        /// The certificate or certificate chain is based on an untrusted root.
        const IS_UNTRUSTED_ROOT = 0x20;
        /// The revocation status of the certificate or one of the certificates in the certificate chain is unknown.
        const REVOCATION_STATUS_UNKNOWN = 0x40;
        /// One of the certificates in the chain was issued by a
        /// [`certification authority`](https://docs.microsoft.com/windows/desktop/SecGloss/c-gly)
        /// that the original certificate had certified.
        const IS_CYCLIC = 0x80;
        /// One of the certificates has an extension that is not valid.
        const INVALID_EXTENSION = 0x100;
        /// The certificate or one of the certificates in the certificate chain has a policy constraints extension,
        /// and one of the issued certificates has a disallowed policy mapping extension or does not have a
        /// required issuance policies extension.
        const INVALID_POLICY_CONSTRAINTS = 0x200;
        /// The certificate or one of the certificates in the certificate chain has a basic constraints extension,
        /// and either the certificate cannot be used to issue other certificates, or the chain path length has been exceeded.
        const INVALID_BASIC_CONSTRAINTS = 0x400;
        /// The certificate or one of the certificates in the certificate chain has a name constraints extension that is not valid.
        const INVALID_NAME_CONSTRAINTS = 0x800;
        /// The certificate or one of the certificates in the certificate chain has a name constraints extension that contains
        /// unsupported fields. The minimum and maximum fields are not supported.
        /// Thus minimum must always be zero and maximum must always be absent. Only UPN is supported for an Other Name.
        /// The following alternative name choices are not supported:
        /// * X400 Address
        /// * EDI Party Name
        /// * Registered Id
        const HAS_NOT_SUPPORTED_NAME_CONSTRAINT = 0x1000;
        /// The certificate or one of the certificates in the certificate chain has a name constraints extension and a name
        /// constraint is missing for one of the name choices in the end certificate.
        const HAS_NOT_DEFINED_NAME_CONSTRAINT = 0x2000;
        /// The certificate or one of the certificates in the certificate chain has a name constraints extension,
        /// and there is not a permitted name constraint for one of the name choices in the end certificate.
        const HAS_NOT_PERMITTED_NAME_CONSTRAINT = 0x4000;
        /// The certificate or one of the certificates in the certificate chain has a name constraints extension,
        /// and one of the name choices in the end certificate is explicitly excluded.
        const HAS_EXCLUDED_NAME_CONSTRAINT = 0x8000;
        /// The certificate chain is not complete.
        const IS_PARTIAL_CHAIN = 0x0001_0000;
        /// A [certificate trust list](https://docs.microsoft.com/windows/desktop/SecGloss/c-gly)
        /// (CTL) used to create this chain was not time valid.
        const CTL_IS_NOT_TIME_VALID = 0x0002_0000;
        /// A CTL used to create this chain did not have a valid signature.
        const CTL_IS_NOT_SIGNATURE_VALID = 0x0004_0000;
        /// A CTL used to create this chain is not valid for this usage.
        const CTL_IS_NOT_VALID_FOR_USAGE = 0x0008_0000;
        /// The revocation status of the certificate or one of the certificates in the certificate chain is either offline or stale.
        const IS_OFFLINE_REVOCATION = 0x100_0000;
        /// The end certificate does not have any resultant issuance policies, and one of the issuing
        /// [certification authority](https://docs.microsoft.com/windows/desktop/SecGloss/c-gly)
        /// certificates has a policy constraints extension requiring it.
        const NO_ISSUANCE_CHAIN_POLICY = 0x200_0000;
    }
}

bitflags! {
    /// Flags representing the info status codes used in `CertTrustStatus`.
    ///
    /// # MSDN
    ///
    /// * [CERT_TRUST_STATUS structure](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_trust_status)
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct CertTrustInfoStatus: u32 {
        /// An exact match issuer certificate has been found for this certificate. This status code applies to certificates only.
        const HAS_EXACT_MATCH_ISSUER = 0x1;
        /// A key match issuer certificate has been found for this certificate. This status code applies to certificates only.
        const HAS_KEY_MATCH_ISSUER = 0x2;
        /// A name match issuer certificate has been found for this certificate. This status code applies to certificates only.
        const HAS_NAME_MATCH_ISSUER = 0x4;
        /// This certificate is self-signed. This status code applies to certificates only.
        const IS_SELF_SIGNED = 0x8;
        const AUTO_UPDATE_CA_REVOCATION = 0x10;
        const AUTO_UPDATE_END_REVOCATION = 0x20;
        const NO_OCSP_FAILOVER_TO_CRL = 0x40;
        const IS_KEY_ROLLOVER = 0x80;
        /// The certificate or chain has a preferred issuer. This status code applies to certificates and chains.
        const HAS_PREFERRED_ISSUER = 0x100;
        /// An issuance chain policy exists. This status code applies to certificates and chains.
        const HAS_ISSUANCE_CHAIN_POLICY = 0x200;
        /// A valid name constraints for all namespaces, including UPN. This status code applies to certificates and chains.
        const HAS_VALID_NAME_CONSTRAINTS = 0x400;
        /// This certificate is peer trusted. This status code applies to certificates only.
        const IS_PEER_TRUSTED = 0x800;
        /// This certificate's [certificate revocation list](https://docs.microsoft.com/windows/desktop/SecGloss/c-gly)
        /// (CRL) validity has been extended. This status code applies to certificates only.
        const HAS_CRL_VALIDITY_EXTENDED = 0x1000;
        const IS_FROM_EXCLUSIVE_TRUST_STORE = 0x2000;
        const IS_CA_TRUSTED = 0x4000;
        const HAS_AUTO_UPDATE_WEAK_SIGNATURE = 0x8000;
        const SSL_HANDSHAKE_OCSP = 0x0004_0000;
        const SSL_TIME_VALID_OCSP = 0x0008_0000;
        const SSL_RECONNECT_OCSP = 0x0010_0000;
        const IS_COMPLEX_CHAIN = 0x0001_0000;
        const HAS_ALLOW_WEAK_SIGNATURE = 0x0002_0000;
        const SSL_TIME_VALID = 0x100_0000;
        const NO_TIME_CHECK = 0x200_0000;
    }
}

/// Indicates the name of the user associated with a security context.
/// `query_context_names` function returns this structure.
///
/// # MSDN
///
/// * [SecPkgContext_NamesW structure](https://docs.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkgcontext_namesw)
#[derive(Debug, Clone)]
pub struct ContextNames {
    pub username: Username,
}

/// Contains information about the session key used for the security context.
/// `query_context_session_key` function returns this structure.
///
/// # MSDN
///
/// * [SecPkgContext_SessionKey structure](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkgcontext_sessionkey)
#[derive(Debug, Clone)]
pub struct SessionKeys {
    pub session_key: Secret<Vec<u8>>,
}

/// The kind of an SSPI related error. Enables to specify an error based on its type.
///
/// [SSPI Status Codes](https://learn.microsoft.com/en-us/windows/win32/secauthn/sspi-status-codes).
#[repr(u32)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, FromPrimitive, ToPrimitive)]
pub enum ErrorKind {
    Unknown = 0,
    InsufficientMemory = 0x8009_0300,
    InvalidHandle = 0x8009_0301,
    UnsupportedFunction = 0x8009_0302,
    TargetUnknown = 0x8009_0303,
    /// May correspond to any internal error (I/O error, server error, etc.).
    InternalError = 0x8009_0304,
    SecurityPackageNotFound = 0x8009_0305,
    NotOwned = 0x8009_0306,
    CannotInstall = 0x8009_0307,
    /// Used in cases when supplied data is missing or invalid.
    InvalidToken = 0x8009_0308,
    CannotPack = 0x8009_0309,
    OperationNotSupported = 0x8009_030A,
    NoImpersonation = 0x8009_030B,
    LogonDenied = 0x8009_030C,
    UnknownCredentials = 0x8009_030D,
    NoCredentials = 0x8009_030E,
    /// Used in contexts of supplying invalid credentials.
    MessageAltered = 0x8009_030F,
    /// Used when a required NTLM state does not correspond to the current.
    OutOfSequence = 0x8009_0310,
    NoAuthenticatingAuthority = 0x8009_0311,
    BadPackageId = 0x8009_0316,
    ContextExpired = 0x8009_0317,
    IncompleteMessage = 0x8009_0318,
    IncompleteCredentials = 0x8009_0320,
    BufferTooSmall = 0x8009_0321,
    WrongPrincipalName = 0x8009_0322,
    TimeSkew = 0x8009_0324,
    UntrustedRoot = 0x8009_0325,
    IllegalMessage = 0x8009_0326,
    CertificateUnknown = 0x8009_0327,
    CertificateExpired = 0x8009_0328,
    EncryptFailure = 0x8009_0329,
    DecryptFailure = 0x8009_0330,
    AlgorithmMismatch = 0x8009_0331,
    SecurityQosFailed = 0x8009_0332,
    UnfinishedContextDeleted = 0x8009_0333,
    NoTgtReply = 0x8009_0334,
    NoIpAddress = 0x8009_0335,
    WrongCredentialHandle = 0x8009_0336,
    CryptoSystemInvalid = 0x8009_0337,
    MaxReferralsExceeded = 0x8009_0338,
    MustBeKdc = 0x8009_0339,
    StrongCryptoNotSupported = 0x8009_033A,
    TooManyPrincipals = 0x8009_033B,
    NoPaData = 0x8009_033C,
    PkInitNameMismatch = 0x8009_033D,
    SmartCardLogonRequired = 0x8009_033E,
    ShutdownInProgress = 0x8009_033F,
    KdcInvalidRequest = 0x8009_0340,
    KdcUnknownEType = 0x8009_0341,
    KdcUnknownEType2 = 0x8009_0342,
    UnsupportedPreAuth = 0x8009_0343,
    DelegationRequired = 0x8009_0345,
    BadBindings = 0x8009_0346,
    MultipleAccounts = 0x8009_0347,
    NoKerbKey = 0x8009_0348,
    CertWrongUsage = 0x8009_0349,
    DowngradeDetected = 0x8009_0350,
    SmartCardCertificateRevoked = 0x8009_0351,
    IssuingCAUntrusted = 0x8009_0352,
    RevocationOffline = 0x8009_0353,
    PkInitClientFailure = 0x8009_0354,
    SmartCardCertExpired = 0x8009_0355,
    NoS4uProtSupport = 0x8009_0356,
    CrossRealmDelegationFailure = 0x8009_0357,
    RevocationOfflineKdc = 0x8009_0358,
    IssuingCaUntrustedKdc = 0x8009_0359,
    KdcCertExpired = 0x8009_035A,
    KdcCertRevoked = 0x8009_035B,
    InvalidParameter = 0x8009_035D,
    DelegationPolicy = 0x8009_035E,
    PolicyNtlmOnly = 0x8009_035F,
    NoContext = 0x8009_0361,
    Pku2uCertFailure = 0x8009_0362,
    MutualAuthFailed = 0x8009_0363,
    OnlyHttpsAllowed = 0x8009_0365,
    ApplicationProtocolMismatch = 0x8009_0367,
}

/// Holds the `ErrorKind` and the description of the SSPI-related error.
#[derive(Debug, Clone)]
pub struct Error {
    pub error_type: ErrorKind,
    pub description: String,
    pub nstatus: Option<credssp::NStatusCode>,
}

/// The success status of SSPI-related operation.
#[derive(Debug, Copy, Clone, Eq, PartialEq, FromPrimitive, ToPrimitive)]
pub enum SecurityStatus {
    Ok = 0,
    ContinueNeeded = 0x0009_0312,
    CompleteNeeded = 0x0009_0313,
    CompleteAndContinue = 0x0009_0314,
    LocalLogon = 0x0009_0315,
    ContextExpired = 0x0009_0317,
    IncompleteCredentials = 0x0009_0320,
    Renegotiate = 0x0009_0321,
    NoLsaContext = 0x0009_0323,
}

impl Error {
    /// Allows to fill a new error easily, supplying it with a coherent description.
    pub fn new(error_type: ErrorKind, description: impl ToString) -> Self {
        Self {
            error_type,
            description: description.to_string(),
            nstatus: None,
        }
    }

    pub fn new_with_nstatus(
        error_type: ErrorKind,
        description: impl Into<String>,
        status_code: credssp::NStatusCode,
    ) -> Self {
        Self {
            error_type,
            description: description.into(),
            nstatus: Some(status_code),
        }
    }
}

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.error_type, self.description)?;

        if let Some(nstatus) = self.nstatus {
            write!(f, "; status is {nstatus}")?;
        }

        Ok(())
    }
}

impl From<auth_identity::UsernameError> for Error {
    fn from(value: auth_identity::UsernameError) -> Self {
        Error::new(ErrorKind::UnknownCredentials, value)
    }
}

impl From<rsa::Error> for Error {
    fn from(value: rsa::Error) -> Self {
        Error::new(
            ErrorKind::InternalError,
            format!("an unexpected RsaError happened: {value}"),
        )
    }
}

impl From<Asn1DerError> for Error {
    fn from(err: Asn1DerError) -> Self {
        Self::new(ErrorKind::InvalidToken, format!("ASN1 DER error: {err:?}"))
    }
}

impl From<KrbError> for Error {
    fn from(krb_error: KrbError) -> Self {
        let (error_kind, mut description) = map_keb_error_code_to_sspi_error(krb_error.0.error_code.0);

        // https://www.rfc-editor.org/rfc/rfc4120#section-5.9.1

        // This field contains additional text to help explain the error code
        // associated with the failed request
        if let Some(e_text) = krb_error.0.e_text.0 {
            description.push_str(&format!(". Additional error text: {:?}", e_text.0));
        }

        // This field contains additional data about the error for use by the
        // application to help it recover from or handle the error.
        if let Some(e_data) = krb_error.0.e_data.0 {
            description.push_str(&format!(". Additional error data: {:?}", e_data.0));
        }

        Error::new(error_kind, description)
    }
}

impl From<picky_krb::crypto::KerberosCryptoError> for Error {
    fn from(err: picky_krb::crypto::KerberosCryptoError) -> Self {
        use picky_krb::crypto::KerberosCryptoError;

        match err {
            KerberosCryptoError::KeyLength(actual, expected) => Self::new(
                ErrorKind::InvalidParameter,
                format!("invalid key length. actual: {actual}. expected: {expected}"),
            ),
            KerberosCryptoError::CipherLength(actual, expected) => Self::new(
                ErrorKind::InvalidParameter,
                format!("invalid cipher length. actual: {actual}. expected: {expected}"),
            ),
            KerberosCryptoError::AlgorithmIdentifier(identifier) => Self::new(
                ErrorKind::InvalidParameter,
                format!("unknown algorithm identifier: {identifier}"),
            ),
            KerberosCryptoError::IntegrityCheck => Self::new(ErrorKind::MessageAltered, err.to_string()),
            KerberosCryptoError::CipherError(description) => Self::new(ErrorKind::InvalidParameter, description),
            KerberosCryptoError::CipherPad(description) => {
                Self::new(ErrorKind::InvalidParameter, description.to_string())
            }
            KerberosCryptoError::CipherUnpad(description) => {
                Self::new(ErrorKind::InvalidParameter, description.to_string())
            }
            KerberosCryptoError::SeedBitLen(description) => Self::new(ErrorKind::InvalidParameter, description),
            KerberosCryptoError::AlgorithmIdentifierData(identifier) => Self::new(
                ErrorKind::InvalidParameter,
                format!("unknown algorithm identifier: {identifier:?}"),
            ),
            KerberosCryptoError::RandError(rand) => {
                Self::new(ErrorKind::InvalidParameter, format!("random error: {rand:?}"))
            }
            KerberosCryptoError::TooSmallBuffer(inout) => {
                Self::new(ErrorKind::InvalidParameter, format!("too small buffer: {inout:?}"))
            }
            KerberosCryptoError::ArrayTryFromSliceError(array) => Self::new(
                ErrorKind::InvalidParameter,
                format!("array try from slice error: {array:?}"),
            ),
        }
    }
}

impl From<picky_krb::crypto::diffie_hellman::DiffieHellmanError> for Error {
    fn from(error: picky_krb::crypto::diffie_hellman::DiffieHellmanError) -> Self {
        use picky_krb::crypto::diffie_hellman::DiffieHellmanError;

        match error {
            DiffieHellmanError::BitLen(description) => Self::new(ErrorKind::InternalError, description),
            error => Self::new(ErrorKind::InternalError, error.to_string()),
        }
    }
}

impl From<CharSetError> for Error {
    fn from(err: CharSetError) -> Self {
        Self::new(ErrorKind::InternalError, err.to_string())
    }
}

impl From<GssApiMessageError> for Error {
    fn from(err: GssApiMessageError) -> Self {
        match err {
            GssApiMessageError::IoError(err) => Self::from(err),
            GssApiMessageError::InvalidId(_, _) => Self::new(ErrorKind::InvalidToken, err.to_string()),
            GssApiMessageError::InvalidMicFiller(_) => Self::new(ErrorKind::InvalidToken, err.to_string()),
            GssApiMessageError::InvalidWrapFiller(_) => Self::new(ErrorKind::InvalidToken, err.to_string()),
            GssApiMessageError::Asn1Error(_) => Self::new(ErrorKind::InvalidToken, err.to_string()),
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::new(ErrorKind::InternalError, format!("IO error: {err:?}"))
    }
}

impl From<getrandom::Error> for Error {
    fn from(err: getrandom::Error) -> Self {
        Self::new(ErrorKind::InternalError, format!("rand error: {err:?}"))
    }
}

impl From<rand::rngs::SysError> for Error {
    fn from(err: rand::rngs::SysError) -> Self {
        Self::new(ErrorKind::InternalError, format!("rand error: {:?}", err))
    }
}

impl From<str::Utf8Error> for Error {
    fn from(err: str::Utf8Error) -> Self {
        Self::new(ErrorKind::InternalError, err)
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(err: string::FromUtf8Error) -> Self {
        Self::new(ErrorKind::InternalError, format!("UTF-8 error: {err:?}"))
    }
}

impl From<string::FromUtf16Error> for Error {
    fn from(err: string::FromUtf16Error) -> Self {
        Self::new(ErrorKind::InternalError, format!("UTF-16 error: {err:?}"))
    }
}

impl From<Error> for io::Error {
    fn from(err: Error) -> io::Error {
        io::Error::other(format!("{:?}: {}", err.error_type, err.description))
    }
}

impl From<std::num::TryFromIntError> for Error {
    fn from(_: std::num::TryFromIntError) -> Self {
        Self::new(ErrorKind::InternalError, "integer conversion error")
    }
}

impl<T> From<std::sync::PoisonError<T>> for Error {
    fn from(_: std::sync::PoisonError<T>) -> Self {
        Self::new(ErrorKind::InternalError, "can not lock SspiHandle mutex")
    }
}

impl From<picky::key::KeyError> for Error {
    fn from(err: picky::key::KeyError) -> Self {
        Self::new(ErrorKind::InternalError, format!("RSA key error: {err:?}"))
    }
}

#[cfg(feature = "scard")]
impl From<winscard::Error> for Error {
    fn from(value: winscard::Error) -> Self {
        Self::new(
            ErrorKind::InternalError,
            format!("Error while using a smart card: {value}"),
        )
    }
}

#[cfg(all(feature = "scard", not(target_arch = "wasm32")))]
impl From<cryptoki::error::Error> for Error {
    fn from(value: cryptoki::error::Error) -> Self {
        Self::new(
            ErrorKind::NoCredentials,
            format!("Error while using a smart card: {value}"),
        )
    }
}

impl From<widestring::error::Utf16Error> for Error {
    fn from(value: widestring::error::Utf16Error) -> Self {
        Self::new(ErrorKind::InvalidParameter, format!("UTF-16 error: {value}"))
    }
}

impl From<widestring::error::ContainsNul<u16>> for Error {
    fn from(value: widestring::error::ContainsNul<u16>) -> Self {
        Self::new(ErrorKind::InvalidParameter, format!("UTF-16 error: {value}"))
    }
}

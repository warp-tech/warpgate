use std::fmt::Debug;
use std::marker::PhantomData;

use time::OffsetDateTime;

use super::{Assigned, NotAssigned, ToAssign};
use crate::{CredentialUse, Luid, SspiPackage};

pub type EmptyAcquireCredentialsHandle<'a, C, A> = AcquireCredentialsHandle<'a, C, A, WithoutCredentialUse>;
pub type FilledAcquireCredentialsHandle<'a, C, A> = AcquireCredentialsHandle<'a, C, A, WithCredentialUse>;

/// Contains data returned by calling the `execute` method of
/// the `AcquireCredentialsHandleBuilder` structure. The builder is returned by calling
/// the `acquire_credentials_handle` method.
#[derive(Debug, Clone)]
pub struct AcquireCredentialsHandleResult<C> {
    pub credentials_handle: C,
    pub expiry: Option<OffsetDateTime>,
}

// we cannot replace it with the `From` trait implementation due to conflict with blanked impl in the std
impl<T> AcquireCredentialsHandleResult<T> {
    pub fn transform_credentials_handle<T2>(self, transformer: &dyn Fn(T) -> T2) -> AcquireCredentialsHandleResult<T2> {
        let Self {
            credentials_handle,
            expiry,
        } = self;
        AcquireCredentialsHandleResult {
            credentials_handle: transformer(credentials_handle),
            expiry,
        }
    }
}

/// A builder to execute one of the SSPI functions. Returned by the `acquire_credentials_handle` method.
///
/// # Requirements for execution
///
/// These methods are required to be called before calling the `execute` method
/// * [`with_credential_use`](struct.AcquireCredentialsHandle.html#method.with_credential_use)
pub struct AcquireCredentialsHandle<'a, CredsHandle, AuthData, CredentialUseSet>
where
    CredentialUseSet: ToAssign,
{
    pub(crate) phantom_cred_handle: PhantomData<CredsHandle>,
    pub(crate) phantom_cred_use_set: PhantomData<CredentialUseSet>,

    pub credential_use: CredentialUse,

    pub principal_name: Option<&'a str>,
    pub logon_id: Option<Luid>,
    pub auth_data: Option<&'a AuthData>,
}

impl<CredsHandle, AuthData, CredentialUseSet> Debug
    for AcquireCredentialsHandle<'_, CredsHandle, AuthData, CredentialUseSet>
where
    CredentialUseSet: ToAssign,
    AuthData: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcquireCredentialsHandle")
            .field("phantom_cred_handle", &self.phantom_cred_handle)
            .field("phantom_cred_use_set", &self.phantom_cred_use_set)
            .field("credential_use", &self.credential_use)
            .field("principal_name", &self.principal_name)
            .field("logon_id", &self.logon_id)
            .field("auth_data", &self.auth_data)
            .finish()
    }
}

impl<'a, CredsHandle, AuthData, CredentialUseSet> AcquireCredentialsHandle<'a, CredsHandle, AuthData, CredentialUseSet>
where
    CredentialUseSet: ToAssign,
{
    pub fn new() -> Self {
        Self {
            phantom_cred_handle: PhantomData,
            phantom_cred_use_set: PhantomData,

            principal_name: None,
            credential_use: CredentialUse::Inbound,
            logon_id: None,
            auth_data: None,
        }
    }

    /// Specifies a flag that indicates how these credentials will be used.
    pub fn with_credential_use(
        self,
        credential_use: CredentialUse,
    ) -> AcquireCredentialsHandle<'a, CredsHandle, AuthData, WithCredentialUse> {
        AcquireCredentialsHandle {
            phantom_cred_handle: PhantomData,
            phantom_cred_use_set: PhantomData,

            principal_name: self.principal_name,
            credential_use,
            logon_id: self.logon_id,
            auth_data: self.auth_data,
        }
    }

    /// Specifies a string that specifies the name of the principal whose credentials the handle will reference.
    pub fn with_principal_name(self, principal_name: &'a str) -> Self {
        Self {
            principal_name: Some(principal_name),
            ..self
        }
    }

    /// Specifies a LUID that identifies the user. This parameter is provided for file-system processes such as network
    /// redirectors.
    pub fn with_logon_id(self, logon_id: Luid) -> Self {
        Self {
            logon_id: Some(logon_id),
            ..self
        }
    }

    /// Specifies a reference to the structure that specifies authentication data for both Schannel and Negotiate packages.
    pub fn with_auth_data(self, auth_data: &'a AuthData) -> Self {
        Self {
            auth_data: Some(auth_data),
            ..self
        }
    }
}

impl<CredsHandle, AuthData, CredentialUseSet> Default
    for AcquireCredentialsHandle<'_, CredsHandle, AuthData, CredentialUseSet>
where
    CredentialUseSet: ToAssign,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<'b, CredsHandle, AuthData> FilledAcquireCredentialsHandle<'b, CredsHandle, AuthData> {
    /// Transforms the builder into new one with the other `AuthData` and `CredsHandle` types.
    /// Useful when we need to pass the builder into the security package with other `AuthData` and `CredsHandle` types.
    pub(crate) fn full_transform<NewCredsHandle, NewAuthData>(
        self,
        auth_data: Option<&'b NewAuthData>,
    ) -> FilledAcquireCredentialsHandle<'b, NewCredsHandle, NewAuthData> {
        AcquireCredentialsHandle {
            phantom_cred_handle: PhantomData,
            phantom_cred_use_set: PhantomData,

            principal_name: self.principal_name,
            credential_use: self.credential_use,
            logon_id: self.logon_id,
            auth_data,
        }
    }
}

impl<CredsHandle, AuthData> FilledAcquireCredentialsHandle<'_, CredsHandle, AuthData> {
    /// Executes the SSPI function that the builder represents.
    pub fn execute(
        self,
        inner: SspiPackage<'_, CredsHandle, AuthData>,
    ) -> crate::Result<AcquireCredentialsHandleResult<CredsHandle>> {
        inner.acquire_credentials_handle_impl(self)
    }
}

/// Simulates the presence of the `credential_use` value of the
/// `AcquireCredentialsHandle` builder.
#[derive(Debug)]
pub struct WithCredentialUse;
impl ToAssign for WithCredentialUse {}
impl Assigned for WithCredentialUse {}

/// Simulates the absence of the `credential_use` value of the
/// `AcquireCredentialsHandle` builder.
#[derive(Debug)]
pub struct WithoutCredentialUse;
impl ToAssign for WithoutCredentialUse {}
impl NotAssigned for WithoutCredentialUse {}

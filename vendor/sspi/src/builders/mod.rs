//! The builders are required to compose and execute some of the `Sspi` methods.

mod accept_sec_context;
mod acq_cred_handle;
mod change_password;
mod init_sec_context;

use std::fmt;

pub use self::accept_sec_context::{
    AcceptSecurityContext, AcceptSecurityContextResult, EmptyAcceptSecurityContext, FilledAcceptSecurityContext,
};
pub use self::acq_cred_handle::{
    AcquireCredentialsHandle, AcquireCredentialsHandleResult, EmptyAcquireCredentialsHandle,
    FilledAcquireCredentialsHandle, WithCredentialUse, WithoutCredentialUse,
};
pub use self::change_password::{ChangePassword, ChangePasswordBuilder};
pub use self::init_sec_context::{
    EmptyInitializeSecurityContext, FilledInitializeSecurityContext, InitializeSecurityContext,
    InitializeSecurityContextResult,
};

/// Allows to represent a value of a builder that is mandatory to be specified (during implementation
/// of the builder).
pub trait ToAssign: fmt::Debug {}
/// Allows to represent a mandatory value of a builder that is already specified (during implementation
/// of the builder).
pub trait Assigned: ToAssign {}
/// Allows to represent a mandatory value that is yet to be specified (during implementation
/// of the builder).
pub trait NotAssigned: ToAssign {}

/// Simulates the presence of a value
///
/// Simulates the presence of the `credentials_handle` value of the
/// `AcceptSecurityContext` and
/// `InitializeSecurityContext` builders.
#[derive(Debug)]
pub struct WithCredentialsHandle;
impl ToAssign for WithCredentialsHandle {}
impl Assigned for WithCredentialsHandle {}

/// Simulates the absence of a value
///
/// Simulates the absence of the `credentials_handle` value of the
/// `AcceptSecurityContext` and
/// `InitializeSecurityContext` builders.
#[derive(Debug)]
pub struct WithoutCredentialsHandle;
impl ToAssign for WithoutCredentialsHandle {}
impl NotAssigned for WithoutCredentialsHandle {}

/// Simulates the presence of a value
///
/// Simulates the presence of the `context_requirements` value of the
/// `AcceptSecurityContext` and
/// `InitializeSecurityContext` builders.
#[derive(Debug)]
pub struct WithContextRequirements;
impl ToAssign for WithContextRequirements {}
impl Assigned for WithContextRequirements {}

/// Simulates the absence of a value
///
/// Simulates the absence of the `context_requirements` value of the
/// `AcceptSecurityContext` and
/// `InitializeSecurityContext` builders.
#[derive(Debug)]
pub struct WithoutContextRequirements;
impl ToAssign for WithoutContextRequirements {}
impl NotAssigned for WithoutContextRequirements {}

/// Simulates the presence of a value
///
/// Simulates the presence of the `target_data_representation` value of the
/// `AcceptSecurityContext` and
/// `InitializeSecurityContext` builders.
#[derive(Debug)]
pub struct WithTargetDataRepresentation;
impl ToAssign for WithTargetDataRepresentation {}
impl Assigned for WithTargetDataRepresentation {}

/// Simulates the absence of a value
///
/// Simulates the absence of the `target_data_representation` value of the
/// `AcceptSecurityContext` and
/// `InitializeSecurityContext` builders.
#[derive(Debug)]
pub struct WithoutTargetDataRepresentation;
impl ToAssign for WithoutTargetDataRepresentation {}
impl NotAssigned for WithoutTargetDataRepresentation {}

/// Simulates the presence of a value
///
/// Simulates the presence of the `output` value of the
/// `AcceptSecurityContext` and
/// `InitializeSecurityContext` builders.
#[derive(Debug)]
pub struct WithOutput;
impl ToAssign for WithOutput {}
impl Assigned for WithOutput {}

/// Simulates the absence of a value
///
/// Simulates the absence of the `output` value of the
/// `AcceptSecurityContext` and
/// `InitializeSecurityContext` builders.
#[derive(Debug)]
pub struct WithoutOutput;
impl ToAssign for WithoutOutput {}
impl NotAssigned for WithoutOutput {}

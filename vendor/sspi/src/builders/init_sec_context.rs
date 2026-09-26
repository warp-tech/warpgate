use std::marker::PhantomData;
use std::mem;

use time::OffsetDateTime;

use super::{
    ToAssign, WithContextRequirements, WithCredentialsHandle, WithOutput, WithTargetDataRepresentation,
    WithoutContextRequirements, WithoutCredentialsHandle, WithoutOutput, WithoutTargetDataRepresentation,
};
use crate::{ClientRequestFlags, ClientResponseFlags, DataRepresentation, SecurityBuffer, SecurityStatus};

pub type EmptyInitializeSecurityContext<'a, 'output, C> = InitializeSecurityContext<
    'a,
    'output,
    C,
    WithoutCredentialsHandle,
    WithoutContextRequirements,
    WithoutTargetDataRepresentation,
    WithoutOutput,
>;
pub type FilledInitializeSecurityContext<'a, 'output, C> = InitializeSecurityContext<
    'a,
    'output,
    C,
    WithCredentialsHandle,
    WithContextRequirements,
    WithTargetDataRepresentation,
    WithOutput,
>;

/// Contains data returned by calling the `execute` method of
/// the `InitializeSecurityContextBuilder` structure. The builder is returned by calling
/// the `initialize_security_context` method.
#[derive(Debug, Clone)]
pub struct InitializeSecurityContextResult {
    pub status: SecurityStatus,
    pub flags: ClientResponseFlags,
    pub expiry: Option<OffsetDateTime>,
}

/// A builder to execute one of the SSPI functions. Returned by the `initialize_security_context` method.
///
/// # Requirements for execution
///
/// These methods are required to be called before calling the `execute` method
/// * [`with_credentials_handle`](struct.InitializeSecurityContext.html#method.with_credentials_handle)
/// * [`with_context_requirements`](struct.InitializeSecurityContext.html#method.with_context_requirements)
/// * [`with_target_data_representation`](struct.InitializeSecurityContext.html#method.with_target_data_representation)
/// * [`with_output`](struct.InitializeSecurityContext.html#method.with_output)
#[derive(Debug)]
pub struct InitializeSecurityContext<
    'a,
    'output,
    CredsHandle,
    CredsHandleSet,
    ContextRequirementsSet,
    TargetDataRepresentationSet,
    OutputSet,
> where
    CredsHandleSet: ToAssign,
    ContextRequirementsSet: ToAssign,
    TargetDataRepresentationSet: ToAssign,
    OutputSet: ToAssign,
{
    phantom_creds_use_set: PhantomData<CredsHandleSet>,
    phantom_context_req_set: PhantomData<ContextRequirementsSet>,
    phantom_data_repr_set: PhantomData<TargetDataRepresentationSet>,
    phantom_output_set: PhantomData<OutputSet>,

    pub credentials_handle: Option<&'a mut CredsHandle>,
    pub context_requirements: ClientRequestFlags,
    pub target_data_representation: DataRepresentation,
    pub output: &'output mut [SecurityBuffer],

    pub target_name: Option<&'a str>,
    pub input: Option<&'a mut [SecurityBuffer]>,
}

// We allow it here because the crate does not compile with single lifetime.
// The whole purpose of the `'a` lifetime is to allow the user to construct a new builder (via `full_transform` method)
// with a different lifetime for `credentials_handle` field.
#[allow(single_use_lifetimes)]
impl<
    'b,
    'a: 'b,
    'output,
    CredsHandle,
    CredsHandleSet: ToAssign,
    ContextRequirementsSet: ToAssign,
    TargetDataRepresentationSet: ToAssign,
    OutputSet: ToAssign,
>
    InitializeSecurityContext<
        'a,
        'output,
        CredsHandle,
        CredsHandleSet,
        ContextRequirementsSet,
        TargetDataRepresentationSet,
        OutputSet,
    >
{
    /// Creates a new builder with the other `AuthData` and `CredsHandle` types.
    ///
    /// References to the input and output buffers will be moved to the created builder leaving the `None` instead.
    pub fn full_transform<CredsHandle2, CredHandleSet2: ToAssign>(
        &mut self,
        credentials_handle: Option<&'b mut CredsHandle2>,
    ) -> InitializeSecurityContext<
        'b,
        'output,
        CredsHandle2,
        CredHandleSet2,
        ContextRequirementsSet,
        TargetDataRepresentationSet,
        OutputSet,
    > {
        InitializeSecurityContext {
            phantom_creds_use_set: PhantomData,
            phantom_context_req_set: PhantomData,
            phantom_data_repr_set: PhantomData,
            phantom_output_set: PhantomData,

            credentials_handle,
            context_requirements: self.context_requirements,
            target_data_representation: self.target_data_representation,
            output: mem::take(&mut self.output),
            target_name: self.target_name,
            input: mem::take(&mut self.input),
        }
    }
}

impl<
    'a,
    'output,
    CredsHandle,
    CredsHandleSet: ToAssign,
    ContextRequirementsSet: ToAssign,
    TargetDataRepresentationSet: ToAssign,
    OutputSet: ToAssign,
>
    InitializeSecurityContext<
        'a,
        'output,
        CredsHandle,
        CredsHandleSet,
        ContextRequirementsSet,
        TargetDataRepresentationSet,
        OutputSet,
    >
{
    pub fn credentials_handle_mut(&mut self) -> &mut Option<&'a mut CredsHandle> {
        &mut self.credentials_handle
    }

    pub fn credentials_handle(&mut self) -> &Option<&'a mut CredsHandle> {
        &self.credentials_handle
    }

    pub(crate) fn new() -> Self {
        Self {
            phantom_creds_use_set: PhantomData,
            phantom_context_req_set: PhantomData,
            phantom_data_repr_set: PhantomData,
            phantom_output_set: PhantomData,

            credentials_handle: None,
            context_requirements: ClientRequestFlags::empty(),
            target_data_representation: DataRepresentation::Network,
            output: &mut [],

            target_name: None,
            input: None,
        }
    }

    /// Specifies a handle to the credentials returned by `acquire_credentials_handle`. This handle is used
    /// to build the security context. The builder requires at least `CredentialUse::Outbound` credentials.
    pub fn with_credentials_handle(
        self,
        credentials_handle: &'a mut CredsHandle,
    ) -> InitializeSecurityContext<
        'a,
        'output,
        CredsHandle,
        WithCredentialsHandle,
        ContextRequirementsSet,
        TargetDataRepresentationSet,
        OutputSet,
    > {
        InitializeSecurityContext {
            phantom_creds_use_set: PhantomData,
            phantom_context_req_set: PhantomData,
            phantom_data_repr_set: PhantomData,
            phantom_output_set: PhantomData,

            credentials_handle: Some(credentials_handle),
            context_requirements: self.context_requirements,
            target_data_representation: self.target_data_representation,
            output: self.output,

            target_name: self.target_name,
            input: self.input,
        }
    }

    /// Specifies bit flags that indicate requests for the context. Not all packages can support all requirements.
    pub fn with_context_requirements(
        self,
        context_requirements: ClientRequestFlags,
    ) -> InitializeSecurityContext<
        'a,
        'output,
        CredsHandle,
        CredsHandleSet,
        WithContextRequirements,
        TargetDataRepresentationSet,
        OutputSet,
    > {
        InitializeSecurityContext {
            phantom_creds_use_set: PhantomData,
            phantom_context_req_set: PhantomData,
            phantom_data_repr_set: PhantomData,
            phantom_output_set: PhantomData,

            credentials_handle: self.credentials_handle,
            context_requirements,
            target_data_representation: self.target_data_representation,
            output: self.output,

            target_name: self.target_name,
            input: self.input,
        }
    }

    /// Specifies the data representation, such as byte ordering, on the target.
    pub fn with_target_data_representation(
        self,
        target_data_representation: DataRepresentation,
    ) -> InitializeSecurityContext<
        'a,
        'output,
        CredsHandle,
        CredsHandleSet,
        ContextRequirementsSet,
        WithTargetDataRepresentation,
        OutputSet,
    > {
        InitializeSecurityContext {
            phantom_creds_use_set: PhantomData,
            phantom_context_req_set: PhantomData,
            phantom_data_repr_set: PhantomData,
            phantom_output_set: PhantomData,

            credentials_handle: self.credentials_handle,
            context_requirements: self.context_requirements,
            target_data_representation,
            output: self.output,

            target_name: self.target_name,
            input: self.input,
        }
    }

    /// Specifies a mutable reference to a buffer with [SecurityBuffer] that receives the output data.
    pub fn with_output(
        self,
        output: &'output mut [SecurityBuffer],
    ) -> InitializeSecurityContext<
        'a,
        'output,
        CredsHandle,
        CredsHandleSet,
        ContextRequirementsSet,
        TargetDataRepresentationSet,
        WithOutput,
    > {
        InitializeSecurityContext {
            phantom_creds_use_set: PhantomData,
            phantom_context_req_set: PhantomData,
            phantom_data_repr_set: PhantomData,
            phantom_output_set: PhantomData,

            credentials_handle: self.credentials_handle,
            context_requirements: self.context_requirements,
            target_data_representation: self.target_data_representation,
            output,

            target_name: self.target_name,
            input: self.input,
        }
    }

    pub fn with_target_name(self, target_name: &'a str) -> Self {
        Self {
            target_name: Some(target_name),
            ..self
        }
    }

    /// Specifies a mutable reference to a buffer with [SecurityBuffer] structures. Don't call this method on during
    /// the first execution of the builder. On the second execution, this parameter is a reference to the partially
    /// formed context returned during the first call.
    pub fn with_input(self, input: &'a mut [SecurityBuffer]) -> Self {
        Self {
            input: Some(input),
            ..self
        }
    }
}

impl<
    CredsHandle,
    CredsHandleSet: ToAssign,
    ContextRequirementsSet: ToAssign,
    TargetDataRepresentationSet: ToAssign,
    OutputSet: ToAssign,
> Default
    for InitializeSecurityContext<
        '_,
        '_,
        CredsHandle,
        CredsHandleSet,
        ContextRequirementsSet,
        TargetDataRepresentationSet,
        OutputSet,
    >
{
    fn default() -> Self {
        Self::new()
    }
}

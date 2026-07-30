use std::marker::PhantomData;

use time::OffsetDateTime;

use super::{
    ToAssign, WithContextRequirements, WithCredentialsHandle, WithOutput, WithTargetDataRepresentation,
    WithoutContextRequirements, WithoutCredentialsHandle, WithoutOutput, WithoutTargetDataRepresentation,
};
use crate::generator::GeneratorAcceptSecurityContext;
use crate::{DataRepresentation, SecurityBuffer, SecurityStatus, ServerRequestFlags, ServerResponseFlags, SspiPackage};

pub type EmptyAcceptSecurityContext<'a, C> = AcceptSecurityContext<
    'a,
    C,
    WithoutCredentialsHandle,
    WithoutContextRequirements,
    WithoutTargetDataRepresentation,
    WithoutOutput,
>;
pub type FilledAcceptSecurityContext<'a, C> = AcceptSecurityContext<
    'a,
    C,
    WithCredentialsHandle,
    WithContextRequirements,
    WithTargetDataRepresentation,
    WithOutput,
>;

/// Contains data returned by calling the `execute` method of
/// the `AcceptSecurityContextBuilder` structure. The builder is returned by calling
/// the `accept_security_context` method.
#[derive(Debug, Clone)]
pub struct AcceptSecurityContextResult {
    pub status: SecurityStatus,
    pub flags: ServerResponseFlags,
    pub expiry: Option<OffsetDateTime>,
}

/// A builder to execute one of the SSPI functions. Returned by the `accept_security_context` method.
///
/// # Requirements for execution
///
/// These methods are required to be called before calling the `execute` method
/// * [`with_credentials_handle`](struct.AcceptSecurityContext.html#method.with_credentials_handle)
/// * [`with_context_requirements`](struct.AcceptSecurityContext.html#method.with_context_requirements)
/// * [`with_target_data_representation`](struct.AcceptSecurityContext.html#method.with_target_data_representation)
/// * [`with_output`](struct.AcceptSecurityContext.html#method.with_output)
pub struct AcceptSecurityContext<
    'a,
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
    pub context_requirements: ServerRequestFlags,
    pub target_data_representation: DataRepresentation,
    pub output: &'a mut [SecurityBuffer],

    pub input: Option<&'a mut [SecurityBuffer]>,
}

impl<
    'a,
    CredsHandle,
    CredsHandleSet: ToAssign,
    ContextRequirementsSet: ToAssign,
    TargetDataRepresentationSet: ToAssign,
    OutputSet: ToAssign,
>
    AcceptSecurityContext<
        'a,
        CredsHandle,
        CredsHandleSet,
        ContextRequirementsSet,
        TargetDataRepresentationSet,
        OutputSet,
    >
{
    pub(crate) fn new() -> Self {
        AcceptSecurityContext {
            phantom_creds_use_set: PhantomData,
            phantom_context_req_set: PhantomData,
            phantom_data_repr_set: PhantomData,
            phantom_output_set: PhantomData,

            credentials_handle: None,
            context_requirements: ServerRequestFlags::empty(),
            target_data_representation: DataRepresentation::Network,

            output: &mut [],
            input: None,
        }
    }

    /// Specifies the server credentials. To retrieve this handle, the server calls the `acquire_credentials_handle`
    /// method with either the `CredentialUse::Inbound` or `CredentialUse::Outbound` flag set.
    pub fn with_credentials_handle(
        self,
        credentials_handle: &'a mut CredsHandle,
    ) -> AcceptSecurityContext<
        'a,
        CredsHandle,
        WithCredentialsHandle,
        ContextRequirementsSet,
        TargetDataRepresentationSet,
        OutputSet,
    > {
        AcceptSecurityContext {
            phantom_creds_use_set: PhantomData,
            phantom_context_req_set: PhantomData,
            phantom_data_repr_set: PhantomData,
            phantom_output_set: PhantomData,

            credentials_handle: Some(credentials_handle),
            context_requirements: self.context_requirements,
            target_data_representation: self.target_data_representation,
            output: self.output,

            input: self.input,
        }
    }

    /// Specifies bit flags that specify the attributes required by the server to establish the context.
    pub fn with_context_requirements(
        self,
        context_requirements: ServerRequestFlags,
    ) -> AcceptSecurityContext<
        'a,
        CredsHandle,
        CredsHandleSet,
        WithContextRequirements,
        TargetDataRepresentationSet,
        OutputSet,
    > {
        AcceptSecurityContext {
            phantom_creds_use_set: PhantomData,
            phantom_context_req_set: PhantomData,
            phantom_data_repr_set: PhantomData,
            phantom_output_set: PhantomData,

            credentials_handle: self.credentials_handle,
            context_requirements,
            target_data_representation: self.target_data_representation,
            output: self.output,

            input: self.input,
        }
    }

    /// Specifies the data representation, such as byte ordering, on the target.
    pub fn with_target_data_representation(
        self,
        target_data_representation: DataRepresentation,
    ) -> AcceptSecurityContext<
        'a,
        CredsHandle,
        CredsHandleSet,
        ContextRequirementsSet,
        WithTargetDataRepresentation,
        OutputSet,
    > {
        AcceptSecurityContext {
            phantom_creds_use_set: PhantomData,
            phantom_context_req_set: PhantomData,
            phantom_data_repr_set: PhantomData,
            phantom_output_set: PhantomData,

            credentials_handle: self.credentials_handle,
            context_requirements: self.context_requirements,
            target_data_representation,
            output: self.output,

            input: self.input,
        }
    }

    /// Specifies a mutable reference to a buffer with [SecurityBuffer] that contains the output buffer descriptor.
    /// This buffer is sent to the client for input into additional calls to `initialize_security_context`. An output
    /// buffer may be generated even if the function returns `SecurityStatus::Ok`. Any buffer generated must be sent
    /// back to the client application.
    pub fn with_output(
        self,
        output: &'a mut [SecurityBuffer],
    ) -> AcceptSecurityContext<
        'a,
        CredsHandle,
        CredsHandleSet,
        ContextRequirementsSet,
        TargetDataRepresentationSet,
        WithOutput,
    > {
        AcceptSecurityContext {
            phantom_creds_use_set: PhantomData,
            phantom_context_req_set: PhantomData,
            phantom_data_repr_set: PhantomData,
            phantom_output_set: PhantomData,

            credentials_handle: self.credentials_handle,
            context_requirements: self.context_requirements,
            target_data_representation: self.target_data_representation,
            output,

            input: self.input,
        }
    }

    /// Specifies a mutable reference to an [SecurityBuffer] generated by a client call to `initialize_security_context`.
    /// The structure contains the input buffer descriptor.
    pub fn with_input(self, input: &'a mut [SecurityBuffer]) -> Self {
        Self {
            input: Some(input),
            ..self
        }
    }
}

impl<'b, CredsHandle> FilledAcceptSecurityContext<'b, CredsHandle> {
    /// Transforms the builder into new one with the other `AuthData` and `CredsHandle` types.
    /// Useful when we need to pass the builder into the security package with other `AuthData` and `CredsHandle` types.
    pub(crate) fn full_transform<CredsHandle2>(
        self,
        credentials_handle: Option<&'b mut CredsHandle2>,
    ) -> FilledAcceptSecurityContext<'b, CredsHandle2> {
        AcceptSecurityContext {
            phantom_creds_use_set: PhantomData,
            phantom_context_req_set: PhantomData,
            phantom_data_repr_set: PhantomData,
            phantom_output_set: PhantomData,

            credentials_handle,
            context_requirements: self.context_requirements,
            target_data_representation: self.target_data_representation,

            output: self.output,
            input: self.input,
        }
    }
}

impl<'a, CredsHandle> FilledAcceptSecurityContext<'a, CredsHandle> {
    /// Executes the SSPI function that the builder represents.
    pub fn execute<AuthData>(
        self,
        inner: SspiPackage<'a, CredsHandle, AuthData>,
    ) -> crate::Result<GeneratorAcceptSecurityContext<'a>> {
        inner.accept_security_context_impl(self)
    }
}

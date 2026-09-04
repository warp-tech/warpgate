use std::error::Error;

use aws_credential_types::provider::error::CredentialsError;
use aws_sigv4::http_request::SigningError;
use aws_sigv4::sign::v4::signing_params::BuildError;

#[derive(Debug)]
pub enum AwsResourceType {
    Ec2Instance,
    EksCluster,
    RdsInstance,
}

#[derive(thiserror::Error, Debug)]
pub enum AwsError {
    #[error("cannot determine region for {0}")]
    RegionUnknown(String),
    #[error("{0:?} resource not found: {1}")]
    ResourceNotFound(AwsResourceType, String),
    #[error("no AWS credentials available")]
    NoCredentials,
    #[error(
        "static AWS credentials (AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY without a session token) are disallowed; Vault authentication requires a temporary workload identity (instance profile, pod identity, or IRSA)"
    )]
    StaticCredentialsDisallowed,
    #[error("credentials: {0}")]
    Credentials(#[from] CredentialsError),

    #[error("signing parameters: {0}")]
    SigningParams(#[from] BuildError),
    #[error("signing: {0}")]
    Signing(#[from] SigningError),
    #[error("HTTP: {0}")]
    Http(#[from] http::Error),
    #[error(transparent)]
    Other(#[from] Box<dyn Error + Send + Sync>),
}

impl AwsError {
    pub fn sdk_error<E: Error + Send + Sync + 'static>(err: E) -> Self {
        Self::Other(Box::new(err))
    }

    pub fn client_message(&self) -> &'static str {
        match self {
            AwsError::NoCredentials => "No AWS credentials are available",
            // Its own message because the credentials exist and we refused
            // them: grouped with "none available", an operator who had set
            // static keys was sent looking for the thing they had already done.
            AwsError::StaticCredentialsDisallowed => {
                "Static AWS credentials are refused; Vault authentication needs a temporary workload identity"
            }
            AwsError::Credentials(_) => "AWS credential provider error",
            AwsError::SigningParams(_) | AwsError::Signing(_) | AwsError::Http(_) => {
                "AWS signing request failed"
            }
            // A region that could not be derived is configuration; a resource
            // that was not found is an id or a permission. Different places to
            // look, so different sentences.
            AwsError::RegionUnknown(_) => "The AWS region could not be determined",
            AwsError::ResourceNotFound(_, _) => "The AWS resource was not found",
            AwsError::Other(_) => "AWS integration error",
        }
    }
}

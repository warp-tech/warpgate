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
        AwsError::Other(Box::new(err))
    }
}

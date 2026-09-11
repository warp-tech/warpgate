use thiserror::Error;

#[derive(Debug, Error)]
pub enum AzureError {
    #[error("Azure SDK error: {0}")]
    Sdk(#[from] azure_core::Error),
    #[error("Azure configuration error: {0}")]
    Config(String),
}

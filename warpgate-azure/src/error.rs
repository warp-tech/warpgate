use thiserror::Error;

#[derive(Debug, Error)]
pub enum AzureError {
    #[error("Azure SDK error: {0}")]
    Sdk(#[from] azure_core::Error),
    #[error("Azure configuration error: {0}")]
    Config(String),
    /// A blob accepts at most 50 000 blocks. Reported rather than left to fail
    /// on commit, so the recording that outgrew the limit is named.
    #[error("recording {key} exceeds the {limit} block limit for one blob")]
    TooManyBlocks { key: String, limit: usize },
}

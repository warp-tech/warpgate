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
    /// The requested range starts at or past the end of the blob. Distinct from
    /// a transport failure because it answers HTTP 416 rather than 500, which
    /// is how a player learns it has reached the end of a recording.
    #[error("requested range is past the end of a {total} byte recording")]
    RangeNotSatisfiable { total: u64 },
}

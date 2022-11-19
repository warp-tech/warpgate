use std::error::Error;

use warpgate_common::WarpgateError;

#[derive(thiserror::Error, Debug)]
pub enum SshClientError {
    #[error("mpsc error")]
    MpscError,
    #[error("russh error: {0}")]
    Russh(#[from] russh::Error),
    #[error(transparent)]
    Warpgate(#[from] WarpgateError),
    #[error(transparent)]
    Other(Box<dyn Error + Send + Sync>),
}

impl SshClientError {
    pub fn other<E: Error + Send + Sync + 'static>(err: E) -> Self {
        Self::Other(Box::new(err))
    }
}

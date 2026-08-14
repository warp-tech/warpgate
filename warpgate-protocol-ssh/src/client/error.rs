use std::error::Error;

use warpgate_common::WarpgateError;

/// What a connected user may be shown for an error carried as `anyhow::Error`.
///
/// `RCEvent::Error` is typed `anyhow::Error`, so the concrete error has to be
/// recovered before it can be sanitised. Anything that does not downcast falls
/// back to a constant — the safe direction, and the only one available when the
/// type is unknown.
#[must_use]
pub fn client_error_message(error: &anyhow::Error) -> &'static str {
    error.downcast_ref::<SshClientError>().map_or(
        "Internal error in the target connection",
        SshClientError::client_message,
    )
}

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

    /// What a connected user may be shown.
    ///
    /// The same job `ConnectionError::client_message` does, and it exists for
    /// the same reason: `Warpgate` here is `#[error(transparent)]`, so
    /// `WarpgateError`'s own `Display` passes straight through — a database
    /// failure renders as `database error: {DbErr}` carrying SQL text, and an
    /// encryption-key mismatch names the configured key fingerprints.
    ///
    /// This error reaches a terminal through `RCEvent::Error`, which wrote
    /// `format!("Error: {e}")` directly and so went around the sanitiser
    /// entirely. One hardened path and one unhardened path to the same sink is
    /// not a boundary.
    pub const fn client_message(&self) -> &'static str {
        match self {
            Self::MpscError => "Internal connection error",
            Self::Russh(_) => "SSH protocol error",
            Self::Warpgate(_) | Self::Other(_) => "Internal error in the target connection",
        }
    }
}

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
    /// The same job `ConnectionError::client_message` does, and for the same
    /// reason: `Warpgate` here is `#[error(transparent)]`, so `WarpgateError`'s
    /// own `Display` would otherwise pass straight through — a database
    /// failure rendering as `database error: {DbErr}` carrying SQL text.
    ///
    /// This error reaches a terminal too, through `RCEvent::Error`, which wrote
    /// `format!("Error: {e}")` and so went around the sanitiser entirely. One
    /// hardened path and one unhardened path to the same sink is not a
    /// boundary.
    pub const fn client_message(&self) -> &'static str {
        match self {
            Self::MpscError => "Internal connection error",
            Self::Russh(_) => "SSH protocol error",
            Self::Warpgate(_) | Self::Other(_) => "Internal error in the target connection",
        }
    }
}

#[cfg(test)]
mod tests {
    use warpgate_common::WarpgateError;

    use super::{SshClientError, client_error_message};

    const LEAK: &str = "database error: SELECT secret FROM credentials";

    fn leaky() -> SshClientError {
        SshClientError::Warpgate(WarpgateError::Other(LEAK.into()))
    }

    #[test]
    fn a_terminal_never_sees_the_error_s_own_words() {
        // Asserted first: without it this test would keep passing if the
        // fixture stopped carrying the text, proving nothing about the
        // boundary.
        assert!(leaky().to_string().contains(LEAK));
        assert!(!leaky().client_message().contains("SELECT"));
    }

    #[test]
    fn sanitising_survives_a_context_wrapper() {
        // `RCEvent::Error` is typed `anyhow::Error`, and anything on the way
        // there may add context. The downcast has to walk the chain, or the
        // sanitiser silently degrades to the fallback for wrapped errors.
        let wrapped = anyhow::Error::from(leaky()).context("connecting to target");
        assert!(format!("{wrapped:?}").contains(LEAK));
        assert_eq!(
            client_error_message(&wrapped),
            "Internal error in the target connection"
        );
    }

    #[test]
    fn an_unrecognised_error_falls_back_rather_than_speaking() {
        let foreign = anyhow::anyhow!("{LEAK}");
        assert!(!client_error_message(&foreign).contains("SELECT"));
    }
}

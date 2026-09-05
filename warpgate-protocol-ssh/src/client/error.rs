use std::error::Error;

use warpgate_common::WarpgateError;

/// What a connected user may be shown for an error carried as `anyhow::Error`.
///
/// The concrete error has to be recovered before it can be sanitised;
/// anything that does not downcast falls back to a constant.
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
    /// `Warpgate` is `#[error(transparent)]`, so its `Display` would pass a
    /// database failure through as `database error: {DbErr}`, SQL included.
    /// This reaches a terminal as well as a browser, through `RCEvent::Error`.
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
        // Asserted first, or a fixture that stopped carrying the text
        // would make the rest of this prove nothing.
        assert!(leaky().to_string().contains(LEAK));
        assert!(!leaky().client_message().contains("SELECT"));
    }

    #[test]
    fn sanitising_survives_a_context_wrapper() {
        // Not the `leaky()` fixture: its `client_message()` is the same
        // string as the fallback, so an assertion on it could not tell a
        // downcast that walked the context chain from the degradation this
        // test exists to catch.
        let wrapped = anyhow::Error::from(SshClientError::MpscError).context("connecting");
        assert_eq!(client_error_message(&wrapped), "Internal connection error");

        // And the leak still does not cross once wrapped.
        let leaky_wrapped = anyhow::Error::from(leaky()).context("connecting to target");
        assert!(format!("{leaky_wrapped:?}").contains(LEAK));
        assert!(!client_error_message(&leaky_wrapped).contains("SELECT"));
    }

    #[test]
    fn an_unrecognised_error_falls_back_rather_than_speaking() {
        let foreign = anyhow::anyhow!("{LEAK}");
        assert!(!client_error_message(&foreign).contains("SELECT"));
    }
}

use std::error::Error;

use warpgate_common::{UserFacingReason, WarpgateError};

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

impl UserFacingReason for SshClientError {
    fn user_facing_reason(&self) -> String {
        match self {
            Self::MpscError => "Internal connection error".into(),
            Self::Russh(_) => "SSH protocol error".into(),
            Self::Warpgate(e) => e.user_facing_reason(),
            Self::Other(_) => "Internal error in the target connection".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use warpgate_common::{UserFacingReason, WarpgateError};

    use super::SshClientError;

    #[test]
    fn a_transparent_error_does_not_show_its_text() {
        let leaky = SshClientError::Warpgate(WarpgateError::Other(
            "database error: SELECT secret FROM credentials".into(),
        ));
        assert!(leaky.to_string().contains("SELECT"));
        assert!(!leaky.user_facing_reason().contains("SELECT"));

        let boxed = SshClientError::other(std::io::Error::other("SELECT secret"));
        assert!(!boxed.user_facing_reason().contains("SELECT"));
    }
}

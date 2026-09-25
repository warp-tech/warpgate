use tokio_util::sync::CancellationToken;
use warpgate_core::SessionHandle;

pub struct KubernetesSessionHandle {
    closed: CancellationToken,
}

impl KubernetesSessionHandle {
    /// Returns the handle together with the token it cancels on `close()`, so
    /// the correlator can race a session's in-flight requests against it --
    /// otherwise closing a correlated session (admin close, or a user's
    /// deletion) would only stop *new* requests from being admitted, not the
    /// potentially long-lived one already streaming.
    pub fn new() -> (Self, CancellationToken) {
        let closed = CancellationToken::new();
        (
            Self {
                closed: closed.clone(),
            },
            closed,
        )
    }
}

impl SessionHandle for KubernetesSessionHandle {
    fn close(&mut self) {
        self.closed.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_cancels_token() {
        let (mut handle, token) = KubernetesSessionHandle::new();
        assert!(!token.is_cancelled());
        handle.close();
        assert!(token.is_cancelled());
    }
}

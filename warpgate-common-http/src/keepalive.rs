use std::sync::Arc;

/// HTTP session remains "in use" for as long as the guard is held
///
/// Used for websockets
/// One strong Arc is provided as Data<> to every request that belongs to a session
#[derive(Clone)]
pub struct SessionKeepalive( Arc<()>);

impl SessionKeepalive {
    pub fn new(token: Arc<()>) -> Self {
        Self(token)
    }

    pub fn guard(&self) -> SessionKeepaliveGuard {
        SessionKeepaliveGuard(self.0.clone())
    }
}

#[must_use]
pub struct SessionKeepaliveGuard(#[allow(dead_code)] Arc<()>); // only its liveness matters, never its contents

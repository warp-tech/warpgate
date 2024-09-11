use poem::session::Session;
use tracing::info;

use crate::session::SessionStore;

pub fn logout(session: &Session, session_middleware: &mut SessionStore) {
    session_middleware.remove_session(session);
    session.clear();
    info!("Logged out");
}

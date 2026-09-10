use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use poem::session::Session;
use poem::web::RemoteAddr;
use poem::{FromRequest, Request};
use sea_orm::{DatabaseConnection, EntityTrait};
use tokio::sync::{Mutex, broadcast, mpsc};
use tracing::{error, info};
use uuid::Uuid;
use warpgate_common::{UserSessionId, WarpgateError};
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::{SessionAuthorization, SessionKeepalive};
use warpgate_core::{State, UserSessionStateInit, WarpgateServerHandle};
use warpgate_db_entities::{HttpSession, UserSession};

use crate::common::{PROTOCOL_NAME, SessionExt};
use crate::middleware::ticket::{TicketSessionKey, ticket_session_key};
use crate::session_handle::{HttpSessionHandle, SessionHandleCommand};

/// The node's view of one user session. Removing the entry fires its
/// `close_sender`, aborting the requests and websockets served through it, and
/// drops the last reference to `handle`, whose teardown detaches a
/// cookie-backed session and ends a node-owned (header-ticket) one. Anything
/// that stores a lasting clone of `handle` keeps that teardown from running.
struct SessionEntry {
    handle: Arc<Mutex<WarpgateServerHandle>>,
    close_sender: broadcast::Sender<()>,
    last_activity: Instant,
    keepalive: Weak<()>,
    /// Set for a [`TemporaryTicketSession`]: the key this entry is indexed
    /// under in `ticket_sessions`, so removing it clears the index too.
    ticket_key: Option<TicketSessionKey>,
}

fn is_session_expired(
    last_activity: Instant,
    keepalive: &Weak<()>,
    now: Instant,
    max_age: Duration,
) -> bool {
    now.duration_since(last_activity) > max_age && keepalive.strong_count() == 0
}

pub struct SessionStore {
    sessions: HashMap<UserSessionId, SessionEntry>,
    /// Lets consecutive header-ticket requests share one user session: they
    /// carry no cookie, so without this index every request would register a
    /// session (and a target session, and an audit event) of its own.
    ticket_sessions: HashMap<TicketSessionKey, UserSessionId>,
    this: Weak<Mutex<Self>>,
}

/// A server handle vetted against the request's own authorization: minted only
/// by [`SessionStore::handle_for_request`], after the user check every branch
/// runs. Request-serving code takes this instead of a bare handle, so a new
/// code path cannot skip the check.
pub struct UserBoundHandle(Arc<Mutex<WarpgateServerHandle>>);

impl std::ops::Deref for UserBoundHandle {
    type Target = Arc<Mutex<WarpgateServerHandle>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// The user the request's browser session is authorized as, if any.
fn request_auth_user_id(session: &Session) -> Option<Uuid> {
    match session.get_auth() {
        Some(SessionAuthorization::User { user_id, .. })
        | Some(SessionAuthorization::Ticket { user_id, .. }) => Some(user_id),
        None => None,
    }
}

pub const SESSION_ID_SESSION_KEY: &str = HttpSession::SESSION_ID_DATA_KEY;

impl SessionStore {
    pub fn new() -> Arc<Mutex<Self>> {
        Arc::new_cyclic(|me| {
            Mutex::new(Self {
                sessions: HashMap::new(),
                ticket_sessions: HashMap::new(),
                this: me.clone(),
            })
        })
    }

    pub async fn process_request(&mut self, mut req: Request) -> poem::Result<Request> {
        let session = <&Session>::from_request_without_body(&req).await?;
        crate::session_storage::mark_session_active(session);

        if let Some(session_id) = session.get_session_id() {
            if let Some(entry) = self.sessions.get_mut(&session_id) {
                entry.last_activity = Instant::now();
            }
            req.set_data(SessionKeepalive::new(self.keepalive(session_id)));
        }

        Ok(req)
    }

    /// The server handle for this request's browser session: the live local
    /// one, a re-attached view over the still-open session the cookie already
    /// references (created on another node, or detached here), or a fresh
    /// registration when the cookie references none. The one refusal is a
    /// cookie referencing a session attributed to a different user — checked
    /// here for every branch, which is what the returned [`UserBoundHandle`]
    /// attests.
    pub async fn handle_for_request(
        &mut self,
        req: &Request,
        ctx: &UnauthenticatedRequestContext,
    ) -> poem::Result<UserBoundHandle> {
        let session = <&Session>::from_request_without_body(req).await?;

        // A header-borne ticket has no cookie to resolve, so it is recognised
        // by the ticket it presents instead — otherwise every request would
        // register a session of its own.
        if let Some(key) = ticket_session_key(req, session) {
            if let Some(entry) = self
                .ticket_sessions
                .get(&key)
                .copied()
                .and_then(|id| self.sessions.get_mut(&id))
            {
                entry.last_activity = Instant::now();
                return Ok(UserBoundHandle(entry.handle.clone()));
            }
            return Ok(UserBoundHandle(self.create_handle_for(req, ctx).await?));
        }

        if let Some(handle) = self.handle_for(session) {
            // An adopted view's user is stamped lazily, so an unattributed
            // handle passes; once attributed, it is handed out only to its
            // user — the live-entry equivalent of `adopt_handle_for`'s check.
            let state_user_id = handle
                .lock()
                .await
                .user_session_state()
                .lock()
                .await
                .user_info
                .as_ref()
                .map(|user| user.id);
            if state_user_id.is_some() && state_user_id != request_auth_user_id(session) {
                return Err(poem::Error::from_status(
                    poem::http::StatusCode::UNAUTHORIZED,
                ));
            }
            return Ok(UserBoundHandle(handle));
        }
        if let Some(id) = session.get_session_id() {
            if let Some(handle) = self.adopt_handle_for(req, ctx, id).await? {
                return Ok(UserBoundHandle(handle));
            }
            // The cookie names a session that is gone or ended. If it also
            // carries an authorization, that authorization was issued under
            // the ended session: deleting the stored browser sessions is what
            // makes an administrative close cluster-wide, but a request
            // already in flight when that happened writes its copy back
            // afterwards, so a revoked cookie can outlive the close.
            // Registering a replacement session would hand it a fresh login
            // and undo the close, so the browser session is dropped instead
            // and the caller has to authenticate again.
            if request_auth_user_id(session).is_some() {
                session.purge();
                return Err(poem::Error::from_status(
                    poem::http::StatusCode::UNAUTHORIZED,
                ));
            }
            // Unauthenticated, so there is no authority to carry over and
            // nothing to undo — the id is a leftover (its session reaped while
            // the cookie lived on) and this is someone arriving to log in.
        }
        Ok(UserBoundHandle(self.create_handle_for(req, ctx).await?))
    }

    async fn create_handle_for(
        &mut self,
        req: &Request,
        ctx: &UnauthenticatedRequestContext,
    ) -> poem::Result<Arc<Mutex<WarpgateServerHandle>>> {
        let session = <&Session>::from_request_without_body(req).await?;

        let (session_handle, session_handle_rx) = HttpSessionHandle::new();
        let init = Self::state_init_for(req, session_handle).await?;
        // A header-ticket session is held open by this node's entry alone: it
        // has no stored browser session, so the orphan sweep would end it
        // while it is still serving. Its lifetime is this node's, and it
        // registers as such.
        let server_handle = if ticket_session_key(req, session).is_some() {
            State::register_node_local_user_session(&ctx.services().state, PROTOCOL_NAME, init)
                .await?
        } else {
            State::register_nonlocal_user_session(&ctx.services().state, PROTOCOL_NAME, init)
                .await?
        };

        let id = server_handle.lock().await.user_session_id();
        session.set(SESSION_ID_SESSION_KEY, id);
        self.install_entry(req, ctx, id, server_handle.clone(), session_handle_rx)?;
        Ok(server_handle)
    }

    /// A node-local handle over a still-open user session this node has no
    /// live entry for: the parent row is validated once here. `None` means the
    /// row is gone, ended or not an HTTP session — nothing to re-attach to.
    /// Per-request liveness comes from the cookie-session storage row, which a
    /// close deletes cluster-wide.
    async fn adopt_handle_for(
        &mut self,
        req: &Request,
        ctx: &UnauthenticatedRequestContext,
        id: UserSessionId,
    ) -> poem::Result<Option<Arc<Mutex<WarpgateServerHandle>>>> {
        if let Some(entry) = self.sessions.get(&id) {
            return Ok(Some(entry.handle.clone()));
        }

        let session = <&Session>::from_request_without_body(req).await?;
        let Some(row) = warpgate_db_entities::UserSession::Entity::find_by_id(id)
            .one(&ctx.services().db)
            .await
            .map_err(WarpgateError::from)?
            // `node_id` must be NULL: a node-owned (ticket) session lives and
            // dies with its node and is never re-attached to from a cookie —
            // the query enforces it rather than the absence of such a cookie.
            .filter(|row| {
                row.ended.is_none()
                    && row.node_id.is_none()
                    && row.protocol == PROTOCOL_NAME.to_string()
            })
        else {
            return Ok(None);
        };
        if row.user_id != request_auth_user_id(session) {
            return Err(poem::Error::from_status(
                poem::http::StatusCode::UNAUTHORIZED,
            ));
        }

        let (session_handle, session_handle_rx) = HttpSessionHandle::new();
        let server_handle = State::adopt_user_session(
            &ctx.services().state,
            id,
            PROTOCOL_NAME,
            Self::state_init_for(req, session_handle).await?,
        )
        .await;
        self.install_entry(req, ctx, id, server_handle.clone(), session_handle_rx)?;
        Ok(Some(server_handle))
    }

    async fn state_init_for(
        req: &Request,
        session_handle: HttpSessionHandle,
    ) -> poem::Result<UserSessionStateInit> {
        let remote_address = <&RemoteAddr>::from_request_without_body(req).await?;
        Ok(UserSessionStateInit {
            remote_address: remote_address.0.as_socket_addr().copied(),
            handle: Box::new(session_handle),
        })
    }

    fn install_entry(
        &mut self,
        req: &Request,
        ctx: &UnauthenticatedRequestContext,
        id: UserSessionId,
        server_handle: Arc<Mutex<WarpgateServerHandle>>,
        session_handle_rx: mpsc::UnboundedReceiver<SessionHandleCommand>,
    ) -> poem::Result<()> {
        let ticket_key = req
            .extensions()
            .get::<Session>()
            .and_then(|session| ticket_session_key(req, session));

        let (session_close_sender, _) = broadcast::channel(1);
        self.sessions.insert(
            id,
            SessionEntry {
                handle: server_handle,
                close_sender: session_close_sender,
                last_activity: Instant::now(),
                keepalive: Weak::new(),
                ticket_key,
            },
        );
        if let Some(key) = ticket_key {
            self.ticket_sessions.insert(key, id);
        }

        let Some(this) = self.this.upgrade() else {
            return Err(anyhow::anyhow!("Invalid session state").into());
        };
        self.spawn_close_listener(this, ctx.services().db.clone(), id, session_handle_rx);
        Ok(())
    }

    fn spawn_close_listener(
        &self,
        this: Arc<Mutex<Self>>,
        db: DatabaseConnection,
        id: UserSessionId,
        mut session_handle_rx: mpsc::UnboundedReceiver<SessionHandleCommand>,
    ) {
        tokio::spawn(async move {
            while let Some(command) = session_handle_rx.recv().await {
                match command {
                    SessionHandleCommand::Close => {
                        // A cluster-wide logout, not just a local detach: the
                        // stored browser sessions are what keep the login
                        // valid on every node.
                        if let Err(error) = UserSession::revoke(&db, id).await {
                            error!(%id, %error, "Could not revoke the closed HTTP session");
                        }
                        info!(%id, "Removed HTTP session");
                        this.lock().await.remove_session_by_id(id);
                    }
                }
            }
        });
    }

    pub fn handle_for(&self, session: &Session) -> Option<Arc<Mutex<WarpgateServerHandle>>> {
        session
            .get_session_id()
            .and_then(|id| self.sessions.get(&id))
            .map(|entry| entry.handle.clone())
    }

    /// The login's close signal: fires when the session is removed from this
    /// node — an admin close, a logout, or expiry — aborting whatever is
    /// served through it. `None` only for a session this node holds no entry
    /// for.
    pub fn close_receiver_by_id(&self, id: UserSessionId) -> Option<broadcast::Receiver<()>> {
        self.sessions
            .get(&id)
            .map(|entry| entry.close_sender.subscribe())
    }

    /// Get a token that prevents the session from getting cleaned up
    /// until it's dropped. For an unknown (already removed) session id the
    /// token is returned unstored — there is nothing left to keep alive.
    fn keepalive(&mut self, id: UserSessionId) -> Arc<()> {
        let Some(entry) = self.sessions.get_mut(&id) else {
            return Arc::new(());
        };
        if let Some(token) = entry.keepalive.upgrade() {
            return token;
        }
        let token = Arc::new(());
        entry.keepalive = Arc::downgrade(&token);
        token
    }

    pub fn remove_session(&mut self, session: &Session) {
        if let Some(id) = session.get_session_id() {
            self.remove_session_by_id(id);
        }
    }

    /// Expires idle local entries. Removing an entry drops the last handle
    /// reference, and what that does is the session's own business: a
    /// connection-bound session (a header ticket's) ends, while a cookie-backed
    /// one is only detached, since another node may still be serving it and
    /// shared storage GC is the authority for global idle expiration.
    pub fn vacuum(&mut self, session_max_age: Duration) {
        let now = Instant::now();
        let to_remove: Vec<UserSessionId> = self
            .sessions
            .iter()
            .filter(|(_, entry)| {
                // A handle a request still holds is in use even if the entry
                // looks idle: a header-ticket request registers no keepalive,
                // since the token is attached before its session exists.
                Arc::strong_count(&entry.handle) == 1
                    && is_session_expired(
                        entry.last_activity,
                        &entry.keepalive,
                        now,
                        session_max_age,
                    )
            })
            .map(|(id, _)| *id)
            .collect();
        for id in to_remove {
            info!(%id, "Expiring idle local HTTP session handle");
            self.remove_session_by_id(id);
        }
    }

    /// The sessions this node is actively serving, so their stored browser
    /// sessions can be kept from ageing out under a long-lived connection.
    pub fn live_session_ids(&self) -> Vec<UserSessionId> {
        self.sessions
            .iter()
            .filter(|(_, entry)| {
                entry.keepalive.strong_count() > 0 || Arc::strong_count(&entry.handle) > 1
            })
            .map(|(id, _)| *id)
            .collect()
    }

    /// Detaches the parent's local handle. Its target sessions are owned by
    /// the parent state and drop with it, which is what aborts the requests
    /// served through them.
    fn remove_session_by_id(&mut self, id: UserSessionId) {
        if let Some(entry) = self.sessions.remove(&id) {
            // Only if it still points here: the key may already have been
            // re-registered by a later request.
            if let Some(key) = entry.ticket_key
                && self.ticket_sessions.get(&key) == Some(&id)
            {
                self.ticket_sessions.remove(&key);
            }
            let _ = entry.close_sender.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_session_expires() {
        let now = Instant::now();
        let stale = now - Duration::from_secs(60);
        assert!(is_session_expired(
            stale,
            &Weak::new(),
            now,
            Duration::from_secs(1)
        ));
        assert!(!is_session_expired(
            now,
            &Weak::new(),
            now,
            Duration::from_secs(1)
        ));
    }

    #[test]
    fn live_connection_spares_session() {
        let now = Instant::now();
        let stale = now - Duration::from_secs(60);

        let token = Arc::new(());
        let keepalive = Arc::downgrade(&token);
        assert!(!is_session_expired(
            stale,
            &keepalive,
            now,
            Duration::from_secs(1)
        ));

        drop(token);
        assert!(is_session_expired(
            stale,
            &keepalive,
            now,
            Duration::from_secs(1)
        ));
    }
}

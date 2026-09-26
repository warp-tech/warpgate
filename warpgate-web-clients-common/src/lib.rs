//! Shared plumbing for Warpgate's browser client crates (`warpgate-web-ssh`,
//! `warpgate-web-desktop`). Both proxy a backend protocol to a WebSocket and need the
//! same machinery: a buffered outbound queue that survives brief reconnects, a
//! liveness flag, a disconnect grace timer, and an in-memory registry of live sessions.
//!
//! Only the message type and the protocol-specific `create_session`/event-loop differ,
//! so those live in each crate; everything here is generic over the message type `M`.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::futures::Notified;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;
use uuid::Uuid;
use warpgate_common::auth::RememberApprovalBy;
use warpgate_common::{UserSessionId, WarpgateError};
use warpgate_core::approvals::{GatedConnection, admit_target_session};
use warpgate_core::{
    AdmittedTarget, Services, SessionHandle, TargetAuthorization, WarpgateServerHandle,
};
use warpgate_db_entities::Target::TargetKind;

/// Session grace period: how long a session lingers after the WebSocket drops before the
/// manager reaps it, so a page reload / brief network blip can reattach and replay the buffer.
const DISCONNECT_GRACE: Duration = Duration::from_secs(60);

/// [`SessionHandle`] backed by an abort channel. Warpgate cores call `close()` (e.g. from the
/// admin "disconnect" action); the receiving end tears the session down. Identical for every
/// web protocol, so it lives here.
pub struct WebSessionHandle {
    abort_tx: UnboundedSender<()>,
}

impl WebSessionHandle {
    pub const fn new(abort_tx: UnboundedSender<()>) -> Self {
        Self { abort_tx }
    }
}

impl SessionHandle for WebSessionHandle {
    fn close(&mut self) {
        let _ = self.abort_tx.send(());
    }
}

/// Whether a buffered outbound message may be dropped when the buffer is over budget.
///
/// Structural messages (connection state, resize, …) must return `false` — losing one desyncs
/// the client. A terminal's byte stream can shed the oldest output; a desktop can shed old
/// framebuffer deltas but never a resize. Each crate's `ServerMessage` implements this.
pub trait Sheddable {
    fn is_droppable(&self) -> bool;
}

/// Something the disconnect timer can hand a session back to for reaping — implemented by each
/// crate's client manager.
pub trait SessionRemover: Send + Sync + 'static {
    fn remove_session(&self, id: UserSessionId) -> impl Future<Output = ()> + Send;
}

/// Protocol-agnostic session core: identity, a bounded replayable outbound buffer, a liveness
/// flag, and the disconnect grace timer. Each crate wraps this with its protocol-specific
/// backend handles and input methods (and `Deref`s to it for the shared surface).
pub struct WebSession<M> {
    id: UserSessionId,
    user_id: Uuid,
    target_name: String,
    target_kind: TargetKind,

    // Kept alive so the registered Warpgate session (and its DB row) isn't dropped early.
    _server_handle: Arc<Mutex<WarpgateServerHandle>>,

    abort_tx: UnboundedSender<()>,

    // Buffered so events can be queued and replayed if the WS stream reconnects.
    output_buffer: Arc<Mutex<VecDeque<M>>>,
    output_notify: Arc<Notify>,
    /// Max retained *droppable* messages; non-droppable ones are never counted or shed.
    shed_cap: usize,

    is_dead: Arc<AtomicBool>,
    disconnect_timer: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl<M: Sheddable> WebSession<M> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: UserSessionId,
        user_id: Uuid,
        target_name: String,
        target_kind: TargetKind,
        server_handle: Arc<Mutex<WarpgateServerHandle>>,
        abort_tx: UnboundedSender<()>,
        initial_capacity: usize,
        shed_cap: usize,
    ) -> Self {
        Self {
            id,
            user_id,
            target_name,
            target_kind,
            _server_handle: server_handle,
            abort_tx,
            output_buffer: Arc::new(Mutex::new(VecDeque::with_capacity(initial_capacity))),
            output_notify: Arc::new(Notify::new()),
            shed_cap,
            is_dead: Arc::new(AtomicBool::new(false)),
            disconnect_timer: Arc::new(Mutex::new(None)),
        }
    }

    /// Queue an outbound message, shedding the oldest droppable messages beyond [`Self::shed_cap`]
    /// (never a structural one), then wake any waiting sender. The buffer stays small, so the scan
    /// is over a handful of items.
    pub async fn push(&self, msg: M) {
        let mut buf = self.output_buffer.lock().await;
        let droppable = msg.is_droppable();
        buf.push_back(msg);
        if droppable {
            while buf.iter().filter(|m| m.is_droppable()).count() > self.shed_cap {
                let Some(idx) = buf.iter().position(Sheddable::is_droppable) else {
                    break;
                };
                buf.remove(idx);
            }
        }
        self.output_notify.notify_waiters();
    }

    pub async fn drain_buffer(&self) -> Vec<M> {
        self.output_buffer.lock().await.drain(..).collect()
    }

    pub fn wait_buffer(&self) -> Notified<'_> {
        self.output_notify.notified()
    }

    pub const fn id(&self) -> UserSessionId {
        self.id
    }

    pub const fn user_id(&self) -> Uuid {
        self.user_id
    }

    pub fn target_name(&self) -> &str {
        &self.target_name
    }

    pub const fn target_kind(&self) -> &TargetKind {
        &self.target_kind
    }

    pub fn is_dead(&self) -> bool {
        self.is_dead.load(Ordering::Relaxed)
    }

    /// Ask the backend/core to tear this session down (admin disconnect, reaping).
    pub fn abort(&self) {
        let _ = self.abort_tx.send(());
    }

    /// Mark dead and wake the WS loop so it observes the state and exits.
    pub fn close(&self) {
        self.is_dead.store(true, Ordering::Relaxed);
        self.output_notify.notify_waiters();
    }

    /// Arm the grace timer that reaps this session if the client doesn't reconnect in time.
    pub async fn start_disconnect_timer<R: SessionRemover>(&self, remover: Arc<R>) {
        let id = self.id;
        let timer = tokio::spawn(async move {
            tokio::time::sleep(DISCONNECT_GRACE).await;
            remover.remove_session(id).await;
        });
        *self.disconnect_timer.lock().await = Some(timer);
    }

    pub async fn cancel_disconnect_timer(&self) {
        if let Some(handle) = self.disconnect_timer.lock().await.take() {
            handle.abort();
        }
    }
}

/// A live session held by a [`ClientManager`].
pub trait ManagedSession: Send + Sync + 'static {
    fn id(&self) -> UserSessionId;
    fn user_id(&self) -> Uuid;
    /// Whether the session has been torn down (admin close, backend disconnect, …) but not yet
    /// removed from the manager. A dead session must read the same as absent: it must not be
    /// reattachable, even during the window before it's reaped.
    fn is_dead(&self) -> bool;
    /// Invoked when the manager drops this session (abort the backend; mark dead if needed).
    fn on_removed(&self);
}

pub enum SessionAccess<S> {
    Granted(Arc<S>),
    NotFound,
    Forbidden,
}

/// Starts a target session, waiting for approval if needed
pub async fn admit_web_client_session<O: Send + Sync>(
    services: &Services,
    server_handle: &Arc<Mutex<WarpgateServerHandle>>,
    authorization: TargetAuthorization<O>,
    remote_address: Option<SocketAddr>,
) -> Result<AdmittedTarget<O>, WarpgateError> {
    server_handle.lock().await.mark_provisional();

    let admitted = admit_target_session(
        services,
        server_handle,
        authorization,
        GatedConnection {
            remote_ip: remote_address.map(|address| address.ip()),
            credentials: RememberApprovalBy::Nothing,
        },
        || async { Ok(()) },
    )
    .await?;

    server_handle.lock().await.confirm();
    Ok(admitted)
}

/// Session slot guard, slots limit the number of parallel approval attempts
#[must_use = "dropping the reservation immediately releases the slot it holds"]
pub struct SessionSlot {
    user_id: Uuid,
    reservations: Arc<Mutex<HashMap<Uuid, usize>>>,
}

impl Drop for SessionSlot {
    fn drop(&mut self) {
        let user_id = self.user_id;
        let reservations = self.reservations.clone();
        tokio::spawn(async move {
            if let Entry::Occupied(mut entry) = reservations.lock().await.entry(user_id) {
                *entry.get_mut() -= 1;
                if *entry.get() == 0 {
                    entry.remove();
                }
            }
        });
    }
}

/// In-memory registry of live sessions, keyed by id. Each crate wraps this and adds its own
/// protocol-specific `create_session`.
pub struct ClientManager<S> {
    sessions: Arc<Mutex<HashMap<UserSessionId, Arc<S>>>>,
    /// Setup slots for not yet running sessions
    reservations: Arc<Mutex<HashMap<Uuid, usize>>>,
}

impl<S> Default for ClientManager<S> {
    fn default() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            reservations: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

// avoid S: Clone
impl<S> Clone for ClientManager<S> {
    fn clone(&self) -> Self {
        Self {
            sessions: self.sessions.clone(),
            reservations: self.reservations.clone(),
        }
    }
}

impl<S: ManagedSession> ClientManager<S> {
    pub fn new() -> Self {
        Self::default()
    }

    /// private, use Self::access
    async fn get_session(&self, id: UserSessionId) -> Option<Arc<S>> {
        self.sessions.lock().await.get(&id).cloned()
    }

    /// resolves a session for a request acting as user_id
    pub async fn access(&self, id: UserSessionId, user_id: Uuid) -> SessionAccess<S> {
        let Some(session) = self.get_session(id).await else {
            return SessionAccess::NotFound;
        };
        if session.user_id() != user_id {
            return SessionAccess::Forbidden;
        }
        SessionAccess::Granted(session)
    }

    /// Like [`Self::access`], but a session that's been closed (admin close, backend
    /// disconnect, …) and not yet reaped reads as absent, same as one that was never found.
    /// Attaching to a session must not resurrect a session that's already torn down, even
    /// during the window before the manager actually removes it.
    pub async fn access_live(&self, id: UserSessionId, user_id: Uuid) -> SessionAccess<S> {
        match self.access(id, user_id).await {
            SessionAccess::Granted(session) if session.is_dead() => SessionAccess::NotFound,
            other => other,
        }
    }

    /// Claim a future session slot for user
    pub async fn reserve_slot(
        &self,
        user_id: Uuid,
        max_per_user: usize,
    ) -> Result<SessionSlot, WarpgateError> {
        // Reservations lock before sessions lock
        let mut reservations = self.reservations.lock().await;
        let live = self
            .sessions
            .lock()
            .await
            .values()
            .filter(|s| s.user_id() == user_id)
            .count();

        let claimed = reservations.entry(user_id).or_default();
        if live + *claimed >= max_per_user {
            return Err(WarpgateError::SessionLimitReached);
        }
        *claimed += 1;

        Ok(SessionSlot {
            user_id,
            reservations: self.reservations.clone(),
        })
    }

    pub async fn insert(&self, session: Arc<S>) {
        self.sessions.lock().await.insert(session.id(), session);
    }

    pub async fn remove_session(&self, id: UserSessionId) {
        if let Some(session) = self.sessions.lock().await.remove(&id) {
            session.on_removed();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use uuid::Uuid;

    use super::*;

    struct FakeSession {
        id: UserSessionId,
        user_id: Uuid,
        dead: AtomicBool,
    }

    impl ManagedSession for FakeSession {
        fn id(&self) -> UserSessionId {
            self.id
        }

        fn user_id(&self) -> Uuid {
            self.user_id
        }

        fn is_dead(&self) -> bool {
            self.dead.load(Ordering::Relaxed)
        }

        fn on_removed(&self) {}
    }

    impl FakeSession {
        fn close(&self) {
            self.dead.store(true, Ordering::Relaxed);
        }
    }

    /// `WebSshClientManager`'s abort handler calls `session.abort()` then
    /// `session.close()` -- the latter only flips the liveness flag, it does not
    /// remove the session from the manager. Removal happens later and separately
    /// (the backend event loop's `Done` handling, or the disconnect grace timer),
    /// so there is a real window where a session is dead but still registered.
    ///
    /// That window is what `ClientManager::access_live()` exists for: without it,
    /// `access()` alone would still report `Granted` for an aborted session and let
    /// it be reattached. A Python end-to-end test can't hit this window
    /// deterministically -- delivery of the admin close is asynchronous, and by the
    /// time it could check, the session may already have been fully removed (giving
    /// a 404 for "not found" instead, which doesn't exercise this guard at all).
    /// This unit test constructs the window directly and deterministically instead,
    /// against the production `access_live()` the endpoints actually call.
    #[tokio::test]
    async fn a_dead_but_still_registered_session_is_rejected() {
        let manager = ClientManager::<FakeSession>::new();
        let user_id = Uuid::new_v4();
        let session = Arc::new(FakeSession {
            id: UserSessionId(Uuid::new_v4()),
            user_id,
            dead: AtomicBool::new(false),
        });
        let id = session.id();
        manager.insert(session.clone()).await;

        // Sanity check: a live, registered session is accepted.
        assert!(matches!(
            manager.access_live(id, user_id).await,
            SessionAccess::Granted(_)
        ));

        // Mark it dead without removing it, exactly like the abort handler's
        // `session.close()` (removal is a separate step it doesn't take).
        session.close();

        assert!(
            matches!(manager.access(id, user_id).await, SessionAccess::Granted(_)),
            "closing a session must not remove it from the manager, otherwise this \
             test isn't reproducing the dead-but-registered window"
        );
        assert!(
            matches!(
                manager.access_live(id, user_id).await,
                SessionAccess::NotFound
            ),
            "a dead session must be rejected even while still registered"
        );

        // Once it's actually removed (event loop exit / grace-timer sweep), the
        // same guard still refuses it, now via the `NotFound` branch instead.
        manager.remove_session(id).await;
        assert!(matches!(
            manager.access_live(id, user_id).await,
            SessionAccess::NotFound
        ));
    }
}

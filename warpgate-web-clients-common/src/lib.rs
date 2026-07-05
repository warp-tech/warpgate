//! Shared plumbing for Warpgate's browser client crates (`warpgate-web-ssh`,
//! `warpgate-web-desktop`). Both proxy a backend protocol to a WebSocket and need the
//! same machinery: a buffered outbound queue that survives brief reconnects, a
//! liveness flag, a disconnect grace timer, and an in-memory registry of live sessions.
//!
//! Only the message type and the protocol-specific `create_session`/event-loop differ,
//! so those live in each crate; everything here is generic over the message type `M`.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::futures::Notified;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;
use uuid::Uuid;
use warpgate_core::{SessionHandle, WarpgateServerHandle};
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
    fn remove_session(&self, id: Uuid) -> impl Future<Output = ()> + Send;
}

/// Protocol-agnostic session core: identity, a bounded replayable outbound buffer, a liveness
/// flag, and the disconnect grace timer. Each crate wraps this with its protocol-specific
/// backend handles and input methods (and `Deref`s to it for the shared surface).
pub struct WebSession<M> {
    id: Uuid,
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
        id: Uuid,
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

    pub const fn id(&self) -> Uuid {
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
    fn id(&self) -> Uuid;
    fn user_id(&self) -> Uuid;
    /// Invoked when the manager drops this session (abort the backend; mark dead if needed).
    fn on_removed(&self);
}

/// In-memory registry of live sessions, keyed by id. Each crate wraps this and adds its own
/// protocol-specific `create_session`.
pub struct ClientManager<S> {
    sessions: Arc<Mutex<HashMap<Uuid, Arc<S>>>>,
}

impl<S> Default for ClientManager<S> {
    fn default() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<S: ManagedSession> ClientManager<S> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Shared handle to the session map, for the event loop to remove itself on backend end.
    pub fn sessions(&self) -> Arc<Mutex<HashMap<Uuid, Arc<S>>>> {
        self.sessions.clone()
    }

    pub async fn get_session(&self, id: Uuid) -> Option<Arc<S>> {
        self.sessions.lock().await.get(&id).cloned()
    }

    pub async fn count_for_user(&self, user_id: Uuid) -> usize {
        self.sessions
            .lock()
            .await
            .values()
            .filter(|s| s.user_id() == user_id)
            .count()
    }

    pub async fn insert(&self, session: Arc<S>) {
        self.sessions.lock().await.insert(session.id(), session);
    }

    pub async fn remove_session(&self, id: Uuid) {
        if let Some(session) = self.sessions.lock().await.remove(&id) {
            session.on_removed();
        }
    }
}

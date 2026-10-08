//! Shared plumbing for Warpgate's browser client crates (`warpgate-web-ssh`,
//! `warpgate-web-desktop`). Both proxy a backend protocol to a WebSocket and need the
//! same machinery: a buffered outbound queue that survives brief reconnects, a session
//! phase the browser can render, a liveness flag, a disconnect grace timer, an in-memory
//! registry of live sessions, the admission gate and the WebSocket pump loop.
//!
//! Only the message type and the protocol-specific `create_session`/event loop differ,
//! so those live in each crate; everything here is generic over the message type `M`.

use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::future::Future;
use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use poem::web::websocket::{Message, WebSocketStream};
use serde::Serialize;
use tokio::sync::futures::Notified;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::warn;
use uuid::Uuid;
use warpgate_common::auth::RememberApprovalBy;
use warpgate_common::{Protocol, UserFacingReason, UserSessionId, WarpgateError};
use warpgate_core::approvals::{Admission, GatedConnection, admit_target_session};
use warpgate_core::{
    AdmittedTarget, Services, SessionHandle, State, TargetAuthorization, UserSessionStateInit,
    WarpgateServerHandle,
};
use warpgate_db_entities::Target::TargetKind;

/// Session grace period: how long a session lingers without a WebSocket attached before the
/// manager reaps it, so a page reload / brief network blip can reattach and replay the buffer.
const DISCONNECT_GRACE: Duration = Duration::from_secs(60);

const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveSessionPhase {
    AwaitingApproval,
    Connecting,
    Connected,
}

/// Session phase as reported to the frontend
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum SessionPhase {
    AwaitingApproval,
    Connecting,
    Connected,
    Closed {
        reason: CloseReason,
        message: Option<String>,
    },
}

impl From<LiveSessionPhase> for SessionPhase {
    fn from(phase: LiveSessionPhase) -> Self {
        match phase {
            LiveSessionPhase::AwaitingApproval => Self::AwaitingApproval,
            LiveSessionPhase::Connecting => Self::Connecting,
            LiveSessionPhase::Connected => Self::Connected,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CloseReason {
    ApprovalRejected,
    ApprovalTimedOut,
    Error,
    Disconnected,
}

pub struct WebSessionHandle(CancellationToken);

impl SessionHandle for WebSessionHandle {
    fn close(&mut self) {
        self.0.cancel();
    }
}

/// Whether a buffered outbound message may be dropped when the buffer is over budget.
///
/// Structural messages (session phase, resize, …) must return `false` — losing one desyncs
/// the client. A terminal's byte stream can shed the oldest output; a desktop can shed old
/// framebuffer deltas but never a resize. Each crate's `ServerMessage` implements this.
pub trait Sheddable {
    fn is_droppable(&self) -> bool;
}

/// outbound queue and latest phase
struct Outbox<M> {
    buffer: VecDeque<M>,
    phase: SessionPhase,
}

/// Protocol-agnostic session core: identity, a bounded replayable outbound buffer, the
/// session phase, a cancellation token, a liveness flag, and the disconnect grace timer.
/// Each crate wraps this with its protocol-specific backend handles and input methods
/// (and `Deref`s to it for the shared surface).
pub struct WebSession<M> {
    id: UserSessionId,
    user_id: Uuid,
    target_name: String,
    target_kind: TargetKind,

    // Kept alive so the registered Warpgate session (and its DB row) isn't dropped early.
    server_handle: Arc<Mutex<WarpgateServerHandle>>,

    cancel: CancellationToken,

    outbox: Mutex<Outbox<M>>,
    output_notify: Notify,
    /// Max retained *droppable* messages; non-droppable ones are never counted or shed.
    shed_cap: usize,

    is_dead: AtomicBool,
    disconnect_timer: Mutex<Option<JoinHandle<()>>>,
}

impl<M: Sheddable + From<SessionPhase>> WebSession<M> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: UserSessionId,
        user_id: Uuid,
        target_name: String,
        target_kind: TargetKind,
        server_handle: Arc<Mutex<WarpgateServerHandle>>,
        cancel: CancellationToken,
        initial_capacity: usize,
        shed_cap: usize,
    ) -> Self {
        Self {
            id,
            user_id,
            target_name,
            target_kind,
            server_handle,
            cancel,
            outbox: Mutex::new(Outbox {
                buffer: VecDeque::with_capacity(initial_capacity),
                phase: SessionPhase::Connecting,
            }),
            output_notify: Notify::new(),
            shed_cap,
            is_dead: AtomicBool::new(false),
            disconnect_timer: Mutex::new(None),
        }
    }

    /// Queue an outbound message, shedding the oldest droppable messages beyond [`Self::shed_cap`]
    /// (never a structural one), then wake any waiting sender. The buffer stays small, so the scan
    /// is over a handful of items.
    pub async fn push(&self, msg: M) {
        let mut outbox = self.outbox.lock().await;
        Self::enqueue(&mut outbox.buffer, msg, self.shed_cap);
        self.output_notify.notify_waiters();
    }

    fn enqueue(buf: &mut VecDeque<M>, msg: M, shed_cap: usize) {
        let droppable = msg.is_droppable();
        buf.push_back(msg);
        if droppable {
            while buf.iter().filter(|m| m.is_droppable()).count() > shed_cap {
                let Some(idx) = buf.iter().position(Sheddable::is_droppable) else {
                    break;
                };
                buf.remove(idx);
            }
        }
    }

    pub async fn set_phase(&self, phase: LiveSessionPhase) {
        self.transition(phase.into()).await;
    }

    async fn transition(&self, phase: SessionPhase) {
        let mut outbox = self.outbox.lock().await;
        outbox.phase = phase.clone();
        Self::enqueue(&mut outbox.buffer, M::from(phase), self.shed_cap);
        self.output_notify.notify_waiters();
    }

    async fn end(&self, reason: CloseReason, message: Option<String>) {
        self.transition(SessionPhase::Closed { reason, message })
            .await;
        self.is_dead.store(true, Ordering::Relaxed);
        self.output_notify.notify_waiters();
    }

    pub async fn replay_phase(&self) {
        let mut outbox = self.outbox.lock().await;
        let phase = outbox.phase.clone();
        Self::enqueue(&mut outbox.buffer, M::from(phase), self.shed_cap);
        self.output_notify.notify_waiters();
    }

    pub async fn drain_buffer(&self) -> Vec<M> {
        self.outbox.lock().await.buffer.drain(..).collect()
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

    fn is_dead(&self) -> bool {
        self.is_dead.load(Ordering::Relaxed)
    }

    pub const fn cancellation(&self) -> &CancellationToken {
        &self.cancel
    }

    pub const fn server_handle(&self) -> &Arc<Mutex<WarpgateServerHandle>> {
        &self.server_handle
    }

    /// Ask the lifecycle task to tear this session down (admin disconnect, reaping).
    pub fn abort(&self) {
        self.cancel.cancel();
    }

    /// Forward cancellation event into mpsc channel
    pub fn forward_cancellation(&self, abort_tx: UnboundedSender<()>) {
        let cancel = self.cancel.clone();
        tokio::spawn(async move {
            cancel.cancelled().await;
            let _ = abort_tx.send(());
        });
    }

    /// Arm the grace timer that reaps this session if no client attaches in time.
    pub async fn start_disconnect_timer<S: ManagedSession>(&self, registry: ClientManager<S>) {
        let id = self.id;
        let timer = tokio::spawn(async move {
            tokio::time::sleep(DISCONNECT_GRACE).await;
            registry.remove_session(id).await;
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
    /// Invoked when the manager drops this session (abort the backend)
    fn on_removed(&self);
}

pub async fn register_provisional_web_client_session(
    services: &Services,
    protocol: Protocol,
    remote_address: Option<SocketAddr>,
    cancel: &CancellationToken,
) -> Result<Arc<Mutex<WarpgateServerHandle>>, WarpgateError> {
    let server_handle = State::register_node_local_user_session(
        &services.state,
        protocol,
        UserSessionStateInit {
            remote_address,
            handle: Box::new(WebSessionHandle(cancel.clone())),
        },
    )
    .await?;
    server_handle.lock().await.mark_provisional();
    Ok(server_handle)
}

/// `connect` connects to target and relays until the backend is done
pub async fn run_web_client_lifecycle<S, M, O, E, Fut>(
    session: &Arc<S>,
    registry: ClientManager<S>,
    services: &Services,
    authorization: TargetAuthorization<O>,
    remote_address: Option<SocketAddr>,
    connect: impl FnOnce(AdmittedTarget<O>) -> Fut,
) where
    S: ManagedSession + Deref<Target = WebSession<M>>,
    M: Sheddable + From<SessionPhase>,
    O: Send + Sync,
    Fut: Future<Output = Result<(), E>>,
    WarpgateError: From<E>,
{
    let _cancel_on_exit = session.cancellation().clone().drop_guard();
    let cancel = session.cancellation();
    // Cancellation drops the gate future, which withdraws the approval request.
    let admission = tokio::select! {
        () = cancel.cancelled() => None,
        admission = admit(session, services, authorization, remote_address) => Some(admission),
    };
    let (reason, error): (CloseReason, Option<WarpgateError>) = match admission {
        Some(Ok(Admission::Admitted(admitted))) if !cancel.is_cancelled() => {
            match connect(admitted).await {
                Err(error) if !cancel.is_cancelled() => (CloseReason::Error, Some(error.into())),
                // The backend ended because we told it to.
                _ => (CloseReason::Disconnected, None),
            }
        }
        Some(Ok(Admission::Admitted(_))) | None => (CloseReason::Disconnected, None),
        Some(Ok(Admission::Refused)) => (CloseReason::ApprovalRejected, None),
        Some(Ok(Admission::Expired)) => (CloseReason::ApprovalTimedOut, None),
        Some(Err(error)) => {
            warn!(session=%session.id(), %error, "Failed to admit the web client session");
            (CloseReason::Error, Some(error.into()))
        }
    };
    session
        .end(reason, error.map(|e| e.user_facing_reason()))
        .await;
    registry.remove_session(session.id()).await;
}

async fn admit<M, O>(
    session: &WebSession<M>,
    services: &Services,
    authorization: TargetAuthorization<O>,
    remote_address: Option<SocketAddr>,
) -> Result<Admission<O>, WarpgateError>
where
    M: Sheddable + From<SessionPhase>,
    O: Send + Sync,
{
    admit_target_session(
        services,
        session.server_handle(),
        authorization,
        GatedConnection {
            remote_ip: remote_address.map(|address| address.ip()),
            credentials: RememberApprovalBy::Nothing,
        },
        || async {
            session.set_phase(LiveSessionPhase::AwaitingApproval).await;
            Ok(())
        },
    )
    .await
}

/// In-memory registry of live sessions, keyed by id. Each crate wraps this and adds its own
/// protocol-specific `create_session`.
pub struct ClientManager<S> {
    sessions: Arc<Mutex<HashMap<UserSessionId, Arc<S>>>>,
}

impl<S> Default for ClientManager<S> {
    fn default() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

// avoid S: Clone
impl<S> Clone for ClientManager<S> {
    fn clone(&self) -> Self {
        Self {
            sessions: self.sessions.clone(),
        }
    }
}

impl<S: ManagedSession> ClientManager<S> {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn lookup_user_session(&self, id: UserSessionId, user_id: Uuid) -> Option<Arc<S>> {
        self.sessions
            .lock()
            .await
            .get(&id)
            .filter(|session| session.user_id() == user_id)
            .cloned()
    }

    pub async fn try_insert(
        &self,
        session: Arc<S>,
        max_per_user: usize,
    ) -> Result<(), WarpgateError> {
        let mut sessions = self.sessions.lock().await;
        let live = sessions
            .values()
            .filter(|s| s.user_id() == session.user_id())
            .count();
        if live >= max_per_user {
            return Err(WarpgateError::SessionLimitReached);
        }
        sessions.insert(session.id(), session);
        Ok(())
    }

    pub async fn remove_session(&self, id: UserSessionId) {
        if let Some(session) = self.sessions.lock().await.remove(&id) {
            session.on_removed();
        }
    }
}

pub async fn run_stream_loop<S, M, Fut>(
    session: &Arc<S>,
    registry: ClientManager<S>,
    socket: WebSocketStream,
    encode: impl Fn(&M) -> Message,
    mut decode_and_handle: impl FnMut(String) -> Fut,
) where
    S: ManagedSession + Deref<Target = WebSession<M>>,
    M: Sheddable + From<SessionPhase>,
    Fut: Future<Output = ()> + Send,
{
    let (mut sink, mut stream) = socket.split();

    let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    keepalive.tick().await; // consume the immediate first tick

    loop {
        let notified = session.wait_buffer();
        tokio::pin!(notified);
        notified.as_mut().enable();

        // flush entire outbound buffer before reading inputs
        let mut closed = false;
        let batch = session.drain_buffer().await;
        let had_messages = !batch.is_empty();
        for msg in batch {
            if sink.feed(encode(&msg)).await.is_err() {
                closed = true;
                break;
            }
        }
        if !closed && had_messages && sink.flush().await.is_err() {
            closed = true;
        }
        if closed || session.is_dead() {
            break;
        }

        tokio::select! {
            () = notified.as_mut() => {}

            maybe_msg = stream.next() => {
                match maybe_msg {
                    Some(Ok(Message::Text(text))) => decode_and_handle(text).await,
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }

            _ = keepalive.tick() => {
                if sink.send(Message::Ping(vec![])).await.is_err() {
                    break;
                }
            }
        }
    }

    session.start_disconnect_timer(registry).await;
}

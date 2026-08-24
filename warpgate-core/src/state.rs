use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex, broadcast};
use tracing::error;
use uuid::Uuid;
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{
    NodeId, Protocol, SessionLifecycle, Target, TargetSessionId, UserSessionId, WarpgateError,
};
use warpgate_db_entities::{TargetSession, UserSession};

use crate::logging::AuditEvent;
use crate::rate_limiting::{RateLimiterRegistry, RateLimiterStackHandle};
use crate::{SessionHandle, TargetSessionHandle, WarpgateServerHandle};

pub struct State {
    /// Live target connections, keyed by target-session id.
    pub target_sessions: HashMap<TargetSessionId, Arc<Mutex<TargetSessionState>>>,
    /// Live authenticated/login sessions, including targetless SSH menus and
    /// HTTP browser sessions with several child target connections.
    pub user_sessions: HashMap<UserSessionId, Arc<Mutex<UserSessionState>>>,
    db: DatabaseConnection,
    node_id: NodeId,
    rate_limiter_registry: Arc<Mutex<RateLimiterRegistry>>,
    change_sender: broadcast::Sender<()>,
}

impl State {
    pub fn new(
        db: &DatabaseConnection,
        rate_limiter_registry: &Arc<Mutex<RateLimiterRegistry>>,
        node_id: NodeId,
    ) -> Arc<Mutex<Self>> {
        let sender = broadcast::channel(2).0;
        Arc::new(Mutex::new(Self {
            target_sessions: HashMap::new(),
            user_sessions: HashMap::new(),
            db: db.clone(),
            node_id,
            rate_limiter_registry: rate_limiter_registry.clone(),
            change_sender: sender,
        }))
    }

    /// Registers a user session with the protocol's own lifecycle. The one
    /// valid exception — a session kept alive by a node-local handle rather
    /// than its protocol's usual backing — registers through
    /// [`Self::register_node_local_user_session`] instead; there is no
    /// lifecycle to pass, so it cannot be passed wrong.
    pub async fn register_user_session(
        this: &Arc<Mutex<Self>>,
        protocol: Protocol,
        state: UserSessionStateInit,
    ) -> Result<Arc<Mutex<WarpgateServerHandle>>, WarpgateError> {
        Self::register_user_session_in(this, protocol, protocol.lifecycle(), state).await
    }

    /// Registers a session that is [`SessionLifecycle::ConnectionBound`]
    /// regardless of its protocol's default: it is kept alive by this node's
    /// handle alone (a header-borne ticket's cookieless HTTP session), so the
    /// row must record an owner — as a shared session it would back nothing
    /// and the orphan reaper would end it mid-use.
    pub async fn register_node_local_user_session(
        this: &Arc<Mutex<Self>>,
        protocol: Protocol,
        state: UserSessionStateInit,
    ) -> Result<Arc<Mutex<WarpgateServerHandle>>, WarpgateError> {
        Self::register_user_session_in(this, protocol, SessionLifecycle::ConnectionBound, state)
            .await
    }

    async fn register_user_session_in(
        this: &Arc<Mutex<Self>>,
        protocol: Protocol,
        lifecycle: SessionLifecycle,
        state: UserSessionStateInit,
    ) -> Result<Arc<Mutex<WarpgateServerHandle>>, WarpgateError> {
        let mut self_ = this.lock().await;
        let id = UserSessionId(Uuid::new_v4());

        // Read before the state is shared: locking a `UserSessionState` while
        // holding `State` is the reverse of the order everything else takes
        // (see `WarpgateServerHandle::start_target_session`), and is only safe
        // here because nothing else can reach this one yet. Not relying on
        // that keeps the order true without an exception.
        let remote_address = state
            .remote_address
            .map_or_else(String::new, |address| address.to_string());
        let state = Arc::new(Mutex::new(UserSessionState::new(
            state,
            self_.change_sender.clone(),
        )));

        {
            use sea_orm::ActiveValue::Set;

            let values = UserSession::ActiveModel {
                id: Set(id.0),
                started: Set(OffsetDateTime::now_utc()),
                remote_address: Set(remote_address),
                protocol: Set(protocol.to_string()),
                // A shared session is served by any node and owned by none;
                // recording an owner would make the reaper end it when this
                // node goes away.
                node_id: Set(match lifecycle {
                    SessionLifecycle::ConnectionBound => Some(self_.node_id.0),
                    SessionLifecycle::Shared(_) => None,
                }),
                ..Default::default()
            };

            let db = &self_.db;
            values
                .insert(db)
                .await
                .context("Error inserting session")
                .map_err(WarpgateError::from)?;
        }

        Ok(self_.install_user_session(this, id, state, protocol, lifecycle))
    }

    /// Registers a user session and wraps its raw connection stream with the
    /// session rate limiters in one step, so a raw-TCP protocol cannot serve
    /// an unlimited stream by forgetting the wrap.
    ///
    /// The session is necessarily connection-bound: it is this socket, and it
    /// ends with it — which is also every raw-TCP protocol's default.
    pub async fn register_user_session_with_stream<S>(
        this: &Arc<Mutex<Self>>,
        protocol: Protocol,
        state: UserSessionStateInit,
        stream: S,
    ) -> Result<
        (
            Arc<Mutex<WarpgateServerHandle>>,
            impl AsyncRead + AsyncWrite + Unpin + Send + use<S>,
        ),
        WarpgateError,
    >
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let handle = Self::register_user_session(this, protocol, state).await?;
        let wrapped = handle.lock().await.wrap_stream(stream).await?;
        Ok((handle, wrapped))
    }

    /// Registers a node-local view over an existing DB-backed user session — an
    /// HTTP browser session created on another node. No row is inserted; the
    /// caller has validated the row. The local handle's drop detaches rather
    /// than ends the session ([`WarpgateServerHandle`] does this for HTTP).
    ///
    /// Always the protocol's own (shared) lifecycle: only a stored-cookie
    /// session has a row to re-attach to — a node-local session lives and dies
    /// with its one owning node and is never adopted.
    pub async fn adopt_user_session(
        this: &Arc<Mutex<Self>>,
        id: UserSessionId,
        protocol: Protocol,
        state: UserSessionStateInit,
    ) -> Arc<Mutex<WarpgateServerHandle>> {
        let mut self_ = this.lock().await;
        let state = Arc::new(Mutex::new(UserSessionState::new(
            state,
            self_.change_sender.clone(),
        )));
        self_.install_user_session(this, id, state, protocol, protocol.lifecycle())
    }

    fn install_user_session(
        &mut self,
        owner: &Arc<Mutex<Self>>,
        id: UserSessionId,
        state: Arc<Mutex<UserSessionState>>,
        protocol: Protocol,
        lifecycle: SessionLifecycle,
    ) -> Arc<Mutex<WarpgateServerHandle>> {
        self.user_sessions.insert(id, state.clone());
        let _ = self.change_sender.send(());
        Arc::new(Mutex::new(WarpgateServerHandle::new(
            id,
            self.db.clone(),
            owner.clone(),
            state,
            self.rate_limiter_registry.clone(),
            protocol,
            lifecycle,
        )))
    }

    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.change_sender.subscribe()
    }

    /// Removes a session that never completed authentication, deleting its row
    /// rather than marking it ended — see
    /// [`WarpgateServerHandle::mark_provisional`]. Target sessions started
    /// while still provisional (Kubernetes confirms only after admission) are
    /// part of the attempt and are discarded with it.
    pub async fn discard_session(&mut self, id: UserSessionId) {
        // Target sessions are owned by the removed state: their slots drop
        // with it, and each handle's teardown then no-ops on the rows deleted
        // here.
        self.user_sessions.remove(&id);

        if let Err(error) = TargetSession::Entity::delete_many()
            .filter(TargetSession::Column::UserSessionId.eq(id.0))
            .exec(&self.db)
            .await
        {
            error!(%error, %id, "Could not delete the session's target sessions from the DB");
        }
        if let Err(error) = UserSession::Entity::delete_by_id(id.0).exec(&self.db).await {
            error!(%error, %id, "Could not delete user session from the DB");
        }

        let _ = self.change_sender.send(());
    }

    pub fn detach_user_session(
        &mut self,
        id: UserSessionId,
        session_state: &Arc<Mutex<UserSessionState>>,
    ) {
        if self
            .user_sessions
            .get(&id)
            .is_some_and(|state| Arc::ptr_eq(state, session_state))
        {
            self.user_sessions.remove(&id);
        }
    }

    /// Creates the target-session row and in-memory state — or, for a shared
    /// (HTTP) session, adopts the live row another node (or an earlier local
    /// handle) already opened for this target, so one access shows as one
    /// record cluster-wide. The caller holds the parent's state lock (see the
    /// lock-order note on [`WarpgateServerHandle::start_target_session`]) and
    /// stores the returned handle in the parent's slot map.
    pub(crate) async fn create_target_session(
        this: &Arc<Mutex<Self>>,
        user_session_id: UserSessionId,
        id: TargetSessionId,
        target: &Target,
        parent: &UserSessionState,
        lifecycle: SessionLifecycle,
        ticket_id: Option<Uuid>,
    ) -> Result<TargetSessionHandle, WarpgateError> {
        let user_info = parent.user_info.clone().ok_or_else(|| {
            WarpgateError::InconsistentState(
                "target session created before user authentication".into(),
            )
        })?;

        let target_state = Arc::new(Mutex::new(TargetSessionState {
            user_session_id,
            user_info: user_info.clone(),
            target: target.clone(),
            change_sender: parent.change_sender.clone(),
            rate_limiter_handles: parent.rate_limiter_handles.clone(),
        }));

        // The row is opened with no lock held: the global state mutex is
        // taken only to register the finished session, so one node's DB
        // latency doesn't serialise every other session starting.
        let (db, node_id, rate_limiter_registry) = {
            let self_ = this.lock().await;
            (
                self_.db.clone(),
                self_.node_id,
                self_.rate_limiter_registry.clone(),
            )
        };
        let id = Self::open_target_session_row(
            &db,
            node_id,
            lifecycle,
            id,
            user_session_id,
            target,
            &user_info,
            ticket_id,
        )
        .await?;

        {
            let mut self_ = this.lock().await;
            self_.target_sessions.insert(id, target_state.clone());
            let _ = self_.change_sender.send(());
        }

        Ok(TargetSessionHandle::new(
            id,
            user_session_id,
            this.clone(),
            target_state,
            rate_limiter_registry,
            lifecycle,
        ))
    }

    /// Adopts the live row for this (parent, target) if one exists, otherwise
    /// inserts one and announces it. Returns the id the session is known by
    /// from here on — the adopted row's, not necessarily the proposed one.
    ///
    /// A shared target session is an access record with at most one live row
    /// per (parent, target).
    /// ponytail: find-then-insert; two nodes racing the first request can
    /// still each insert — a spare access record, not a correctness issue.
    /// A partial unique index would close it where the backend supports one.
    async fn open_target_session_row(
        db: &DatabaseConnection,
        node_id: NodeId,
        lifecycle: SessionLifecycle,
        id: TargetSessionId,
        user_session_id: UserSessionId,
        target: &Target,
        user_info: &AuthStateUserInfo,
        ticket_id: Option<Uuid>,
    ) -> Result<TargetSessionId, WarpgateError> {
        use sea_orm::ActiveValue::Set;

        if matches!(lifecycle, SessionLifecycle::Shared(_))
            && let Some(row) = TargetSession::Entity::find()
                .filter(TargetSession::Column::UserSessionId.eq(user_session_id.0))
                .filter(TargetSession::Column::TargetId.eq(target.id))
                .filter(TargetSession::Column::Ended.is_null())
                .one(db)
                .await?
        {
            return Ok(TargetSessionId(row.id));
        }

        let mut snapshot = serde_json::to_value(target)?;
        warpgate_common::redact_target_secrets(&mut snapshot);
        TargetSession::ActiveModel {
            id: Set(id.0),
            user_session_id: Set(user_session_id.0),
            target_snapshot: Set(snapshot.to_string()),
            target_id: Set(target.id),
            started: Set(OffsetDateTime::now_utc()),
            ended: Set(None),
            ticket_id: Set(ticket_id),
            node_id: Set(match lifecycle {
                SessionLifecycle::ConnectionBound => Some(node_id.0),
                SessionLifecycle::Shared(_) => None,
            }),
        }
        .insert(db)
        .await?;

        AuditEvent::TargetSessionStarted {
            session_id: id.0,
            target_id: target.id,
            target_name: target.name.clone(),
            user_id: user_info.id,
            username: user_info.username.clone(),
        }
        .emit();
        Ok(id)
    }

    /// Drops this node's view of a shared target session without ending it —
    /// the row is an access record other nodes may be serving, and it ends
    /// with its parent. The pointer check keeps a stale handle from evicting
    /// a re-adopted session's fresh state under the same id.
    pub fn detach_target_session(
        &mut self,
        id: TargetSessionId,
        session_state: &Arc<Mutex<TargetSessionState>>,
    ) {
        if self
            .target_sessions
            .get(&id)
            .is_some_and(|state| Arc::ptr_eq(state, session_state))
        {
            self.target_sessions.remove(&id);
            let _ = self.change_sender.send(());
        }
    }

    pub async fn remove_target_session(&mut self, id: TargetSessionId) {
        self.target_sessions.remove(&id);
        let row = match TargetSession::Entity::find_by_id(id.0).one(&self.db).await {
            Ok(row) => row,
            Err(error) => {
                error!(%error, %id, "Could not load target session from the DB");
                None
            }
        };

        let ended = match crate::db::mark_target_session_ended(&self.db, id).await {
            Ok(ended) => ended,
            Err(error) => {
                error!(%error, %id, "Could not update target session in the DB");
                false
            }
        };
        if ended && let Some(row) = row {
            crate::db::emit_target_session_ended(&self.db, row).await;
        }

        let _ = self.change_sender.send(());
    }

    pub async fn remove_session(&mut self, id: UserSessionId) {
        // Target sessions are owned by the removed state: their slots drop
        // with it, and each handle's teardown clears `target_sessions`. The
        // rows are marked ended here already so the audit trail doesn't wait
        // for those drops.
        //
        // The row is ended whether or not this node still holds the state: a
        // handle dropped just before this call detaches the entry without
        // ending anything, and ending the row is the whole point of the call.
        self.user_sessions.remove(&id);

        if let Err(error) = crate::db::mark_user_session_and_targets_ended(&self.db, id).await {
            error!(%error, %id, "Could not end user session in the DB");
        }

        let _ = self.change_sender.send(());
    }
}

#[derive(Clone)]
pub struct SharedSessionHandle {
    inner: Arc<std::sync::Mutex<Box<dyn SessionHandle + Send + Sync>>>,
}

impl SharedSessionHandle {
    fn new(handle: Box<dyn SessionHandle + Send + Sync>) -> Self {
        Self {
            inner: Arc::new(std::sync::Mutex::new(handle)),
        }
    }

    pub fn close(&self) {
        match self.inner.lock() {
            Ok(mut handle) => handle.close(),
            Err(error) => error!(%error, "Could not lock session close handle"),
        }
    }
}

pub struct UserSessionState {
    pub remote_address: Option<SocketAddr>,
    pub user_info: Option<AuthStateUserInfo>,
    pub handle: SharedSessionHandle,
    /// The parent owns its target sessions, at most one per target: their
    /// lifetime is this state's, and a slot's dropped sender aborts the
    /// requests served through it.
    pub(crate) target_sessions: HashMap<Uuid, TargetSessionSlot>,
    change_sender: broadcast::Sender<()>,
    pub rate_limiter_handles: Vec<RateLimiterStackHandle>,
}

pub(crate) struct TargetSessionSlot {
    pub(crate) handle: TargetSessionHandle,
    pub(crate) close_tx: broadcast::Sender<()>,
}

pub struct UserSessionStateInit {
    pub remote_address: Option<SocketAddr>,
    pub handle: Box<dyn SessionHandle + Send + Sync>,
}

impl UserSessionState {
    fn new(init: UserSessionStateInit, change_sender: broadcast::Sender<()>) -> Self {
        Self {
            remote_address: init.remote_address,
            user_info: None,
            handle: SharedSessionHandle::new(init.handle),
            target_sessions: HashMap::new(),
            change_sender,
            rate_limiter_handles: vec![],
        }
    }

    pub fn emit_change(&self) {
        let _ = self.change_sender.send(());
    }
}

/// In-memory state of one target connection. Deliberately carries no close
/// handle: the close signal is threaded through the parent user session, whose
/// teardown takes its children with it.
pub struct TargetSessionState {
    pub user_session_id: UserSessionId,
    pub user_info: AuthStateUserInfo,
    pub target: Target,
    change_sender: broadcast::Sender<()>,
    pub rate_limiter_handles: Vec<RateLimiterStackHandle>,
}

impl TargetSessionState {
    pub fn emit_change(&self) {
        let _ = self.change_sender.send(());
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use sea_orm::{ColumnTrait, Database, PaginatorTrait, QueryFilter};
    use warpgate_common::{TargetHTTPOptions, TargetOptions, Tls, UserSessionId};
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
    use warpgate_db_migrations::migrate_database;

    use super::*;

    struct TestHandle;

    impl SessionHandle for TestHandle {
        fn close(&mut self) {}
    }

    fn target() -> Target {
        Target {
            id: Uuid::new_v4(),
            name: "web".into(),
            description: String::new(),
            allow_roles: vec![],
            options: TargetOptions::Http(TargetHTTPOptions {
                url: "http://target".into(),
                tls: Tls::default(),
                headers: None,
                external_host: None,
            }),
            rate_limit_bytes_per_second: None,
            group_id: None,
            ticket_max_duration_seconds: None,
            ticket_requests_disabled: false,
            ticket_require_approval: false,
            ticket_max_uses: None,
        }
    }

    /// A revoked login must not keep serving: an administrative close ends the
    /// row on whichever node runs it, and a node that still holds a view of
    /// the session has to refuse rather than open something new under it.
    #[tokio::test]
    async fn an_ended_login_cannot_open_a_target_session() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let rate_limiters = Arc::new(Mutex::new(RateLimiterRegistry::new(db.clone())));
        let state = State::new(&db, &rate_limiters, NodeId(Uuid::new_v4()));
        let parent = State::register_user_session(
            &state,
            Protocol::Http,
            UserSessionStateInit {
                remote_address: None,
                handle: Box::new(TestHandle),
            },
        )
        .await
        .unwrap();
        let user_info = AuthStateUserInfo {
            id: Uuid::new_v4(),
            username: "alice".into(),
        };
        parent
            .lock()
            .await
            .set_user_info(user_info.clone())
            .await
            .unwrap();
        let parent_id = parent.lock().await.user_session_id();

        // Closed elsewhere in the cluster: only the row changes here.
        crate::db::mark_user_session_and_targets_ended(&db, parent_id)
            .await
            .unwrap();

        let refused = parent
            .lock()
            .await
            .start_target_session(crate::TargetAuthorization::for_test(
                user_info,
                target(),
                Protocol::Http,
            ))
            .await;
        assert!(matches!(refused, Err(WarpgateError::UserSessionEnded)));
    }

    /// Closing a login is what aborts the traffic running under it, and the
    /// chain that makes that true is ownership: the last handle reference
    /// drops the parent state, which drops its target-session slots, which
    /// drops their close senders. A cached handle clone anywhere in the
    /// serving path would break this silently, so it is asserted here.
    #[tokio::test]
    async fn close_parent_drops_target_sessions() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let rate_limiters = Arc::new(Mutex::new(RateLimiterRegistry::new(db.clone())));
        let state = State::new(&db, &rate_limiters, NodeId(Uuid::new_v4()));
        let parent = State::register_user_session(
            &state,
            Protocol::Http,
            UserSessionStateInit {
                remote_address: None,
                handle: Box::new(TestHandle),
            },
        )
        .await
        .unwrap();
        let user_info = AuthStateUserInfo {
            id: Uuid::new_v4(),
            username: "alice".into(),
        };
        parent
            .lock()
            .await
            .set_user_info(user_info.clone())
            .await
            .unwrap();

        let (target_session_id, _approved, close_signal) = *parent
            .lock()
            .await
            .start_target_session(crate::TargetAuthorization::for_test(
                user_info,
                target(),
                Protocol::Http,
            ))
            .await
            .unwrap()
            .admitted()
            .unwrap();
        let mut close_rx = close_signal.receiver();

        // The only reference a request would have held.
        drop(parent);

        // Teardown runs on a spawned task, so this is the wait for it, not a
        // sleep-and-hope: the receiver resolves as soon as the sender drops.
        tokio::time::timeout(std::time::Duration::from_secs(5), close_rx.recv())
            .await
            .expect("close signal did not fire")
            .expect_err("the sender is dropped, not fired");

        // And the session is gone from the node's registry, not merely signalled.
        for _ in 0..50 {
            if !state
                .lock()
                .await
                .target_sessions
                .contains_key(&target_session_id)
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("target session was not removed");
    }

    #[tokio::test]
    async fn user_session_reuses_its_target_session_per_target() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let rate_limiters = Arc::new(Mutex::new(RateLimiterRegistry::new(db.clone())));
        let state = State::new(&db, &rate_limiters, warpgate_common::NodeId(Uuid::new_v4()));
        let parent = State::register_user_session(
            &state,
            Protocol::Http,
            UserSessionStateInit {
                remote_address: None,
                handle: Box::new(TestHandle),
            },
        )
        .await
        .unwrap();
        let user_info = AuthStateUserInfo {
            id: Uuid::new_v4(),
            username: "alice".into(),
        };
        parent
            .lock()
            .await
            .set_user_info(user_info.clone())
            .await
            .unwrap();
        let parent_id: UserSessionId = parent.lock().await.user_session_id();
        let other_target = target();
        let target = target();

        let (first_id, _, _) = *parent
            .lock()
            .await
            .start_target_session(crate::TargetAuthorization::for_test(
                user_info.clone(),
                target.clone(),
                Protocol::Http,
            ))
            .await
            .unwrap()
            .admitted()
            .unwrap();
        let (second_id, _, _) = *parent
            .lock()
            .await
            .start_target_session(crate::TargetAuthorization::for_test(
                user_info.clone(),
                target.clone(),
                Protocol::Http,
            ))
            .await
            .unwrap()
            .admitted()
            .unwrap();
        assert_eq!(first_id, second_id);
        assert_eq!(
            TargetSession::Entity::find()
                .filter(TargetSession::Column::UserSessionId.eq(parent_id.0))
                .count(&db)
                .await
                .unwrap(),
            1
        );

        let (other_id, _, _) = *parent
            .lock()
            .await
            .start_target_session(crate::TargetAuthorization::for_test(
                user_info,
                other_target,
                Protocol::Http,
            ))
            .await
            .unwrap()
            .admitted()
            .unwrap();
        assert_ne!(first_id, other_id);
        assert_eq!(
            TargetSession::Entity::find()
                .filter(TargetSession::Column::UserSessionId.eq(parent_id.0))
                .count(&db)
                .await
                .unwrap(),
            2
        );
    }

    /// A node adopting a shared session (created elsewhere, or detached here)
    /// starts with an empty in-memory slot map; the live target-session row
    /// must be adopted, not duplicated.
    #[tokio::test]
    async fn adopted_user_session_reuses_the_live_target_session_row() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let rate_limiters = Arc::new(Mutex::new(RateLimiterRegistry::new(db.clone())));
        let state = State::new(&db, &rate_limiters, warpgate_common::NodeId(Uuid::new_v4()));
        let parent = State::register_user_session(
            &state,
            Protocol::Http,
            UserSessionStateInit {
                remote_address: None,
                handle: Box::new(TestHandle),
            },
        )
        .await
        .unwrap();
        let user_info = AuthStateUserInfo {
            id: Uuid::new_v4(),
            username: "alice".into(),
        };
        let parent_id: UserSessionId = parent.lock().await.user_session_id();
        let target = target();

        let (first_id, _, _) = *parent
            .lock()
            .await
            .start_target_session(crate::TargetAuthorization::for_test(
                user_info.clone(),
                target.clone(),
                Protocol::Http,
            ))
            .await
            .unwrap()
            .admitted()
            .unwrap();

        let adopted = State::adopt_user_session(
            &state,
            parent_id,
            Protocol::Http,
            UserSessionStateInit {
                remote_address: None,
                handle: Box::new(TestHandle),
            },
        )
        .await;
        let (adopted_id, _, _) = *adopted
            .lock()
            .await
            .start_target_session(crate::TargetAuthorization::for_test(
                user_info,
                target,
                Protocol::Http,
            ))
            .await
            .unwrap()
            .admitted()
            .unwrap();

        assert_eq!(first_id, adopted_id);
        assert_eq!(
            TargetSession::Entity::find()
                .filter(TargetSession::Column::UserSessionId.eq(parent_id.0))
                .count(&db)
                .await
                .unwrap(),
            1
        );

        // The adopting view detaching must not end the shared row.
        drop(adopted);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            TargetSession::Entity::find_by_id(first_id.0)
                .one(&db)
                .await
                .unwrap()
                .unwrap()
                .ended
                .is_none()
        );
    }

    /// Which constructor a session registers through — not its protocol — is
    /// what decides whether the row records an owning node, the only thing the
    /// reaper reads. An HTTP session held open by a node-local handle (a
    /// header-borne ticket's) records its owner and so is not swept as an
    /// unbacked orphan.
    #[tokio::test]
    async fn registration_kind_decides_the_owning_node() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let rate_limiters = Arc::new(Mutex::new(RateLimiterRegistry::new(db.clone())));
        let node_id = NodeId(Uuid::new_v4());
        let state = State::new(&db, &rate_limiters, node_id);

        let init = || UserSessionStateInit {
            remote_address: None,
            handle: Box::new(TestHandle),
        };
        let node_of = async |handle: &Arc<Mutex<WarpgateServerHandle>>| {
            let id = handle.lock().await.user_session_id();
            UserSession::Entity::find_by_id(id.0)
                .one(&db)
                .await
                .unwrap()
                .unwrap()
                .node_id
        };

        let cookie_backed = State::register_user_session(&state, Protocol::Http, init())
            .await
            .unwrap();
        assert_eq!(node_of(&cookie_backed).await, None);

        let node_local = State::register_node_local_user_session(&state, Protocol::Http, init())
            .await
            .unwrap();
        assert_eq!(node_of(&node_local).await, Some(node_id.0));
    }

    #[tokio::test]
    async fn direct_target_session_has_independent_state() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let rate_limiters = Arc::new(Mutex::new(RateLimiterRegistry::new(db.clone())));
        let state = State::new(&db, &rate_limiters, warpgate_common::NodeId(Uuid::new_v4()));
        let parent = State::register_user_session(
            &state,
            Protocol::Ssh,
            UserSessionStateInit {
                remote_address: None,
                handle: Box::new(TestHandle),
            },
        )
        .await
        .unwrap();
        let user_info = AuthStateUserInfo {
            id: Uuid::new_v4(),
            username: "alice".into(),
        };
        parent
            .lock()
            .await
            .set_user_info(user_info.clone())
            .await
            .unwrap();
        let parent_id = parent.lock().await.id();
        let target = target();
        let wrong_user = AuthStateUserInfo {
            id: Uuid::new_v4(),
            username: "mallory".into(),
        };
        assert!(
            parent
                .lock()
                .await
                .start_target_session(crate::TargetAuthorization::for_test(
                    wrong_user,
                    target.clone(),
                    Protocol::Ssh,
                ))
                .await
                .is_err()
        );
        assert!(
            parent
                .lock()
                .await
                .start_target_session(crate::TargetAuthorization::for_test(
                    user_info.clone(),
                    target.clone(),
                    Protocol::Http,
                ))
                .await
                .is_err()
        );
        let (target_session_id, approved, _) = *parent
            .lock()
            .await
            .start_target_session(crate::TargetAuthorization::for_test(
                user_info.clone(),
                target.clone(),
                Protocol::Ssh,
            ))
            .await
            .unwrap()
            .admitted()
            .unwrap();
        assert_eq!(target_session_id.0, parent_id.0);
        assert_eq!(approved.target(), &target);

        let target_state = state
            .lock()
            .await
            .target_sessions
            .get(&target_session_id)
            .cloned()
            .unwrap();
        let target_state = target_state.lock().await;
        assert_eq!(target_state.user_session_id, parent_id);
        assert_eq!(target_state.user_info, user_info);
        assert_eq!(target_state.target, target);
        drop(target_state);

        let (again_id, _, _) = *parent
            .lock()
            .await
            .start_target_session(crate::TargetAuthorization::for_test(
                user_info,
                target,
                Protocol::Ssh,
            ))
            .await
            .unwrap()
            .admitted()
            .unwrap();
        assert_eq!(again_id, target_session_id);
    }
}

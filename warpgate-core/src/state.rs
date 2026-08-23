use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use time::OffsetDateTime;
use tokio::sync::{Mutex, broadcast};
use tracing::error;
use uuid::Uuid;
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{Protocol, Target, TargetSessionId, UserSessionId, WarpgateError};
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
    // Node IDs are random
    node_id: Uuid,
    rate_limiter_registry: Arc<Mutex<RateLimiterRegistry>>,
    change_sender: broadcast::Sender<()>,
}

impl State {
    pub fn new(
        db: &DatabaseConnection,
        rate_limiter_registry: &Arc<Mutex<RateLimiterRegistry>>,
        node_id: Uuid,
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

    pub async fn register_user_session(
        this: &Arc<Mutex<Self>>,
        protocol: Protocol,
        state: UserSessionStateInit,
    ) -> Result<Arc<Mutex<WarpgateServerHandle>>, WarpgateError> {
        let mut self_ = this.lock().await;
        let id = UserSessionId(Uuid::new_v4());

        let state = Arc::new(Mutex::new(UserSessionState::new(
            state,
            self_.change_sender.clone(),
        )));

        {
            use sea_orm::ActiveValue::Set;

            let values = UserSession::ActiveModel {
                id: Set(id.0),
                started: Set(OffsetDateTime::now_utc()),
                remote_address: Set(state
                    .lock()
                    .await
                    .remote_address
                    .map_or_else(String::new, |x| x.to_string())),
                protocol: Set(protocol.to_string()),
                node_id: Set(self_.node_id),
                ..Default::default()
            };

            let db = &self_.db;
            values
                .insert(db)
                .await
                .context("Error inserting session")
                .map_err(WarpgateError::from)?;
        }

        Ok(self_.install_user_session(this, id, state, protocol))
    }

    /// Registers a node-local view over an existing DB-backed user session — an
    /// HTTP browser session created on another node. No row is inserted; the
    /// caller has validated the row. The local handle's drop detaches rather
    /// than ends the session ([`WarpgateServerHandle`] does this for HTTP).
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
        self_.install_user_session(this, id, state, protocol)
    }

    fn install_user_session(
        &mut self,
        owner: &Arc<Mutex<Self>>,
        id: UserSessionId,
        state: Arc<Mutex<UserSessionState>>,
        protocol: Protocol,
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

    /// Creates the target-session row and in-memory state. The caller holds
    /// the parent's state lock (see the lock-order note on
    /// [`WarpgateServerHandle::start_target_session`]) and stores the returned
    /// handle in the parent's slot map.
    pub(crate) async fn create_target_session(
        this: &Arc<Mutex<Self>>,
        user_session_id: UserSessionId,
        id: TargetSessionId,
        target: &Target,
        parent: &UserSessionState,
    ) -> Result<TargetSessionHandle, WarpgateError> {
        let user_info = parent.user_info.clone().ok_or_else(|| {
            WarpgateError::InconsistentState(
                "target session created before user authentication".into(),
            )
        })?;

        let target_state = Arc::new(Mutex::new(TargetSessionState {
            user_session_id,
            user_info,
            target: target.clone(),
            change_sender: parent.change_sender.clone(),
            rate_limiter_handles: parent.rate_limiter_handles.clone(),
        }));

        let mut self_ = this.lock().await;
        self_.insert_target_session(this, id, target_state).await
    }

    async fn insert_target_session(
        &mut self,
        owner: &Arc<Mutex<Self>>,
        id: TargetSessionId,
        state: Arc<Mutex<TargetSessionState>>,
    ) -> Result<TargetSessionHandle, WarpgateError> {
        use sea_orm::ActiveValue::Set;

        let state_guard = state.lock().await;
        let user_session_id = state_guard.user_session_id;
        let user_info = state_guard.user_info.clone();
        let target = state_guard.target.clone();
        let mut snapshot = serde_json::to_value(&target)?;
        warpgate_common::redact_target_secrets(&mut snapshot);
        TargetSession::ActiveModel {
            id: Set(id.0),
            user_session_id: Set(user_session_id.0),
            target_snapshot: Set(snapshot.to_string()),
            target_id: Set(target.id),
            started: Set(OffsetDateTime::now_utc()),
            ended: Set(None),
            ticket_id: Set(None),
            node_id: Set(self.node_id),
        }
        .insert(&self.db)
        .await?;
        drop(state_guard);
        self.target_sessions.insert(id, state.clone());
        let _ = self.change_sender.send(());

        AuditEvent::TargetSessionStarted {
            session_id: id.0,
            target_id: target.id,
            target_name: target.name,
            user_id: user_info.id,
            username: user_info.username,
        }
        .emit();

        Ok(TargetSessionHandle::new(
            id,
            user_session_id,
            owner.clone(),
            state,
            self.rate_limiter_registry.clone(),
        ))
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
        let Some(_session_state) = self.user_sessions.remove(&id) else {
            return;
        };

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

    #[tokio::test]
    async fn user_session_reuses_its_target_session_per_target() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let rate_limiters = Arc::new(Mutex::new(RateLimiterRegistry::new(db.clone())));
        let state = State::new(&db, &rate_limiters, Uuid::new_v4());
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

    #[tokio::test]
    async fn direct_target_session_has_independent_state() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let rate_limiters = Arc::new(Mutex::new(RateLimiterRegistry::new(db.clone())));
        let state = State::new(&db, &rate_limiters, Uuid::new_v4());
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
        assert_eq!(again_id, target_session_id
        );
    }
}

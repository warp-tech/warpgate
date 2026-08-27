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
use warpgate_common::{NodeId, Protocol, Target, UserSessionId, WarpgateError};
use warpgate_db_entities::{TargetSession, UserSession};

use crate::rate_limiting::{RateLimiterRegistry, RateLimiterStackHandle};
use crate::{SessionHandle, WarpgateServerHandle};

pub struct State {
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
            user_sessions: HashMap::new(),
            db: db.clone(),
            node_id,
            rate_limiter_registry: rate_limiter_registry.clone(),
            change_sender: sender,
        }))
    }

    /// Registers a session with no owning node: it is a DB record any node
    /// may serve, kept alive by its own backing rather than this node's
    /// handle (a stored browser cookie session). The row's `node_id` is left
    /// unset — the only kind of session for which the orphan reaper looks
    /// elsewhere for liveness instead of this node's registration.
    pub async fn register_nonlocal_user_session(
        this: &Arc<Mutex<Self>>,
        protocol: Protocol,
        state: UserSessionStateInit,
    ) -> Result<Arc<Mutex<WarpgateServerHandle>>, WarpgateError> {
        Self::register_user_session_in(this, protocol, false, state).await
    }

    /// Registers a session bound to this node: it is kept alive by this
    /// node's handle alone, so the row must record an owner — unowned it
    /// would back nothing and the orphan reaper would end it mid-use.
    pub async fn register_node_local_user_session(
        this: &Arc<Mutex<Self>>,
        protocol: Protocol,
        state: UserSessionStateInit,
    ) -> Result<Arc<Mutex<WarpgateServerHandle>>, WarpgateError> {
        Self::register_user_session_in(this, protocol, true, state).await
    }

    async fn register_user_session_in(
        this: &Arc<Mutex<Self>>,
        protocol: Protocol,
        node_owned: bool,
        state: UserSessionStateInit,
    ) -> Result<Arc<Mutex<WarpgateServerHandle>>, WarpgateError> {
        let mut self_ = this.lock().await;
        let id = UserSessionId(Uuid::new_v4());

        // Read before the state is shared: locking a `UserSessionState` while
        // holding `State` is the reverse of the order everything else takes,
        // and is only safe here because nothing else can reach this one yet.
        // Not relying on that keeps the order true without an exception.
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
                id: Set(id),
                started: Set(OffsetDateTime::now_utc()),
                remote_address: Set(remote_address),
                protocol: Set(protocol.to_string()),
                // An unowned session is served by any node; recording an owner
                // would make the reaper end it when this node goes away.
                node_id: Set(node_owned.then_some(self_.node_id)),
                ..Default::default()
            };

            let db = &self_.db;
            values
                .insert(db)
                .await
                .context("Error inserting session")
                .map_err(WarpgateError::from)?;
        }

        Ok(self_.install_user_session(this, id, state, protocol, node_owned))
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
        let handle = Self::register_node_local_user_session(this, protocol, state).await?;
        let wrapped = handle.lock().await.wrap_stream(stream).await?;
        Ok((handle, wrapped))
    }

    /// Registers a node-local view over an existing DB-backed user session — an
    /// HTTP browser session created on another node. No row is inserted; the
    /// caller has validated the row. The local handle's drop detaches rather
    /// than ends the session ([`WarpgateServerHandle`] does this for unowned
    /// sessions).
    ///
    /// Never node-owned: only a stored-cookie session has a row to re-attach
    /// to — a node-local session lives and dies with its one owning node and
    /// is never adopted.
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
        self_.install_user_session(this, id, state, protocol, false)
    }

    fn install_user_session(
        &mut self,
        owner: &Arc<Mutex<Self>>,
        id: UserSessionId,
        state: Arc<Mutex<UserSessionState>>,
        protocol: Protocol,
        node_owned: bool,
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
            node_owned,
            self.node_id,
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
        self.user_sessions.remove(&id);

        if let Err(error) = TargetSession::Entity::delete_many()
            .filter(TargetSession::Column::UserSessionId.eq(id))
            .exec(&self.db)
            .await
        {
            error!(%error, %id, "Could not delete the session's target sessions from the DB");
        }
        if let Err(error) = UserSession::Entity::delete_by_id(id).exec(&self.db).await {
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

    pub async fn remove_session(&mut self, id: UserSessionId) {
        // The row is ended whether or not this node still holds the state: a
        // handle dropped just before this call detaches the entry without
        // ending anything, and ending the row is the whole point of the call.
        self.user_sessions.remove(&id);

        if let Err(error) = UserSession::mark_ended_including_target_sessions(&self.db, id).await {
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
    /// The target this session's connection streams are limited against.
    /// Set when a target session starts and never unset — a stream serves at
    /// most one target for its whole life.
    pub target: Option<Target>,
    change_sender: broadcast::Sender<()>,
    pub rate_limiter_handles: Vec<RateLimiterStackHandle>,
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
            target: None,
            change_sender,
            rate_limiter_handles: vec![],
        }
    }

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
        let parent = State::register_nonlocal_user_session(
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
        UserSession::mark_ended_including_target_sessions(&db, parent_id)
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

    #[tokio::test]
    async fn target_open_racing_session_end_cannot_leave_an_open_access() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let rate_limiters = Arc::new(Mutex::new(RateLimiterRegistry::new(db.clone())));
        let state = State::new(&db, &rate_limiters, NodeId(Uuid::new_v4()));
        let parent = State::register_nonlocal_user_session(
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
        let access_target = target();

        let opening = TargetSession::open_or_lookup(
            &db,
            warpgate_common::TargetSessionId(Uuid::new_v4()),
            parent_id,
            &access_target,
            None,
            None,
            &user_info,
        );
        let ending = UserSession::mark_ended_including_target_sessions(&db, parent_id);
        let (opened, ended) = tokio::join!(opening, ending);

        ended.unwrap();
        assert!(opened.is_ok() || matches!(opened, Err(WarpgateError::UserSessionEnded)));
        assert_eq!(
            TargetSession::Entity::find()
                .filter(TargetSession::Column::UserSessionId.eq(parent_id))
                .filter(TargetSession::Column::Ended.is_null())
                .count(&db)
                .await
                .unwrap(),
            0
        );
    }

    /// Dropping the last handle of a node-owned session ends the session and
    /// every access recorded under it — the audit trail's "ended" comes from
    /// this, not from any per-access teardown.
    #[tokio::test]
    async fn dropping_the_handle_ends_the_session_and_its_accesses() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let rate_limiters = Arc::new(Mutex::new(RateLimiterRegistry::new(db.clone())));
        let state = State::new(&db, &rate_limiters, NodeId(Uuid::new_v4()));
        let parent = State::register_node_local_user_session(
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

        let (target_session_id, _approved) = parent
            .lock()
            .await
            .start_target_session(crate::TargetAuthorization::for_test(
                user_info,
                target(),
                Protocol::Ssh,
            ))
            .await
            .unwrap()
            .admitted()
            .unwrap();

        // The only reference the connection would have held.
        drop(parent);

        // Teardown runs on a spawned task; poll for it.
        for _ in 0..50 {
            let child = TargetSession::Entity::find_by_id(target_session_id)
                .one(&db)
                .await
                .unwrap()
                .unwrap();
            if child.ended.is_some() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("target session row was not ended");
    }

    #[tokio::test]
    async fn user_session_reuses_its_target_session_per_target() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let rate_limiters = Arc::new(Mutex::new(RateLimiterRegistry::new(db.clone())));
        let state = State::new(&db, &rate_limiters, warpgate_common::NodeId(Uuid::new_v4()));
        let parent = State::register_nonlocal_user_session(
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

        let (first_id, _) = parent
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
        let (second_id, _) = parent
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
                .filter(TargetSession::Column::UserSessionId.eq(parent_id))
                .count(&db)
                .await
                .unwrap(),
            1
        );

        let (other_id, _) = parent
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
                .filter(TargetSession::Column::UserSessionId.eq(parent_id))
                .count(&db)
                .await
                .unwrap(),
            2
        );
    }

    /// A node adopting a shared session (created elsewhere, or detached here)
    /// has no memory of the row another node already recorded for this target;
    /// the unique (user session, target) pair makes it reuse that row rather
    /// than record a duplicate.
    #[tokio::test]
    async fn adopted_user_session_reuses_the_live_target_session_row() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let rate_limiters = Arc::new(Mutex::new(RateLimiterRegistry::new(db.clone())));
        let state = State::new(&db, &rate_limiters, warpgate_common::NodeId(Uuid::new_v4()));
        let parent = State::register_nonlocal_user_session(
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

        let (first_id, _) = parent
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
        let (adopted_id, _) = adopted
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
                .filter(TargetSession::Column::UserSessionId.eq(parent_id))
                .count(&db)
                .await
                .unwrap(),
            1
        );

        // The adopting view detaching must not end the shared row.
        drop(adopted);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            TargetSession::Entity::find_by_id(first_id)
                .one(&db)
                .await
                .unwrap()
                .unwrap()
                .ended
                .is_none()
        );
    }

    #[tokio::test]
    async fn nodes_racing_a_shared_target_session_adopt_one_row() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let rate_limiters = Arc::new(Mutex::new(RateLimiterRegistry::new(db.clone())));
        let first_state = State::new(&db, &rate_limiters, NodeId(Uuid::new_v4()));
        let second_state = State::new(&db, &rate_limiters, NodeId(Uuid::new_v4()));
        let first_parent = State::register_nonlocal_user_session(
            &first_state,
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
        first_parent
            .lock()
            .await
            .set_user_info(user_info.clone())
            .await
            .unwrap();
        let parent_id = first_parent.lock().await.user_session_id();
        let second_parent = State::adopt_user_session(
            &second_state,
            parent_id,
            Protocol::Http,
            UserSessionStateInit {
                remote_address: None,
                handle: Box::new(TestHandle),
            },
        )
        .await;
        let target = target();
        let first_authorization =
            crate::TargetAuthorization::for_test(user_info.clone(), target.clone(), Protocol::Http);
        let second_authorization =
            crate::TargetAuthorization::for_test(user_info, target, Protocol::Http);

        let first = async {
            first_parent
                .lock()
                .await
                .start_target_session(first_authorization)
                .await
                .unwrap()
                .admitted()
                .unwrap()
                .0
        };
        let second = async {
            second_parent
                .lock()
                .await
                .start_target_session(second_authorization)
                .await
                .unwrap()
                .admitted()
                .unwrap()
                .0
        };
        let (first_id, second_id) = tokio::join!(first, second);

        assert_eq!(first_id, second_id);
        assert_eq!(
            TargetSession::Entity::find()
                .filter(TargetSession::Column::UserSessionId.eq(parent_id))
                .count(&db)
                .await
                .unwrap(),
            1
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
            UserSession::Entity::find_by_id(id)
                .one(&db)
                .await
                .unwrap()
                .unwrap()
                .node_id
        };

        let cookie_backed = State::register_nonlocal_user_session(&state, Protocol::Http, init())
            .await
            .unwrap();
        assert_eq!(node_of(&cookie_backed).await, None);

        let node_local = State::register_node_local_user_session(&state, Protocol::Http, init())
            .await
            .unwrap();
        assert_eq!(node_of(&node_local).await, Some(node_id));
    }

    #[tokio::test]
    async fn direct_target_session_has_independent_state() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let rate_limiters = Arc::new(Mutex::new(RateLimiterRegistry::new(db.clone())));
        let state = State::new(&db, &rate_limiters, warpgate_common::NodeId(Uuid::new_v4()));
        let parent = State::register_node_local_user_session(
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
        let parent_id = parent.lock().await.user_session_id();
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
        let (target_session_id, approved) = parent
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
        assert_eq!(approved.target(), &target);
        let row = TargetSession::Entity::find_by_id(target_session_id)
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.user_session_id, parent_id);
        // The ids are independent: nothing may rely on a child sharing its
        // parent's UUID.
        assert_ne!(target_session_id.0, parent_id.0);

        let (again_id, _) = parent
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

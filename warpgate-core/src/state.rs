use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait};
use time::OffsetDateTime;
use tokio::sync::{Mutex, broadcast};
use tracing::error;
use uuid::Uuid;
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{Protocol, SessionId, Target, WarpgateError};
use warpgate_db_entities::Session;

use crate::approvals::AdminApprovalStatuses;
use crate::logging::AuditEvent;
use crate::rate_limiting::{RateLimiterRegistry, RateLimiterStackHandle};
use crate::{SessionHandle, WarpgateServerHandle};

pub struct State {
    pub sessions: HashMap<SessionId, Arc<Mutex<SessionState>>>,
    db: DatabaseConnection,
    // Node IDs are random
    node_id: Uuid,
    rate_limiter_registry: Arc<Mutex<RateLimiterRegistry>>,
    change_sender: broadcast::Sender<()>,
    /// Administrator-gate outcomes for sessions that observe the gate rather
    /// than parking on it. Kept here because an entry describes one connection
    /// and must be dropped with it, which is what this type already tracks.
    admin_approval_statuses: AdminApprovalStatuses,
}

impl State {
    pub fn new(
        db: &DatabaseConnection,
        rate_limiter_registry: &Arc<Mutex<RateLimiterRegistry>>,
        node_id: Uuid,
    ) -> Arc<Mutex<Self>> {
        let sender = broadcast::channel(2).0;
        Arc::new(Mutex::new(Self {
            sessions: HashMap::new(),
            db: db.clone(),
            node_id,
            rate_limiter_registry: rate_limiter_registry.clone(),
            change_sender: sender,
            admin_approval_statuses: AdminApprovalStatuses::default(),
        }))
    }

    /// Handle to the administrator-gate outcomes, for the wait sites that
    /// record them.
    pub fn admin_approval_statuses(&self) -> AdminApprovalStatuses {
        self.admin_approval_statuses.clone()
    }

    pub async fn register_session(
        this: &Arc<Mutex<Self>>,
        protocol: Protocol,
        state: SessionStateInit,
    ) -> Result<Arc<Mutex<WarpgateServerHandle>>, WarpgateError> {
        let this_copy = this.clone();
        let mut self_ = this.lock().await;
        let id = uuid::Uuid::new_v4();

        let state = Arc::new(Mutex::new(SessionState::new(
            state,
            self_.change_sender.clone(),
        )));

        self_.sessions.insert(id, state.clone());

        {
            use sea_orm::ActiveValue::Set;

            let values = Session::ActiveModel {
                id: Set(id),
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

        let _ = self_.change_sender.send(());

        Ok(Arc::new(Mutex::new(WarpgateServerHandle::new(
            id,
            self_.db.clone(),
            this_copy,
            state,
            self_.rate_limiter_registry.clone(),
        ))))
    }

    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.change_sender.subscribe()
    }

    /// Removes a session that never completed authentication, deleting its row
    /// rather than marking it ended — see
    /// [`WarpgateServerHandle::mark_provisional`].
    pub async fn discard_session(&mut self, id: SessionId) {
        self.sessions.remove(&id);

        if let Err(error) = Session::Entity::delete_by_id(id).exec(&self.db).await {
            error!(%error, %id, "Could not delete session from the DB");
        }

        self.drop_session_approvals(id).await;

        let _ = self.change_sender.send(());
    }

    /// Forgets everything an approval decision could still be applied to once a
    /// session is over. The connection is gone, so a decision can never reach
    /// it — but a pending request left behind would keep sitting in the
    /// approval queues, where approving it would still stamp a grace-period
    /// bypass, and a gate outcome left behind describes a connection a later
    /// session must not inherit.
    ///
    /// The requests are closed, not removed: they stay as the record of what
    /// was asked, and are pruned with the rest of the audit trail.
    async fn drop_session_approvals(&self, id: SessionId) {
        if let Err(error) = crate::approvals::abandon_requests_for_session(&self.db, id).await {
            error!(%error, %id, "Could not close the session's approval requests");
        }
        self.admin_approval_statuses.lock().await.remove(&id);
    }

    pub async fn remove_session(&mut self, id: SessionId) {
        if let Some(session_state) = self.sessions.remove(&id) {
            let state_guard = session_state.lock().await;
            if let (Some(user_info), Some(target)) = (&state_guard.user_info, &state_guard.target) {
                AuditEvent::TargetSessionEnded {
                    session_id: id,
                    target_id: target.id,
                    target_name: target.name.clone(),
                    user_id: user_info.id,
                    username: user_info.username.clone(),
                }
                .emit();
            }
        }

        if let Err(error) = crate::db::mark_session_ended(&self.db, id).await {
            error!(%error, %id, "Could not update session in the DB");
        }

        self.drop_session_approvals(id).await;

        let _ = self.change_sender.send(());
    }
}

pub struct SessionState {
    pub remote_address: Option<SocketAddr>,
    pub user_info: Option<AuthStateUserInfo>,
    pub target: Option<Target>,
    pub handle: Box<dyn SessionHandle + Send + Sync>,
    change_sender: broadcast::Sender<()>,
    pub rate_limiter_handles: Vec<RateLimiterStackHandle>,
}

pub struct SessionStateInit {
    pub remote_address: Option<SocketAddr>,
    pub handle: Box<dyn SessionHandle + Send + Sync>,
}

impl SessionState {
    fn new(init: SessionStateInit, change_sender: broadcast::Sender<()>) -> Self {
        Self {
            remote_address: init.remote_address,
            user_info: None,
            target: None,
            handle: init.handle,
            change_sender,
            rate_limiter_handles: vec![],
        }
    }

    pub fn emit_change(&self) {
        let _ = self.change_sender.send(());
    }
}

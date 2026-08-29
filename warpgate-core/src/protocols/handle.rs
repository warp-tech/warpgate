use std::sync::Arc;

use sea_orm::{ColumnTrait, Condition, DatabaseConnection, EntityTrait, QueryFilter};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tracing::{Instrument, info_span};
use uuid::Uuid;
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{NodeId, Protocol, Target, TargetSessionId, UserSessionId, WarpgateError};
use warpgate_db_entities::TargetSession::TargetSessionOpenOutcome;
use warpgate_db_entities::{TargetSession, UserSession};

use crate::rate_limiting::{RateLimiterRegistry, stack_rate_limiters};
use crate::{ApprovedTarget, State, TargetAuthorization, UserSessionState};

pub trait SessionHandle {
    fn close(&mut self);
}

// Deliberately not Clone: `Drop` tears the session down, so a second copy
// would end the session while the first is still proxying. Share via the
// surrounding `Arc<Mutex<..>>` instead.
pub struct WarpgateServerHandle {
    user_session_id: UserSessionId,
    db: DatabaseConnection,
    state: Arc<Mutex<State>>,
    user_session_state: Arc<Mutex<UserSessionState>>,
    rate_limiters_registry: Arc<Mutex<RateLimiterRegistry>>,
    protocol: Protocol,
    /// is this session's lifetime bound to this node?
    /// Often no for HTTP (cookie session), otherwise yes
    node_owned: bool,
    node_id: NodeId,
    provisional: bool,
}

impl WarpgateServerHandle {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        user_session_id: UserSessionId,
        db: DatabaseConnection,
        state: Arc<Mutex<State>>,
        user_session_state: Arc<Mutex<UserSessionState>>,
        rate_limiters_registry: Arc<Mutex<RateLimiterRegistry>>,
        protocol: Protocol,
        node_owned: bool,
        node_id: NodeId,
    ) -> Self {
        Self {
            user_session_id,
            db,
            state,
            user_session_state,
            rate_limiters_registry,
            protocol,
            node_owned,
            node_id,
            provisional: false,
        }
    }

    pub const fn user_session_id(&self) -> UserSessionId {
        self.user_session_id
    }

    /// Marks a session that was registered before its authentication finished
    /// (so that it is addressable across the cluster while a web approval is
    /// pending). Dropping the handle while still provisional deletes the
    /// session instead of ending it, so an attempt that never became a session
    /// leaves nothing behind.
    pub const fn mark_provisional(&mut self) {
        self.provisional = true;
    }

    /// Turns a provisional session into a real one.
    pub const fn confirm(&mut self) {
        self.provisional = false;
    }

    pub const fn user_session_state(&self) -> &Arc<Mutex<UserSessionState>> {
        &self.user_session_state
    }

    pub async fn set_user_info(&self, user_info: AuthStateUserInfo) -> Result<(), WarpgateError> {
        {
            // Kubernetes reuses one session handle for many concurrent requests, so
            // most calls are no-ops, and the lock must span the no-op check and the
            // commit to keep the DB and in-memory state consistent.
            let mut state = self.user_session_state.lock().await;
            self.set_user_info_in(&mut state, user_info).await?;
        }

        self.update_rate_limiters().await
    }

    async fn set_user_info_in(
        &self,
        state: &mut UserSessionState,
        user_info: AuthStateUserInfo,
    ) -> Result<(), WarpgateError> {
        use sea_orm::ActiveValue::Set;

        if state.user_info.as_ref() == Some(&user_info) {
            return Ok(());
        }

        // The row itself carries the invariant: a node that adopted this
        // session has no in-memory identity to compare against, so an
        // unguarded write would let a login on someone else's still-valid
        // cookie re-attribute their sessions and audit history.
        let result = UserSession::Entity::update_many()
            .set(UserSession::ActiveModel {
                username: Set(Some(user_info.username.clone())),
                user_id: Set(Some(user_info.id)),
                ..Default::default()
            })
            .filter(UserSession::Column::Id.eq(self.user_session_id))
            .filter(
                Condition::any()
                    .add(UserSession::Column::UserId.is_null())
                    .add(UserSession::Column::UserId.eq(user_info.id)),
            )
            .exec(&self.db)
            .await?;
        if result.rows_affected == 0 {
            return Err(WarpgateError::UserSessionAlreadyAttributed);
        }

        state.user_info = Some(user_info);
        state.emit_change();
        Ok(())
    }

    pub async fn start_target_session<O>(
        &mut self,
        authorization: TargetAuthorization<O>,
    ) -> Result<TargetSessionStart<O>, WarpgateError> {
        self.stamp_target_session_identity(&authorization).await?;

        if self.needs_target_approval(authorization.target()).await? {
            return Ok(TargetSessionStart::NeedsApproval(authorization));
        }

        let id = self.open_target_session_row(&authorization).await?;
        Ok(TargetSessionStart::Started((
            id,
            ApprovedTarget::new(authorization),
        )))
    }

    /// Starts a target session for a proof the administrator gate minted.
    ///
    /// The gate is the only other source of [`ApprovedTarget`], so between this
    /// and [`Self::start_target_session`] every admission — gated or not — goes
    /// through the same row and the same audit event.
    pub async fn register_approved_target_session<O>(
        &self,
        approved: &ApprovedTarget<O>,
    ) -> Result<TargetSessionId, WarpgateError> {
        self.stamp_target_session_identity(approved).await?;
        self.open_target_session_row(approved).await
    }

    async fn stamp_target_session_identity<O>(
        &self,
        authorization: &TargetAuthorization<O>,
    ) -> Result<(), WarpgateError> {
        if authorization.protocol() != self.protocol {
            return Err(WarpgateError::InconsistentState(
                "target authorization protocol does not match the user session".into(),
            ));
        }

        {
            let mut parent = self.user_session_state.lock().await;
            if parent.user_info.is_none() {
                self.set_user_info_in(&mut parent, authorization.user_info().clone())
                    .await?;
            } else if parent.user_info.as_ref() != Some(authorization.user_info()) {
                return Err(WarpgateError::InconsistentState(
                    "target authorization user does not match the user session".into(),
                ));
            }
            parent.target = Some(authorization.target().clone());
        }
        self.update_rate_limiters().await
    }

    async fn open_target_session_row<O>(
        &self,
        authorization: &TargetAuthorization<O>,
    ) -> Result<TargetSessionId, WarpgateError> {
        let outcome = TargetSession::open_or_lookup(
            &self.db,
            TargetSessionId(Uuid::new_v4()),
            self.user_session_id,
            authorization.target(),
            self.node_owned.then_some(self.node_id),
            authorization.ticket_id(),
            authorization.user_info(),
        )
        .await?;

        let target_session = match outcome {
            TargetSessionOpenOutcome::Created(model) => {
                self.user_session_state.lock().await.emit_change();

                model
            }
            TargetSessionOpenOutcome::AlreadyExists(model) => model,
        };
        Ok(target_session.id)
    }

    async fn needs_target_approval(&self, target: &Target) -> Result<bool, WarpgateError> {
        if !target.require_approval {
            return Ok(false);
        }
        // skip the check if there is already a matching open target session in this user session
        Ok(!TargetSession::is_open(&self.db, self.user_session_id, target.id).await?)
    }

    /// Wraps a client stream, adding rate limiters. Wrapping happens at connection time
    /// and the limiters are swapped out later. See [State::register_user_session_with_stream]
    pub(crate) async fn wrap_stream<S>(
        &self,
        stream: S,
    ) -> Result<impl AsyncRead + AsyncWrite + Unpin + Send + use<S>, WarpgateError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let (stream, handle) = stack_rate_limiters(stream);
        let mut state = self.user_session_state.lock().await;
        self.rate_limiters_registry
            .lock()
            .await
            .update_user_rate_limiter(state.user_info.as_ref(), &handle)
            .await?;
        state.rate_limiter_handles.push(handle);
        Ok(stream)
    }

    async fn update_rate_limiters(&self) -> Result<(), WarpgateError> {
        let mut state = self.user_session_state.lock().await;
        let mut registry = self.rate_limiters_registry.lock().await;
        registry.update_session_rate_limiters(&mut state).await?;
        Ok(())
    }
}

/// Target session start outcome.
///
/// `NeedsApproval` hands the authorization back: the caller takes it to the
/// administrator gate ([`Services::require_admin_approval`] or
/// [`Services::poll_admin_approval`]), and registers the proof the gate mints
/// via [`WarpgateServerHandle::register_approved_target_session`].
///
/// [`Services::require_admin_approval`]: crate::Services::require_admin_approval
/// [`Services::poll_admin_approval`]: crate::Services::poll_admin_approval
pub enum TargetSessionStart<O> {
    Started((TargetSessionId, ApprovedTarget<O>)),
    NeedsApproval(TargetAuthorization<O>),
}

#[cfg(test)]
impl<O> TargetSessionStart<O> {
    /// For tests that set up an ungated target and only care about the row.
    ///
    /// Deliberately test-only: in production every caller answers
    /// `NeedsApproval` by holding the connection at the gate, and a shorthand
    /// for turning it into an error is a shorthand for skipping the gate.
    pub(crate) fn started(self) -> (TargetSessionId, ApprovedTarget<O>) {
        match self {
            Self::Started(started) => started,
            Self::NeedsApproval(_) => panic!("the test target should not require approval"),
        }
    }
}

impl Drop for WarpgateServerHandle {
    fn drop(&mut self) {
        let id = self.user_session_id;
        let state = self.state.clone();
        let user_session_state = self.user_session_state.clone();
        let provisional = self.provisional;
        let protocol = self.protocol;

        // Unowned sessions are managed by their backing (HTTP session store);
        // this handle is just a node-local view
        let end_user_session_on_drop = self.node_owned;
        tokio::spawn(async move {
            if provisional {
                state.lock().await.discard_session(id).await;
                return;
            }
            if !end_user_session_on_drop {
                state
                    .lock()
                    .await
                    .detach_user_session(id, &user_session_state);
                return;
            }
            // session ID from the span is needed for the audit log to get stored in the DB
            let username = user_session_state
                .lock()
                .await
                .user_info
                .as_ref()
                .map_or_else(String::new, |x| x.username.clone());
            let span = info_span!("Teardown", protocol=protocol.name(), session=%id, session_username=%username);
            state.lock().await.remove_session(id).instrument(span).await;
        });
    }
}

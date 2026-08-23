use std::sync::Arc;

use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex, broadcast};
use tracing::{Instrument, info_span};
use uuid::Uuid;
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{Protocol, Target, TargetSessionId, UserSessionId, WarpgateError};
use warpgate_db_entities::UserSession;

use crate::rate_limiting::{RateLimiterRegistry, stack_rate_limiters};
use crate::state::TargetSessionSlot;
use crate::{ApprovedTarget, State, TargetAuthorization, TargetSessionState, UserSessionState};

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
    provisional: bool,
    end_user_session_on_drop: bool,
}

impl WarpgateServerHandle {
    pub fn new(
        user_session_id: UserSessionId,
        db: DatabaseConnection,
        state: Arc<Mutex<State>>,
        user_session_state: Arc<Mutex<UserSessionState>>,
        rate_limiters_registry: Arc<Mutex<RateLimiterRegistry>>,
        protocol: Protocol,
    ) -> Self {
        Self {
            user_session_id,
            db,
            state,
            user_session_state,
            rate_limiters_registry,
            protocol,
            provisional: false,
            // HTTP browser sessions are DB-backed and can be active on several
            // nodes. Their DB lifetime is ended by the Poem session storage,
            // not by one node dropping its local handle.
            end_user_session_on_drop: protocol != Protocol::Http,
        }
    }

    /// The parent login/session id. Target connections have their own ids,
    /// carried by the [`TargetSessionHandle`] a start returns.
    pub const fn id(&self) -> UserSessionId {
        self.user_session_id
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
        use sea_orm::ActiveValue::Set;

        {
            // Kubernetes reuses one session handle for many concurrent requests, so
            // most calls are no-ops, and the lock must span the no-op check and the
            // commit to keep the DB and in-memory state consistent.
            let mut state = self.user_session_state.lock().await;
            if state.user_info.as_ref() == Some(&user_info) {
                return Ok(());
            }

            UserSession::Entity::update_many()
                .set(UserSession::ActiveModel {
                    username: Set(Some(user_info.username.clone())),
                    user_id: Set(Some(user_info.id)),
                    ..Default::default()
                })
                .filter(UserSession::Column::Id.eq(self.user_session_id.0))
                .exec(&self.db)
                .await?;

            state.user_info = Some(user_info);
            state.emit_change();
        }

        self.update_user_rate_limiters().await
    }

    /// The user session's target session for the authorized target, opening
    /// one if none is live: a user session never has two target sessions to
    /// the same target, so a repeat call admits the caller onto the existing
    /// one. The parent owns the session — it lives until the parent's state is
    /// torn down — and the returned receiver fires (or closes) when it ends,
    /// aborting the requests served through it.
    ///
    /// One-to-one protocols reuse the parent's id for their sole target
    /// session, so recordings, tracing and connection control use one stable
    /// identifier; HTTP children get ids of their own.
    ///
    /// Lock order: an existing `UserSessionState` may be locked before the
    /// global `State`, never after — nothing locks an existing session state
    /// while holding `State`.
    pub async fn start_target_session<O>(
        &mut self,
        authorization: TargetAuthorization<O>,
    ) -> Result<
        TargetSessionStart<Box<(TargetSessionId, ApprovedTarget<O>, broadcast::Receiver<()>)>>,
        WarpgateError,
    > {
        if authorization.protocol() != self.protocol {
            return Err(WarpgateError::InconsistentState(
                "target authorization protocol does not match the user session".into(),
            ));
        }

        let mut parent = self.user_session_state.lock().await;
        if parent.user_info.as_ref() != Some(authorization.user_info()) {
            return Err(WarpgateError::InconsistentState(
                "target authorization user does not match the user session".into(),
            ));
        }

        if let Some(slot) = parent.target_sessions.get(&authorization.target().id) {
            return Ok(TargetSessionStart::Started(Box::new((
                slot.handle.id(),
                ApprovedTarget::new(authorization),
                slot.close_tx.subscribe(),
            ))));
        }

        // Admission applies to opening a session; readmission above is onto
        // one already admitted.
        if self.needs_target_approval(authorization.target()).await? {
            return Ok(TargetSessionStart::NeedsApproval);
        }

        let id = if self.protocol == Protocol::Http {
            TargetSessionId(Uuid::new_v4())
        } else {
            TargetSessionId(self.user_session_id.0)
        };
        let target_session = State::create_target_session(
            &self.state,
            self.user_session_id,
            id,
            authorization.target(),
            &parent,
        )
        .await?;
        target_session.update_rate_limiters().await?;

        let close_tx = broadcast::channel(1).0;
        let close_rx = close_tx.subscribe();
        parent.target_sessions.insert(
            authorization.target().id,
            TargetSessionSlot {
                handle: target_session,
                close_tx,
            },
        );
        Ok(TargetSessionStart::Started(Box::new((
            id,
            ApprovedTarget::new(authorization),
            close_rx,
        ))))
    }

    async fn needs_target_approval(&self, target: &Target) -> Result<bool, WarpgateError> {
        target_session_needs_approval(&self.db, self.user_session_id, target).await
    }

    /// Wraps a connection stream with the user-session rate limiters. Streams
    /// are wrapped at accept time, before any target is known; once a target
    /// session starts, [`State::start_target_session`] moves the handles onto
    /// it and re-derives the limits for the target.
    pub async fn wrap_stream<S>(
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

    async fn update_user_rate_limiters(&self) -> Result<(), WarpgateError> {
        let mut state = self.user_session_state.lock().await;
        let mut registry = self.rate_limiters_registry.lock().await;
        registry
            .update_all_user_session_rate_limiters(&mut state)
            .await?;
        Ok(())
    }
}

/// Policy hook for target-session admission. It currently admits every target;
/// approval policy and remembered approval records belong behind this check.
pub async fn target_session_needs_approval(
    _db: &DatabaseConnection,
    _user_session_id: UserSessionId,
    _target: &Target,
) -> Result<bool, WarpgateError> {
    Ok(false)
}

/// Admission outcome for a target session: direct protocols start
/// `TargetSessionStart<ApprovedTarget>` sessions, HTTP additionally receives
/// the lifetime handle. One shared enum keeps every protocol's
/// pending-approval arm explicit.
pub enum TargetSessionStart<T> {
    Started(T),
    NeedsApproval,
}

impl<T> TargetSessionStart<T> {
    /// The admission, or the pending-approval error — for call sites that
    /// cannot yet hold their session open while an approval is decided.
    pub fn admitted(self) -> Result<T, WarpgateError> {
        match self {
            Self::Started(started) => Ok(started),
            Self::NeedsApproval => Err(WarpgateError::TargetSessionRequiresApproval),
        }
    }
}

/// Lifetime guard for one target connection. Dropping it ends only that child
/// session; the parent user session can continue and start another connection.
pub struct TargetSessionHandle {
    id: TargetSessionId,
    user_session_id: UserSessionId,
    state: Arc<Mutex<State>>,
    session_state: Arc<Mutex<TargetSessionState>>,
    rate_limiters_registry: Arc<Mutex<RateLimiterRegistry>>,
}

impl TargetSessionHandle {
    pub(crate) const fn new(
        id: TargetSessionId,
        user_session_id: UserSessionId,
        state: Arc<Mutex<State>>,
        session_state: Arc<Mutex<TargetSessionState>>,
        rate_limiters_registry: Arc<Mutex<RateLimiterRegistry>>,
    ) -> Self {
        Self {
            id,
            user_session_id,
            state,
            session_state,
            rate_limiters_registry,
        }
    }

    pub const fn id(&self) -> TargetSessionId {
        self.id
    }

    pub const fn user_session_id(&self) -> UserSessionId {
        self.user_session_id
    }

    pub const fn session_state(&self) -> &Arc<Mutex<TargetSessionState>> {
        &self.session_state
    }

    /// Re-derives the rate limits of every stream handle attached to this
    /// target session from the current user and target.
    pub async fn update_rate_limiters(&self) -> Result<(), WarpgateError> {
        let mut state = self.session_state.lock().await;
        let mut registry = self.rate_limiters_registry.lock().await;
        registry
            .update_all_target_session_rate_limiters(&mut state)
            .await?;
        Ok(())
    }
}

impl Drop for TargetSessionHandle {
    fn drop(&mut self) {
        let id = self.id;
        let state = self.state.clone();
        tokio::spawn(async move {
            state.lock().await.remove_target_session(id).await;
        });
    }
}

impl Drop for WarpgateServerHandle {
    fn drop(&mut self) {
        let id = self.user_session_id;
        let state = self.state.clone();
        let user_session_state = self.user_session_state.clone();
        let provisional = self.provisional;
        let end_user_session_on_drop = self.end_user_session_on_drop;
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
            let span = info_span!("SSH", session=%id, session_username=%username);
            state.lock().await.remove_session(id).instrument(span).await;
        });
    }
}

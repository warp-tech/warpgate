use std::sync::Arc;

use sea_orm::{ColumnTrait, Condition, DatabaseConnection, EntityTrait, QueryFilter};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex, broadcast};
use tracing::{Instrument, info_span};
use uuid::Uuid;
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{
    Protocol, SessionLifecycle, Target, TargetSessionId, UserSessionId, WarpgateError,
};
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
            // Shared sessions can be active on several nodes; their DB
            // lifetime is ended by the shared session storage, not by one
            // node dropping its local handle.
            end_user_session_on_drop: protocol.lifecycle() == SessionLifecycle::ConnectionBound,
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
        {
            // Kubernetes reuses one session handle for many concurrent requests, so
            // most calls are no-ops, and the lock must span the no-op check and the
            // commit to keep the DB and in-memory state consistent.
            let mut state = self.user_session_state.lock().await;
            self.set_user_info_in(&mut state, user_info).await?;
        }

        self.update_user_rate_limiters().await
    }

    /// The locked half of [`Self::set_user_info`], for callers already holding
    /// the session state lock. The caller is responsible for refreshing user
    /// rate limiters afterwards (outside the lock).
    ///
    /// A user session's identity is write-once: target sessions and audit
    /// events attribute through the parent row, so changing it would rewrite
    /// who did everything recorded under it. Logging in as someone else
    /// requires a fresh session.
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
            .filter(UserSession::Column::Id.eq(self.user_session_id.0))
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
    ///
    /// The parent lock is held only to read and to publish the slot. Every
    /// database round trip — the liveness checks and, above all, the wait for
    /// an administrator's approval — happens between those two phases, so one
    /// pending target never blocks the login's other requests.
    pub async fn start_target_session<O>(
        &mut self,
        authorization: TargetAuthorization<O>,
    ) -> Result<
        TargetSessionStart<Box<(TargetSessionId, ApprovedTarget<O>, TargetSessionCloseSignal)>>,
        WarpgateError,
    > {
        if authorization.protocol() != self.protocol {
            return Err(WarpgateError::InconsistentState(
                "target authorization protocol does not match the user session".into(),
            ));
        }

        let lifecycle = self.protocol.lifecycle();

        // Phase 1, under the parent lock: stamp the identity and read the
        // slot. Nothing slow happens here — see the lock note below.
        let (existing, user_info_stamped) = {
            let mut parent = self.user_session_state.lock().await;
            // The authorization already carries the authenticated user, so a
            // session whose user was never set explicitly (target-only
            // protocols) is stamped here; one attributed to a different user
            // is refused.
            let user_info_stamped = if parent.user_info.is_none() {
                self.set_user_info_in(&mut parent, authorization.user_info().clone())
                    .await?;
                true
            } else {
                if parent.user_info.as_ref() != Some(authorization.user_info()) {
                    return Err(WarpgateError::InconsistentState(
                        "target authorization user does not match the user session".into(),
                    ));
                }
                false
            };
            let existing = parent
                .target_sessions
                .get(&authorization.target().id)
                .map(|slot| (slot.handle.id(), slot.close_tx.subscribe()));
            (existing, user_info_stamped)
        };
        if user_info_stamped {
            self.update_user_rate_limiters().await?;
        }

        // Phase 2, unlocked: the checks that reach the database. A shared
        // session's row can be ended by another node while this node's slot
        // survives; readmitting onto it would keep serving requests under a
        // closed record — or under a revoked login, which is how an
        // administrative close reaches a node that missed the fan-out. A
        // connection-bound session's row outlives its parent's state by
        // construction, and re-opening one would collide on the shared id, so
        // it is readmitted as-is.
        let target_id = authorization.target().id;
        if let Some((id, close_rx)) = existing {
            if matches!(lifecycle, SessionLifecycle::ConnectionBound)
                || crate::db::target_session_is_servable(&self.db, id).await?
            {
                return Ok(TargetSessionStart::Started(Box::new((
                    id,
                    ApprovedTarget::new(authorization),
                    TargetSessionCloseSignal(close_rx),
                ))));
            }
            // Retire the closed session before opening its replacement, and
            // only if it is still the one in the slot: a request that raced
            // this one may already have put a live session there.
            let mut parent = self.user_session_state.lock().await;
            if parent
                .target_sessions
                .get(&target_id)
                .is_some_and(|slot| slot.handle.id() == id)
            {
                parent.target_sessions.remove(&target_id);
            }
        }

        // Admission applies to opening a session; readmission above is onto
        // one already admitted. Deliberately outside the parent lock: this is
        // the wait for an administrator, and holding the lock across it would
        // block every other request on the same login — including the ones
        // the user needs in order to get the approval answered.
        if self.needs_target_approval(authorization.target()).await? {
            return Ok(TargetSessionStart::NeedsApproval);
        }

        // A shared session outlives the request that opened it, so its login
        // has to be open for a new one to be worth opening at all.
        if matches!(lifecycle, SessionLifecycle::Shared(_))
            && !crate::db::user_session_is_open(&self.db, self.user_session_id).await?
        {
            return Err(WarpgateError::UserSessionEnded);
        }

        // Phase 3, back under the parent lock: creation is serialised here, so
        // two concurrent requests for the same target cannot each open a
        // session (and end up with two handles ending one row).
        let mut parent = self.user_session_state.lock().await;
        if let Some(slot) = parent.target_sessions.get(&target_id) {
            // Another request got there during phase 2. It ran the same checks
            // for the same target, so its session is the one to join.
            return Ok(TargetSessionStart::Started(Box::new((
                slot.handle.id(),
                ApprovedTarget::new(authorization),
                TargetSessionCloseSignal(slot.close_tx.subscribe()),
            ))));
        }

        let id = match lifecycle {
            SessionLifecycle::Shared(_) => TargetSessionId(Uuid::new_v4()),
            SessionLifecycle::ConnectionBound => {
                // One-to-one protocols reuse the parent id, so a second target
                // session would collide on the primary key. Refusing here turns
                // that into a typed error instead of a DB constraint failure.
                if !parent.target_sessions.is_empty() {
                    return Err(WarpgateError::InconsistentState(
                        "this protocol allows one target session per user session".into(),
                    ));
                }
                TargetSessionId(self.user_session_id.0)
            }
        };
        let target_session = State::create_target_session(
            &self.state,
            self.user_session_id,
            id,
            authorization.target(),
            &parent,
        )
        .await?;
        // A shared session may have adopted the live row another node opened
        // for this target, so the row's id — not the proposed one — is the
        // session's id from here on.
        let id = target_session.id();
        target_session.update_rate_limiters().await?;

        let close_tx = broadcast::channel(1).0;
        let close_rx = close_tx.subscribe();
        parent.target_sessions.insert(
            target_id,
            TargetSessionSlot {
                handle: target_session,
                close_tx,
            },
        );
        drop(parent);
        Ok(TargetSessionStart::Started(Box::new((
            id,
            ApprovedTarget::new(authorization),
            TargetSessionCloseSignal(close_rx),
        ))))
    }

    /// [`Self::start_target_session`] for a protocol whose connection and sole
    /// target session live and die together: the close signal is redundant
    /// because the connection's own teardown aborts everything served here,
    /// and a pending approval cannot be held open, so it becomes an error.
    ///
    /// HTTP is the exception and calls [`Self::start_target_session`] directly:
    /// its requests come and go against a session that outlives them, so it
    /// needs both the signal and the ability to answer "approval pending".
    pub async fn start_sole_target_session<O>(
        &mut self,
        authorization: TargetAuthorization<O>,
    ) -> Result<(TargetSessionId, ApprovedTarget<O>), WarpgateError> {
        let (id, approved, close_signal) =
            *self.start_target_session(authorization).await?.admitted()?;
        close_signal.forget();
        Ok((id, approved))
    }

    async fn needs_target_approval(&self, target: &Target) -> Result<bool, WarpgateError> {
        target_session_needs_approval(&self.db, self.user_session_id, target).await
    }

    /// Wraps a connection stream with the user-session rate limiters. Streams
    /// are wrapped at accept time — via
    /// [`State::register_user_session_with_stream`], the only outside entry —
    /// before any target is known; a starting target session shares these
    /// handles and re-derives the target limits onto them.
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

/// Fires (or closes) when the target session is torn down, so the requests
/// served through it can abort. Consuming it is a decision: [`Self::receiver`]
/// to actually watch it, or [`Self::forget`] where teardown provably arrives
/// another way — silently dropping it as `_` is how a session outlives its
/// teardown.
#[must_use = "either watch the close signal or explicitly forget() it"]
pub struct TargetSessionCloseSignal(broadcast::Receiver<()>);

impl TargetSessionCloseSignal {
    pub fn receiver(self) -> broadcast::Receiver<()> {
        self.0
    }

    /// For one-to-one protocols whose sole target session shares the parent's
    /// lifetime: the parent's abort path already tears down everything served
    /// here, so the signal is redundant. That reasoning breaks the moment a
    /// target session can end while its parent survives — a caller of this
    /// method is signing up to revisit it then.
    pub fn forget(self) {}
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

/// Lifetime guard for one target connection. For a connection-bound session,
/// dropping it ends that child session (the parent user session can continue
/// and start another connection); for a shared session it detaches this node's
/// view only — the row is an access record that ends with its parent.
pub struct TargetSessionHandle {
    id: TargetSessionId,
    user_session_id: UserSessionId,
    state: Arc<Mutex<State>>,
    session_state: Arc<Mutex<TargetSessionState>>,
    rate_limiters_registry: Arc<Mutex<RateLimiterRegistry>>,
    lifecycle: SessionLifecycle,
}

impl TargetSessionHandle {
    pub(crate) const fn new(
        id: TargetSessionId,
        user_session_id: UserSessionId,
        state: Arc<Mutex<State>>,
        session_state: Arc<Mutex<TargetSessionState>>,
        rate_limiters_registry: Arc<Mutex<RateLimiterRegistry>>,
        lifecycle: SessionLifecycle,
    ) -> Self {
        Self {
            id,
            user_session_id,
            state,
            session_state,
            rate_limiters_registry,
            lifecycle,
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
        let session_state = self.session_state.clone();
        let lifecycle = self.lifecycle;
        tokio::spawn(async move {
            match lifecycle {
                SessionLifecycle::ConnectionBound => {
                    state.lock().await.remove_target_session(id).await;
                }
                SessionLifecycle::Shared(_) => {
                    state.lock().await.detach_target_session(id, &session_state);
                }
            }
        });
    }
}

impl Drop for WarpgateServerHandle {
    fn drop(&mut self) {
        let id = self.user_session_id;
        let state = self.state.clone();
        let user_session_state = self.user_session_state.clone();
        let provisional = self.provisional;
        let protocol = self.protocol;
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
            let span = info_span!("Teardown", protocol=protocol.name(), session=%id, session_username=%username);
            state.lock().await.remove_session(id).instrument(span).await;
        });
    }
}

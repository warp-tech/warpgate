use std::sync::Arc;

use sea_orm::ActiveValue::Set;
use sea_orm::DatabaseConnection;
use tokio::sync::Mutex;
use warpgate_common::auth::{ApprovalKind, AuthCredential, AuthResult, AuthState, CredentialKind};
use warpgate_common::{NodeId, UserSessionId, WarpgateError};
use warpgate_db_entities::SessionApprovalRequest;
use warpgate_db_entities::SessionApprovalRequest::{
    mark_consumed, undelivered_user_approvals_for_session, upsert_request,
};

use super::*;
use crate::services::Services;

impl Services {
    /// Applies a decision already recorded for this session's own approval, if
    /// one is waiting on its row.
    ///
    /// The background sweep delivers these within a tick anyway; an auth flow
    /// that answers the client per message calls this before reporting "still
    /// waiting", so a decision the user just made takes effect on that very
    /// round. SSH clients with no TTY answer the web-approval prompt instantly
    /// and burn through their retry budget in well under a sweep interval, so
    /// for them this is correctness, not just latency.
    pub async fn apply_recorded_user_decision(
        &self,
        session_id: &UserSessionId,
    ) -> Result<(), WarpgateError> {
        for row in undelivered_user_approvals_for_session(&self.db, *session_id).await? {
            self.deliver_user_decision(&row).await?;
        }
        Ok(())
    }

    /// Applies decisions recorded elsewhere to the auth states this node holds.
    ///
    /// A self approval satisfies a credential on an in-memory auth state, so
    /// only the node holding that state can act on the decision — wherever the
    /// user happened to click. Administrator gates need no sweep: each polls its
    /// own row while it holds the connection.
    pub(crate) async fn apply_decided_user_approvals(&self) -> Result<(), WarpgateError> {
        let rows = SessionApprovalRequest::undelivered_user_approvals_for_node(
            &self.db,
            self.cluster.node_id,
        )
        .await?;

        for row in rows {
            self.deliver_user_decision(&row).await?;
        }
        Ok(())
    }

    /// Delivers one recorded decision to the auth state it was asked for.
    async fn deliver_user_decision(
        &self,
        row: &SessionApprovalRequest::Model,
    ) -> Result<bool, WarpgateError> {
        let RowState::Decided(decision, actor) = row_state(row)? else {
            return Ok(false);
        };
        self.apply_user_decision(row.session_id, decision, &actor, Some(row))
            .await
    }

    /// Applies a user's own approval to the locally-owned auth state: adds or
    /// withholds the approval credential through the pending gate, records the
    /// grace key, audits, and stamps the row as picked up. `Ok(false)` when the state is
    /// gone or no longer pending an approval (resolved concurrently, expired,
    /// or never asked).
    ///
    /// The store hands out auth states by session id, so the row's key is also
    /// the key of the state it resolves against.
    pub async fn apply_user_approval(
        &self,
        session_id: UserSessionId,
        decision: ApprovalDecision,
        actor: &ApprovalActor,
    ) -> Result<bool, WarpgateError> {
        self.apply_user_decision(session_id, decision, actor, None)
            .await
    }

    /// [`Self::apply_user_approval`], with the question named. `question` is
    /// the request row a recorded decision was read off; `None` means the
    /// decision is being made fresh against whatever the state is asking now
    /// (the user clicked on the node holding it).
    ///
    /// The distinction matters because a state answers one question at a time
    /// while a session's rows keep one per target: a decision recorded for a
    /// question the state has since moved on from — a different target, or a
    /// different user after a fresh attempt on the same connection — must not
    /// satisfy the state's current question, and its consumption stamp must
    /// land on its own row, not on the live question's.
    async fn apply_user_decision(
        &self,
        session_id: UserSessionId,
        decision: ApprovalDecision,
        actor: &ApprovalActor,
        question: Option<&SessionApprovalRequest::Model>,
    ) -> Result<bool, WarpgateError> {
        let consumed =
            |target: &str| SessionApprovalRequest::Key::new(session_id, ApprovalKind::User, target);

        let Some(state_arc) = self.auth_state_store.lock().await.get(&session_id) else {
            // The state is gone (vacuumed or node restarted) — nothing can act
            // on a recorded decision, so its row is stamped picked up to stop
            // the sweep re-offering it. It keeps who decided what; that the
            // login never heard is in its own audit trail. A fresh click with
            // no state has recorded nothing, so there is nothing to stamp.
            if let Some(row) = question {
                mark_consumed(&self.db, consumed(&row.target)).await?;
            }
            return Ok(false);
        };

        // All the in-memory work under one lock — it's synchronous, and this
        // path runs at most once per session.
        let target_name = {
            let mut state = state_arc.lock().await;
            let subject = ApprovalSubject::from_auth_state(&state);

            // A recorded decision answers the question its row names. A state
            // asking about a different target — or about a different user,
            // after a fresh attempt took over the connection — is a different
            // question; the one this answers can no longer be delivered to
            // anything, so its row is stamped picked up and the state left
            // waiting on its own answer.
            if let Some(row) = question
                && (row.target != subject.target_name || row.user_id != subject.user_info.id)
            {
                drop(state);
                mark_consumed(&self.db, consumed(&row.target)).await?;
                return Ok(false);
            }

            // Only resolve a request the state is actually still waiting on —
            // not already accepted, rejected, or resolved concurrently.
            if !matches!(
                state.verify(),
                AuthResult::Need(ref kinds) if kinds.contains(&CredentialKind::WebUserApproval)
            ) {
                // A state that no longer wants it means the row is stale
                // (satisfied by a grace bypass, or resolved concurrently) —
                // stamp it picked up rather than leave it waiting on delivery.
                drop(state);
                mark_consumed(&self.db, consumed(&subject.target_name)).await?;
                return Ok(false);
            }

            match decision {
                ApprovalDecision::Approved(_) => {
                    state.add_web_user_approval();
                }
                ApprovalDecision::Rejected => {
                    state.reject();
                    // A denied login is a failed authentication too — alerting
                    // keys off this event, and a user explicitly denying an
                    // out-of-band request is its highest-value instance.
                    state.emit_authentication_failed_event(
                        Some(&AuthCredential::WebUserApproval),
                        "rejected by user",
                    );
                }
            }
            subject.target_name
        };

        // The row is the durable record of who answered — and, scope and all,
        // the remembered approval later attempts bypass on. A decision the
        // sweep read off the row already stands there, and the pending-only
        // transition makes this a no-op; one applied straight off the click —
        // the user answered on the node holding the state — reaches the row
        // only here.
        let _ = record_decision(
            &self.db,
            session_id,
            ApprovalKind::User,
            &target_name,
            decision,
            actor,
        )
        .await?;
        mark_consumed(&self.db, consumed(&target_name)).await?;
        Ok(true)
    }
}

/// Records a self-approval request, so it is visible to every node.
///
/// Written *before* the user is told a request is waiting: the notification and
/// the record would otherwise race, and a user acting on the notification the
/// instant it arrives could find nothing to act on.
///
/// Note: this can be called multiple times within the same auth, new credentials
/// arriving rewrite the credential fingerprint and the node ID may change
pub(crate) async fn advertise_user_request(
    db: &DatabaseConnection,
    node_id: NodeId,
    state_arc: &Arc<Mutex<AuthState>>,
) -> Result<(), WarpgateError> {
    // Snapshot under the state lock and release it before the insert, so
    // database IO never runs while a login's state is held.
    let row = {
        let state = state_arc.lock().await;
        let session_id = *state.session_id();
        SessionApprovalRequest::ActiveModel {
            session_id: Set(session_id),
            kind: Set(ApprovalKind::User.into()),
            node_id: Set(node_id),
            protocol: Set(state.protocol().to_string()),
            username: Set(state.user_info().username.clone()),
            user_id: Set(state.user_info().id),
            target: Set(state.target_name().to_string()),
            remote_address: Set(state.remote_ip().map(|ip| ip.to_string())),
            identification_string: Set(Some(state.identification_string().to_owned())),
            match_digest: Set(state
                .web_approval_match_key()
                .map(|key| key.identity().digest())),
            consumes_ticket_id: Set(None),
            started: Set(*state.started()),
            status: Set(SessionApprovalRequest::ApprovalRequestStatus::Pending),
            scope: Set(None),
            resolved_by_username: Set(None),
            resolved_by_user_id: Set(None),
            resolved_at: Set(None),
            consumed_at: Set(None),
        }
    };

    upsert_request(db, row).await?;
    Ok(())
}

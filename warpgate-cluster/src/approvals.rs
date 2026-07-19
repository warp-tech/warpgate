//! Owner-side resolution of session approval requests.
//!
//! The request row names the node running the held session, and only that node
//! can deliver a decision — the waiting connection and the auth state are both
//! in its memory. Reaching it is the ordinary cross-node problem, so it uses the
//! ordinary mechanism: the admin's own approve/reject request is forwarded to
//! the owner by [`crate::proxy::local_or_forward`], and the owner runs the same
//! handler under a cluster token, attributing the decision to the actor carried
//! alongside it.

use sea_orm::EntityTrait;
use uuid::Uuid;
use warpgate_common::WarpgateError;
use warpgate_common::auth::ApprovalKind;
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_core::approvals::{ApprovalActor, ApprovalDecision};
use warpgate_db_entities::{Node, SessionApprovalRequest};

use crate::proxy::Owner;

/// The identity to record against a decision.
///
/// For a forwarded request this is the admin on the originating node, carried
/// in the cluster actor header — the cluster token says which node is asking,
/// never who.
pub fn acting_approver(ctx: &AuthenticatedRequestContext) -> ApprovalActor {
    let actor = ctx.auth.actor();
    let user_id = actor.user_id();
    ApprovalActor {
        // Token-authenticated callers have no user behind them; name the
        // mechanism rather than logging an empty actor.
        username: actor
            .username()
            .cloned()
            .unwrap_or_else(|| "<api token>".to_string()),
        // A nil id means the request wasn't made by a user (admin API token).
        user_id: (!user_id.is_nil()).then_some(user_id),
    }
}

/// A pending approval request: where it has to be handled, and who it is about.
pub struct PendingApproval {
    pub owner: Owner,
    /// The user whose session is being held — the one an approver must not be.
    pub username: String,
}

/// Looks up the pending `kind` approval of `session_id`.
///
/// `None` when there is no such request — unknown session, no request of that
/// kind, or already resolved. A row whose owning node has left the cluster is
/// deleted here: the waiting connection went with it, so nothing can ever
/// resolve it.
pub async fn find_pending_approval(
    ctx: &AuthenticatedRequestContext,
    session_id: Uuid,
    kind: ApprovalKind,
) -> Result<Option<PendingApproval>, WarpgateError> {
    let services = ctx.services();
    let key = (
        session_id,
        SessionApprovalRequest::ApprovalRequestKind::from(kind),
    );

    let Some(row) = SessionApprovalRequest::Entity::find_by_id(key)
        .one(&services.db)
        .await?
    else {
        return Ok(None);
    };

    if row.node_id == services.cluster.node_id {
        return Ok(Some(PendingApproval {
            owner: Owner::Local,
            username: row.username,
        }));
    }

    let Some(node) = Node::Entity::find_by_id(row.node_id)
        .one(&services.db)
        .await?
    else {
        SessionApprovalRequest::Entity::delete_by_id(key)
            .exec(&services.db)
            .await?;
        return Ok(None);
    };

    Ok(Some(PendingApproval {
        owner: Owner::remote(node),
        username: row.username,
    }))
}

/// Applies a decision to a request this node owns. `Ok(false)` when nothing is
/// waiting for it any more.
///
/// Rows are keyed by `(session_id, kind)`, so a stale click for one kind can
/// never resolve the other — a user's own approval cannot satisfy an
/// administrator requirement.
pub async fn resolve_locally(
    ctx: &AuthenticatedRequestContext,
    session_id: Uuid,
    kind: ApprovalKind,
    decision: ApprovalDecision,
    actor: &ApprovalActor,
) -> Result<bool, WarpgateError> {
    let services = ctx.services();
    let key = (
        session_id,
        SessionApprovalRequest::ApprovalRequestKind::from(kind),
    );
    let Some(row) = SessionApprovalRequest::Entity::find_by_id(key)
        .one(&services.db)
        .await?
    else {
        return Ok(false);
    };

    match kind {
        ApprovalKind::Admin => {
            services
                .deliver_admin_approval(session_id, decision, actor)
                .await
        }
        ApprovalKind::User => match row.auth_state_id {
            Some(auth_state_id) => {
                services
                    .apply_user_approval(session_id, auth_state_id, decision, actor)
                    .await
            }
            // A user-approval row with no auth state can never be satisfied.
            None => Ok(false),
        },
    }
}

//! Any-node resolution of session approval requests.
//!
//! The request row names the owning node; when that's us, the decision is
//! delivered locally — to the waiting connection for an administrator approval,
//! to the in-memory auth state for a user's own approval. Otherwise it is
//! carried to the owner by a purpose-built internal cluster RPC (cluster-token
//! authenticated, JSON body — nothing of the caller's request is forwarded).

use poem::http::StatusCode;
use sea_orm::EntityTrait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use warpgate_common::WarpgateError;
use warpgate_common::auth::ApprovalKind;
use warpgate_core::approvals::{ApprovalActor, ApprovalDecision};
use warpgate_db_entities::{Node, SessionApprovalRequest};

use crate::AuthenticatedRequestContext;
use crate::cluster_proxy::post_json_to_peer;

/// Body of the internal owner-side resolution RPC.
#[derive(Serialize, Deserialize)]
pub struct ResolveApprovalRpc {
    pub kind: ApprovalKind,
    /// The auth state to resolve, for [`ApprovalKind::User`]. Carried from the
    /// row so the owner doesn't have to re-read it.
    pub auth_state_id: Option<Uuid>,
    pub decision: ApprovalDecision,
    pub actor: ApprovalActor,
}

/// The resolver's identity, for audit attribution on the owning node.
pub fn acting_approver(ctx: &AuthenticatedRequestContext) -> ApprovalActor {
    let user_id = ctx.auth.user_id();
    ApprovalActor {
        // Token-authenticated callers have no user behind them; name the
        // mechanism rather than logging an empty actor.
        username: ctx
            .auth
            .username()
            .cloned()
            .unwrap_or_else(|| "<api token>".to_string()),
        // A nil id means the request wasn't made by a user (admin API token).
        user_id: (!user_id.is_nil()).then_some(user_id),
    }
}

/// Resolves the pending `kind` approval of `session_id` from any node. Returns
/// `Ok(false)` when there is no matching pending request (unknown session, no
/// request of that kind, already resolved, or the owning node is gone).
///
/// Rows are keyed by `(session_id, kind)`, so a stale click for one kind can
/// never resolve the other — a user's own approval cannot satisfy an
/// administrator requirement.
pub async fn resolve_approval(
    ctx: &AuthenticatedRequestContext,
    session_id: Uuid,
    kind: ApprovalKind,
    decision: ApprovalDecision,
    actor: &ApprovalActor,
) -> poem::Result<bool> {
    let services = ctx.services();

    let key = (
        session_id,
        SessionApprovalRequest::ApprovalRequestKind::from(kind),
    );
    let Some(row) = SessionApprovalRequest::Entity::find_by_id(key)
        .one(&services.db)
        .await
        .map_err(WarpgateError::from)?
    else {
        return Ok(false);
    };

    if row.node_id == services.cluster.node_id {
        return Ok(match kind {
            ApprovalKind::Admin => {
                services
                    .deliver_admin_approval(session_id, decision, actor)
                    .await?
            }
            ApprovalKind::User => {
                let Some(auth_state_id) = row.auth_state_id else {
                    return Ok(false);
                };
                services
                    .apply_user_approval(session_id, auth_state_id, decision, actor)
                    .await?
            }
        });
    }

    let Some(node) = Node::Entity::find_by_id(row.node_id)
        .one(&services.db)
        .await
        .map_err(WarpgateError::from)?
    else {
        // The owning node is gone, and with it the waiting connection — the
        // row is a ghost; it cannot be resurrected.
        SessionApprovalRequest::Entity::delete_by_id(key)
            .exec(&services.db)
            .await
            .map_err(WarpgateError::from)?;
        return Ok(false);
    };

    let status = post_json_to_peer(
        ctx,
        node,
        &format!("/@warpgate/admin/api/session-approvals/{session_id}/resolve"),
        &ResolveApprovalRpc {
            kind,
            auth_state_id: row.auth_state_id,
            decision,
            actor: actor.clone(),
        },
    )
    .await?;
    match status {
        StatusCode::OK => Ok(true),
        StatusCode::NOT_FOUND => Ok(false),
        status => Err(poem::Error::from_string(
            format!("Unexpected response from the owner node: {status}"),
            StatusCode::BAD_GATEWAY,
        )),
    }
}

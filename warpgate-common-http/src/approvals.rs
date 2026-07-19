//! Any-node resolution of session approval requests.
//!
//! The request row names the owning node; when that's us, the decision is
//! applied directly to the in-memory auth state, otherwise it is carried to
//! the owner by a purpose-built internal cluster RPC (cluster-token
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

/// Resolves the approval request `id` of the given `kind` from any node.
/// Returns `Ok(false)` when there is no matching pending request (unknown id,
/// kind mismatch, already resolved, or the owning node is gone).
pub async fn resolve_approval(
    ctx: &AuthenticatedRequestContext,
    id: Uuid,
    kind: ApprovalKind,
    decision: ApprovalDecision,
    actor: &ApprovalActor,
) -> poem::Result<bool> {
    let services = ctx.services();

    let Some(row) = SessionApprovalRequest::Entity::find_by_id(id)
        .one(&services.db)
        .await
        .map_err(WarpgateError::from)?
    else {
        return Ok(false);
    };
    // A stale click for one factor must never resolve a request for another
    // (e.g. a user's web approval satisfying an admin requirement).
    if row.kind != SessionApprovalRequest::ApprovalRequestKind::from(kind) {
        return Ok(false);
    }

    if row.node_id == services.cluster.node_id {
        return Ok(services
            .apply_approval_resolution(id, kind, decision, actor)
            .await?);
    }

    let Some(node) = Node::Entity::find_by_id(row.node_id)
        .one(&services.db)
        .await
        .map_err(WarpgateError::from)?
    else {
        // The owning node is gone, and with it the auth state — the row is a
        // ghost; the waiting connection cannot be resurrected.
        SessionApprovalRequest::Entity::delete_by_id(id)
            .exec(&services.db)
            .await
            .map_err(WarpgateError::from)?;
        return Ok(false);
    };

    let status = post_json_to_peer(
        ctx,
        node,
        &format!("/@warpgate/admin/api/session-approvals/{id}/resolve"),
        &ResolveApprovalRpc {
            kind,
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

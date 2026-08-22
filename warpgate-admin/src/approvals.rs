//! Looking up and resolving out-of-band approval requests.
//!
//! Only the node running the held session can act on a decision — the waiting
//! connection and the auth state are both in its memory — but nothing has to
//! reach it to tell it. The decision is written to the request row, which every
//! node shares, and the owner reads it back from there. So an approve or reject
//! is served wherever it lands: no forwarding, no cluster token, and no
//! dependency on the owner being reachable at the moment of the click.

use sea_orm::EntityTrait;
use uuid::Uuid;
use warpgate_common::WarpgateError;
use warpgate_common::auth::ApprovalKind;
use warpgate_common::helpers::username::username_eq_ci;
use warpgate_common_http::{
    AuthenticatedRequestContext, RequestAuthorization, SessionAuthorization,
};
use warpgate_core::approvals::{ApprovalActor, ApprovalDecision, close_request, record_decision};
use warpgate_db_entities::{Node, SessionApprovalRequest};

/// The identity to record against a decision.
pub fn acting_approver(ctx: &AuthenticatedRequestContext) -> ApprovalActor {
    let user_id = ctx.auth.user_id();
    ApprovalActor {
        // Token-authenticated callers have no user behind them; name the
        // mechanism rather than recording an empty actor.
        username: ctx
            .auth
            .username()
            .cloned()
            .unwrap_or_else(|| "<api token>".to_string()),
        // A nil id means the request wasn't made by a user (admin API token).
        user_id: (!user_id.is_nil()).then_some(user_id),
    }
}

/// A request still waiting on a decision, and who it is about.
pub struct PendingApproval {
    pub session_id: Uuid,
    pub kind: ApprovalKind,
    /// The user whose session is being held — the one an approver must not be.
    pub username: String,
}

/// Whether a decision was recorded, or the request had already gone.
pub enum ApprovalResolution {
    Resolved,
    NotFound,
}

/// Looks up the pending `kind` approval of `session_id`.
///
/// `None` when there is no such request — unknown session, no request of that
/// kind, or already resolved.
pub async fn find_pending_approval(
    ctx: &AuthenticatedRequestContext,
    session_id: Uuid,
    kind: ApprovalKind,
) -> Result<Option<PendingApproval>, WarpgateError> {
    let key = (
        session_id,
        SessionApprovalRequest::ApprovalRequestKind::from(kind),
    );

    let Some(row) = SessionApprovalRequest::Entity::find_by_id(key)
        .one(&ctx.services().db)
        .await?
        .filter(is_pending)
    else {
        return Ok(None);
    };

    pending_approval_from_row(ctx, row).await
}

/// Rows outlive the request they record, so being there is no longer the same
/// as being answerable.
fn is_pending(row: &SessionApprovalRequest::Model) -> bool {
    row.status == SessionApprovalRequest::ApprovalRequestStatus::Pending
}

/// The user-approval request of a session, if it belongs to the
/// browser-authenticated user.
///
/// The row is the whole record, so it is also what a node that isn't holding
/// the auth state renders the approval page from.
pub async fn find_user_approval_row(
    ctx: &AuthenticatedRequestContext,
    session_id: Uuid,
) -> Result<Option<SessionApprovalRequest::Model>, WarpgateError> {
    let RequestAuthorization::Session(SessionAuthorization::User { username, .. }) = &ctx.auth
    else {
        return Ok(None);
    };
    let row = SessionApprovalRequest::Entity::find_by_id((
        session_id,
        SessionApprovalRequest::ApprovalRequestKind::User,
    ))
    .one(&ctx.services().db)
    .await?;
    Ok(row.filter(|row| is_pending(row) && username_eq_ci(&row.username, username)))
}

/// Looks up the pending user approval for an auth state, provided it belongs
/// to the browser-authenticated user.
pub async fn find_pending_user_approval(
    ctx: &AuthenticatedRequestContext,
    session_id: Uuid,
) -> Result<Option<PendingApproval>, WarpgateError> {
    let Some(row) = find_user_approval_row(ctx, session_id).await? else {
        return Ok(None);
    };

    pending_approval_from_row(ctx, row).await
}

/// Turns a row into a resolvable request, closing one whose owning node has
/// left the cluster: the waiting connection went with it, so a decision written
/// there would never be read. Closing it now keeps it out of the approvals list
/// rather than leaving it to be reaped by age.
async fn pending_approval_from_row(
    ctx: &AuthenticatedRequestContext,
    row: SessionApprovalRequest::Model,
) -> Result<Option<PendingApproval>, WarpgateError> {
    let services = ctx.services();
    let kind = match row.kind {
        SessionApprovalRequest::ApprovalRequestKind::User => ApprovalKind::User,
        SessionApprovalRequest::ApprovalRequestKind::Admin => ApprovalKind::Admin,
    };

    if row.node_id != services.cluster.node_id
        && Node::Entity::find_by_id(row.node_id)
            .one(&services.db)
            .await?
            .is_none()
    {
        close_request(
            &services.db,
            row.session_id,
            kind,
            SessionApprovalRequest::ApprovalRequestStatus::Abandoned,
        )
        .await?;
        return Ok(None);
    }

    Ok(Some(PendingApproval {
        session_id: row.session_id,
        kind,
        username: row.username,
    }))
}

/// Records a decision on a pending request, wherever the approver is talking to
/// the cluster. The owning node picks it up from the row.
///
/// Rows are keyed by `(session_id, kind)`, so a stale click for one kind can
/// never resolve the other — a user's own approval cannot satisfy an
/// administrator requirement.
pub async fn resolve_pending_approval(
    ctx: &AuthenticatedRequestContext,
    pending: PendingApproval,
    decision: ApprovalDecision,
) -> Result<ApprovalResolution, WarpgateError> {
    let actor = acting_approver(ctx);
    let recorded = record_decision(
        &ctx.services().db,
        pending.session_id,
        pending.kind,
        decision,
        &actor,
    )
    .await?;

    Ok(if recorded {
        ApprovalResolution::Resolved
    } else {
        ApprovalResolution::NotFound
    })
}

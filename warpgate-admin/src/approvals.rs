//! Looking up and resolving out-of-band approval requests.
//!
//! Only the node running the held session can act on a decision — the waiting
//! connection and the auth state are both in its memory — but nothing has to
//! reach it to tell it. The decision is written to the request row, which every
//! node shares, and the owner reads it back from there. So an approve or reject
//! is served wherever it lands: no forwarding, no cluster token, and no
//! dependency on the owner being reachable at the moment of the click.

use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use warpgate_common::auth::ApprovalKind;
use warpgate_common::helpers::username::username_eq_ci;
use warpgate_common::{AdminPermission, UserSessionId, WarpgateError};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_core::approvals::{ApprovalActor, ApprovalDecision, record_decision};
use warpgate_db_entities::{Node, SessionApprovalRequest};

use crate::api::common::has_admin_permission;

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
    pub session_id: UserSessionId,
    pub kind: ApprovalKind,
    /// The user whose session is being held — the one an approver must not be.
    pub username: String,
    /// The target the question is about — part of the row's key, echoed into
    /// the decision so a click can only resolve the question it was shown for.
    pub target: String,
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
    session_id: UserSessionId,
    kind: ApprovalKind,
    target: &str,
) -> Result<Option<PendingApproval>, WarpgateError> {
    let key = (session_id, kind, target.to_owned());

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
    session_id: UserSessionId,
) -> Result<Option<SessionApprovalRequest::Model>, WarpgateError> {
    let Some(user) = ctx.auth.as_full_user() else {
        return Ok(None);
    };
    let username = user.username();
    // A login has one target name, fixed when its auth state is built, so its
    // own request is unambiguous without naming it.
    let row = SessionApprovalRequest::Entity::find()
        .filter(SessionApprovalRequest::Column::SessionId.eq(session_id))
        .filter(SessionApprovalRequest::Column::Kind.eq(ApprovalKind::User))
        .one(&ctx.services().db)
        .await?;
    Ok(row.filter(|row| is_pending(row) && username_eq_ci(&row.username, username)))
}

/// Looks up the pending user approval for an auth state, provided it belongs
/// to the browser-authenticated user.
pub async fn find_pending_user_approval(
    ctx: &AuthenticatedRequestContext,
    session_id: UserSessionId,
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
    let kind = row.kind;

    if row.node_id != services.cluster.node_id
        && Node::Entity::find_by_id(row.node_id)
            .one(&services.db)
            .await?
            .is_none()
    {
        SessionApprovalRequest::close_request(
            &services.db,
            row.session_id,
            kind,
            &row.target,
            SessionApprovalRequest::ApprovalRequestStatus::Abandoned,
        )
        .await?;
        return Ok(None);
    }

    Ok(Some(PendingApproval {
        session_id: row.session_id,
        kind,
        username: row.username,
        target: row.target,
    }))
}

/// Who is answering a request, which is what decides whether answering for
/// yourself is allowed.
///
/// The two callers of [`resolve_pending_approval`] want opposite things here —
/// the administrator inbox must refuse a self-approval, the gateway's own-request
/// endpoint exists to serve one — and nothing in a `ctx` says which you are. So
/// the caller states it, and the check lives with the resolution rather than in
/// whichever endpoint remembered to run it.
pub enum Approver {
    /// An administrator acting on someone else's held session.
    Administrator,
    /// The user answering their own out-of-band request.
    TheUserThemselves,
}

/// Approving your own held session defeats the four-eyes property the
/// administrator gate exists for, so it is refused — unless the approver could
/// edit targets, since that lets them clear `require_approval` and walk through
/// anyway.
///
/// Only approvals: rejecting your own session grants nothing.
async fn check_self_approval(
    ctx: &AuthenticatedRequestContext,
    approver: &Approver,
    pending: &PendingApproval,
    decision: ApprovalDecision,
) -> Result<(), WarpgateError> {
    if matches!(approver, Approver::TheUserThemselves)
        || matches!(decision, ApprovalDecision::Rejected)
    {
        return Ok(());
    }

    let Some(username) = ctx.auth.username() else {
        // Not a user (admin API token) — there is no "own session" to speak of.
        return Ok(());
    };

    if !username_eq_ci(&pending.username, username)
        || has_admin_permission(ctx, Some(AdminPermission::TargetsEdit)).await?
    {
        return Ok(());
    }

    Err(WarpgateError::NoAdminPermission(
        AdminPermission::TargetsEdit,
    ))
}

/// Records a decision on a pending request, wherever the approver is talking to
/// the cluster. The owning node picks it up from the row.
///
/// Rows are keyed by `(session_id, kind, target)`, so a stale click for one
/// kind can never resolve the other — a user's own approval cannot satisfy an
/// administrator requirement.
pub async fn resolve_pending_approval(
    ctx: &AuthenticatedRequestContext,
    approver: Approver,
    pending: PendingApproval,
    decision: ApprovalDecision,
) -> Result<ApprovalResolution, WarpgateError> {
    // [`Approver::TheUserThemselves`] exists to answer the user's own
    // `User`-kind request, and skips the four-eyes check on that basis. An
    // administrator gate answered under that flag would skip it too, so the
    // pairing is enforced here rather than trusted to each endpoint.
    if matches!(approver, Approver::TheUserThemselves) && pending.kind != ApprovalKind::User {
        return Err(WarpgateError::InconsistentState(
            "only the user's own approval request can be answered as the user themselves".into(),
        ));
    }

    check_self_approval(ctx, &approver, &pending, decision).await?;

    let actor = acting_approver(ctx);
    let recorded = record_decision(
        &ctx.services().db,
        pending.session_id,
        pending.kind,
        &pending.target,
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

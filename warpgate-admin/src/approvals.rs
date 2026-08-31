use sea_orm::EntityTrait;
use warpgate_common::auth::ApprovalKind;
use warpgate_common::helpers::username::username_eq_ci;
use warpgate_common::{AdminPermission, UserSessionId, WarpgateError};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_core::approvals::{ApprovalDecision, record_decision};
use warpgate_db_entities::SessionApprovalRequest::ApprovalActor;
use warpgate_db_entities::{Node, SessionApprovalRequest as SAR};

use crate::api::common::has_admin_permission;

pub fn acting_approver(ctx: &AuthenticatedRequestContext) -> ApprovalActor {
    let user_id = ctx.auth.user_id();
    ApprovalActor {
        username: ctx.auth.username().cloned(),
        user_id,
    }
}

/// a known-pending approval request
pub struct PendingApproval {
    session_id: UserSessionId,
    kind: ApprovalKind,
    username: String,
    target: String,
}

impl PendingApproval {
    pub fn target(&self) -> &str {
        &self.target
    }

    pub async fn parse(
        ctx: &AuthenticatedRequestContext,
        row: SAR::Model,
    ) -> Result<Option<Self>, WarpgateError> {
        let services = ctx.services();

        if row.node_id != services.cluster.node_id
            && Node::Entity::find_by_id(row.node_id)
                .one(&services.db)
                .await?
                .is_none()
        {
            SAR::close_request(
                &services.db,
                row.session_id,
                row.kind,
                &row.target,
                SAR::UndecidedApprovalRequestStatus::Abandoned,
            )
            .await?;
            return Ok(None);
        }

        Ok(Some(Self {
            session_id: row.session_id,
            kind: row.kind,
            username: row.username,
            target: row.target,
        }))
    }
}

pub enum ApprovalResolution {
    Resolved,
    NotFound,
}

pub async fn find_pending_approval(
    ctx: &AuthenticatedRequestContext,
    session_id: UserSessionId,
    kind: ApprovalKind,
    target: &str,
) -> Result<Option<PendingApproval>, WarpgateError> {
    let row = SAR::Entity::find_by_id((session_id, kind, target.to_owned()))
        .one(&ctx.services().db)
        .await?
        .filter(is_pending);

    let Some(row) = row else {
        return Ok(None);
    };

    PendingApproval::parse(ctx, row).await
}

fn is_pending(row: &SAR::Model) -> bool {
    row.status == SAR::ApprovalRequestStatus::Pending
}

/// Admin approvals should refuse self-approval and user-approvals are always self-approvals
pub enum Approver {
    Administrator,
    TheUserThemselves,
}

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
        // somehow, admin API token -> there is no "own session"
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

pub async fn resolve_pending_approval(
    ctx: &AuthenticatedRequestContext,
    approver: Approver,
    pending: PendingApproval,
    decision: ApprovalDecision,
) -> Result<ApprovalResolution, WarpgateError> {
    check_self_approval(ctx, &approver, &pending, decision).await?;

    let actor = acting_approver(ctx);
    let recorded = record_decision(
        &ctx.services().db,
        pending.session_id,
        pending.kind,
        &pending.target,
        decision,
        actor,
    )
    .await?;

    Ok(if recorded {
        ApprovalResolution::Resolved
    } else {
        ApprovalResolution::NotFound
    })
}

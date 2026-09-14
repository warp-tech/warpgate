//! Common mechanism for approvals:
//! * Web user approvals (a credential type)
//!   - is a credential type
//!   - for a node-local AuthState
//! * Admin just-in-time approvals
//!   - is a per-target policy setting
//!   - check happens after the user session is running and before target session is started
//!
//! Both states are persisted in DB (source of truth) and can be read by any node (both request and decision which remains there as audit trail)
//! In a cross-node situation, the node with the session polling for admin decision or periodically checking for any settled web user aprovals.
//! There can be max 1 entry of each type for a specific (user session + target) combo
//! Past decision entries are reused for approval bypass ("remember decision" option)
//!
use std::time::Duration;

use sea_orm::sea_query::Condition;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use time::OffsetDateTime;
use warpgate_common::WarpgateError;
pub use warpgate_common::auth::ApprovalScope;
use warpgate_common::auth::{WebApprovalMatchKey, WebApprovalScopeKey};
use warpgate_db_entities::{Parameters, SessionApprovalRequest};

use crate::auth_state_store::TIMEOUT;
use crate::helpers::i64_seconds_to_duration;

mod gate;
mod self_approval;
mod subject;
mod wait;

pub use gate::*;
pub(crate) use self_approval::*;
use subject::*;
pub use wait::*;

#[cfg(all(test, feature = "sqlite"))]
mod tests;

/// A decision delivered to the waiting side
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ApprovalDecision {
    Approved(ApprovalScope),
    Rejected,
}

/// Look for a matching, still acceptable approval in the DB
pub(crate) async fn approval_is_remembered(
    db: &DatabaseConnection,
    key: &WebApprovalMatchKey,
    grace: Duration,
) -> Result<bool, WarpgateError> {
    use SessionApprovalRequest::{ApprovalRequestStatus, Column};

    #[allow(clippy::cast_possible_wrap)]
    let cutoff = OffsetDateTime::now_utc() - time::Duration::seconds(grace.as_secs() as i64);

    let asked_target = match &key.scope() {
        WebApprovalScopeKey::Target(name) => name.as_str(),
        // An untargeted flow stores an empty target name on its rows.
        WebApprovalScopeKey::Untargeted => "",
    };
    let scope_matches = Condition::any()
        .add(
            Column::Scope
                .eq(ApprovalScope::Target)
                .and(Column::Target.eq(asked_target)),
        )
        .add(Column::Scope.eq(ApprovalScope::AllTargets));

    let rows = SessionApprovalRequest::Entity::find()
        .filter(Column::Kind.eq(key.identity().kind()))
        .filter(Column::Status.eq(ApprovalRequestStatus::Approved))
        .filter(Column::ResolvedAt.gte(cutoff))
        .filter(scope_matches)
        .all(db)
        .await?;

    let digest = key.identity().digest();
    Ok(rows
        .into_iter()
        .any(|row| row.match_digest.as_deref() == Some(digest.as_str())))
}

pub(crate) async fn admin_approval_timeout(
    db: &DatabaseConnection,
) -> Result<Duration, WarpgateError> {
    Ok(Parameters::Entity::get(db)
        .await?
        .admin_approval_timeout_seconds
        .and_then(i64_seconds_to_duration)
        //default auth-state timeout when unset
        .unwrap_or(*TIMEOUT))
}

pub(crate) async fn request_lifetime(db: &DatabaseConnection) -> Result<Duration, WarpgateError> {
    // requests may not be cleaned up before their owning AuthState, otherwise that leaves AuthState hanging
    Ok(admin_approval_timeout(db).await?.max(*TIMEOUT))
}

pub(crate) async fn reap_stale(db: &DatabaseConnection) -> Result<(), WarpgateError> {
    let lifetime = request_lifetime(db).await?;
    #[allow(clippy::cast_possible_wrap)]
    let cutoff = OffsetDateTime::now_utc() - time::Duration::seconds(lifetime.as_secs() as i64);
    SessionApprovalRequest::abandon_all_requested_before(db, cutoff).await
}

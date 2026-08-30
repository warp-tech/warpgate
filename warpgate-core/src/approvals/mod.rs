//! Out-of-band approval requests: in-browser self approval, and administrator
//! just-in-time approval of a session.
//!
//! The two are deliberately different mechanisms. Self approval is a
//! *credential* — it satisfies a pending [`CredentialKind::WebUserApproval`] on
//! an in-memory auth state, held by the node that keyed it under the same
//! session id the row is keyed by. Administrator approval is a *gate on the
//! connection*, decided once the target is known and after the credentials are
//! settled; it touches no auth state at all.
//!
//! What they share is the record, and the record is the whole substrate: a
//! `session_approval_requests` row keyed by `(session_id, kind, target)`
//! carries both the question and its answer. Any node can list the rows and
//! any node can resolve one by writing the decision to it — there is no
//! cross-node delivery, because nothing has to reach the owner. The owner
//! instead reads the decision back off the row: an administrator gate polls its
//! own row while it holds the connection, and self approvals are applied by a
//! node-wide sweep, since only the node holding an auth state can satisfy a
//! credential on it.
//!
//! No row is ever deleted while it still means something. A request that ends —
//! consumed, timed out, given up on, torn down with its session, or aged out
//! because its owner died — moves to a terminal status and stays as the record
//! of what was asked and who answered. Only the audit retention removes one.
//! That is also what makes the row safe to read: a gate can tell "answered, and
//! I have yet to see it" from "no longer a live question", where a row that
//! could disappear underneath a wait can only ever mean the second.
//!
//! An approved row is also the remembered approval: the grace-period bypass
//! looks for a recent approval matching the same kind, user, origin,
//! credentials and scope among the rows themselves, so a grant given while
//! talking to one node bypasses the gate on every node, and the record an
//! auditor reads is the record the bypass ran on. The corollary is that a
//! grace period only reaches as far as the audit retention keeps the rows.

use std::time::Duration;

use sea_orm::sea_query::Condition;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use time::OffsetDateTime;
use uuid::Uuid;
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
// Not re-exported outward: the subject is how this module talks about a
// request among its own parts.
use subject::*;
pub use wait::*;

#[cfg(all(test, feature = "sqlite"))]
mod tests;

/// A decision delivered to the waiting side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ApprovalDecision {
    Approved(ApprovalScope),
    Rejected,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApprovalActor {
    /// None if not a user (admin API token)
    pub username: Option<String>,
    pub user_id: Uuid,
}

/// Whether a stored approval within `grace` matches `key` — the grace-period
/// bypass, answered from the request rows themselves, so a grant given while
/// talking to one node bypasses the gate on every node.
///
/// Scope is matched by breadth and everything else by equality, which is why
/// they are matched in different places. The scope condition covers the exact
/// ask and an all-targets grant, which is strictly broader; an untargeted ask
/// (empty target name) is its own bucket, so a grant for a real target never
/// stands in for it, nor the other way round.
///
/// Everything else is one comparison against
/// [`WebApprovalIdentity::digest`] — the same value the row was written with.
/// Comparing the columns one by one instead would mean a field added to the
/// identity silently widening every remembered grant, because nothing makes
/// the comparison list follow the type.
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

/// The configured administrator-approval window, or the default auth-state
/// timeout when unset.
pub(crate) async fn admin_approval_timeout(
    db: &DatabaseConnection,
) -> Result<Duration, WarpgateError> {
    Ok(Parameters::Entity::get(db)
        .await?
        .admin_approval_timeout_seconds
        .and_then(i64_seconds_to_duration)
        .unwrap_or(*TIMEOUT))
}

/// How long approval requests must stay alive: the administrator-approval
/// window, never shorter than the auth-state [`TIMEOUT`].
///
/// A request legitimately outlives the auth state that may have preceded it, so
/// expiring it at the shorter interval would strand sessions still waiting.
pub(crate) async fn request_lifetime(db: &DatabaseConnection) -> Result<Duration, WarpgateError> {
    Ok(admin_approval_timeout(db).await?.max(*TIMEOUT))
}

/// Ends requests whose waiter is gone without having closed them (owning node
/// crashed, or a `Drop` that never got to run). Nothing can still be waiting on
/// a request older than the window it would have waited for.
pub(crate) async fn reap_stale(db: &DatabaseConnection) -> Result<(), WarpgateError> {
    let lifetime = request_lifetime(db).await?;
    #[allow(clippy::cast_possible_wrap)]
    let cutoff = OffsetDateTime::now_utc() - time::Duration::seconds(lifetime.as_secs() as i64);
    SessionApprovalRequest::abandon_all_requested_before(db, cutoff).await
}

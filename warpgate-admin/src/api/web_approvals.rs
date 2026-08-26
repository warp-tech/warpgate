//! Admin visibility into, and revocation of, cached web-approval auth
//! bypasses (see [`warpgate_core::AuthStateStore`]). The cache is per-node
//! in-memory, so a clear (or the list) fans out to every other cluster node,
//! the same way session termination does in `sessions_list`.

use poem::Request;
use poem::http::StatusCode;
use poem_openapi::param::{Path, Query};
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use time::OffsetDateTime;
use tracing::warn;
use warpgate_common::auth::WebApprovalScopeKey;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_common_http::{AuthenticatedRequestContext, is_cluster_peer_request};

use super::ClusterOrAdminContext;
use super::cluster_proxy::{fan_out_to_peers, parse_forwarded_body};

pub struct Api;

#[derive(Object)]
struct ActiveWebApprovalInfo {
    username: String,
    remote_ip: String,
    protocol: String,
    /// Human-readable summary of what the approval covers: a target name,
    /// `*` for all targets, or `sign-in` for an untargeted portal/menu login.
    scope: String,
    /// The target name when this approval is scoped to one target — echo
    /// this back (with `all_targets: false`) to revoke just this row via
    /// `clear_web_approval_scope_for_user`.
    scope_target: Option<String>,
    /// Whether this approval covers every target — echo this back to revoke
    /// just this row.
    all_targets: bool,
    granted_at: OffsetDateTime,
}

#[derive(Object)]
struct ClearWebApprovalsResult {
    cleared_count: u64,
}

#[derive(ApiResponse)]
enum ListWebApprovalsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<ActiveWebApprovalInfo>>),
}

#[derive(ApiResponse)]
enum ClearWebApprovalsResponse {
    #[oai(status = 200)]
    Ok(Json<ClearWebApprovalsResult>),
}

fn scope_label(scope: &WebApprovalScopeKey) -> String {
    match scope {
        WebApprovalScopeKey::Untargeted => "sign-in".to_string(),
        WebApprovalScopeKey::Target(name) => name.clone(),
        WebApprovalScopeKey::AllTargets => "*".to_string(),
    }
}

fn scope_key(target: Option<String>, all_targets: bool) -> WebApprovalScopeKey {
    if all_targets {
        WebApprovalScopeKey::AllTargets
    } else if let Some(target) = target {
        WebApprovalScopeKey::Target(target)
    } else {
        WebApprovalScopeKey::Untargeted
    }
}

#[OpenApi]
impl Api {
    /// List currently active (unexpired) cached web-approval bypasses across
    /// the whole cluster.
    #[oai(
        path = "/web-approvals",
        method = "get",
        operation_id = "list_web_approvals"
    )]
    async fn list_web_approvals(
        &self,
        req: &Request,
        admin: ClusterOrAdminContext,
    ) -> Result<ListWebApprovalsResponse, WarpgateError> {
        let mut result = local_web_approvals(&admin).await?;

        // Peer-forwarded copies of this request must not fan out again.
        if !is_cluster_peer_request(req, &admin.services().cluster_token) {
            result.extend(web_approvals_from_peers(&admin, req).await);
        }

        Ok(ListWebApprovalsResponse::Ok(Json(result)))
    }

    /// Clear every cached web-approval bypass, on this node and the rest of
    /// the cluster, immediately requiring re-approval for anything that was
    /// relying on one.
    #[oai(
        path = "/web-approvals",
        method = "delete",
        operation_id = "clear_web_approvals"
    )]
    async fn clear_web_approvals(
        &self,
        req: &Request,
        admin: ClusterOrAdminContext,
        /// Clear only this node's own cache instead of the whole cluster's.
        /// Set on cluster-forwarded copies of the request.
        local_only: Query<Option<bool>>,
    ) -> Result<ClearWebApprovalsResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;

        let mut cleared = admin.services().clear_web_approvals().await as u64;

        if !local_only.unwrap_or(false) {
            cleared = cleared.saturating_add(clear_on_peers(&admin, req).await);
        }

        Ok(ClearWebApprovalsResponse::Ok(Json(
            ClearWebApprovalsResult {
                cleared_count: cleared,
            },
        )))
    }

    /// Clear cached web-approval bypasses for a single user, on this node and
    /// the rest of the cluster.
    #[oai(
        path = "/web-approvals/:username",
        method = "delete",
        operation_id = "clear_web_approvals_for_user"
    )]
    async fn clear_web_approvals_for_user(
        &self,
        req: &Request,
        admin: ClusterOrAdminContext,
        username: Path<String>,
        /// Clear only this node's own cache instead of the whole cluster's.
        /// Set on cluster-forwarded copies of the request.
        local_only: Query<Option<bool>>,
    ) -> Result<ClearWebApprovalsResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;

        let mut cleared = admin
            .services()
            .clear_web_approvals_for_user(&username.0)
            .await as u64;

        if !local_only.unwrap_or(false) {
            cleared = cleared.saturating_add(clear_on_peers(&admin, req).await);
        }

        Ok(ClearWebApprovalsResponse::Ok(Json(
            ClearWebApprovalsResult {
                cleared_count: cleared,
            },
        )))
    }

    /// Clear cached web-approval bypasses for a single user, restricted to one
    /// scope (a target, or every target via `all_targets`) — for revoking a
    /// single row of the admin approvals list rather than the whole user.
    #[oai(
        path = "/web-approvals/:username/scope",
        method = "delete",
        operation_id = "clear_web_approval_scope_for_user"
    )]
    #[allow(clippy::too_many_arguments)]
    async fn clear_web_approval_scope_for_user(
        &self,
        req: &Request,
        admin: ClusterOrAdminContext,
        username: Path<String>,
        /// Target name to revoke. Ignored when `all_targets` is set; omitted
        /// together with `all_targets: false` for the untargeted (sign-in)
        /// scope.
        target: Query<Option<String>>,
        /// Revoke the all-targets grant instead of a single target.
        all_targets: Query<Option<bool>>,
        /// Clear only this node's own cache instead of the whole cluster's.
        /// Set on cluster-forwarded copies of the request.
        local_only: Query<Option<bool>>,
    ) -> Result<ClearWebApprovalsResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;

        let scope = scope_key(target.0, all_targets.unwrap_or(false));
        let mut cleared = admin
            .services()
            .clear_web_approvals_for_user_and_scope(&username.0, &scope)
            .await as u64;

        if !local_only.unwrap_or(false) {
            cleared = cleared.saturating_add(clear_on_peers(&admin, req).await);
        }

        Ok(ClearWebApprovalsResponse::Ok(Json(
            ClearWebApprovalsResult {
                cleared_count: cleared,
            },
        )))
    }
}

async fn local_web_approvals(
    ctx: &AuthenticatedRequestContext,
) -> Result<Vec<ActiveWebApprovalInfo>, WarpgateError> {
    Ok(ctx
        .services()
        .list_active_web_approvals()
        .await?
        .into_iter()
        .map(|(key, age)| {
            let age = time::Duration::try_from(age).unwrap_or(time::Duration::ZERO);
            let scope_target = match &key.scope {
                WebApprovalScopeKey::Target(name) => Some(name.clone()),
                WebApprovalScopeKey::Untargeted | WebApprovalScopeKey::AllTargets => None,
            };
            ActiveWebApprovalInfo {
                username: key.username,
                remote_ip: key.remote_ip.to_string(),
                protocol: key.protocol.to_string(),
                scope: scope_label(&key.scope),
                all_targets: matches!(key.scope, WebApprovalScopeKey::AllTargets),
                scope_target,
                granted_at: OffsetDateTime::now_utc() - age,
            }
        })
        .collect())
}

/// The same list from every other node, so the admin UI sees the whole
/// cluster. Best effort: a peer that fails or answers unexpectedly
/// contributes nothing rather than failing the request.
async fn web_approvals_from_peers(
    ctx: &AuthenticatedRequestContext,
    req: &Request,
) -> Vec<ActiveWebApprovalInfo> {
    let mut results = vec![];
    for (hostname, response) in fan_out_to_peers(ctx, req, req.original_uri().path()).await {
        if response.status() != StatusCode::OK {
            let status = response.status();
            warn!(node = %hostname, %status, "Failed to list web approvals on a cluster node");
            continue;
        }
        match parse_forwarded_body::<Vec<ActiveWebApprovalInfo>>(response).await {
            Ok(items) => results.extend(items),
            Err(error) => {
                warn!(node = %hostname, %error, "Malformed web approval list from a cluster node");
            }
        }
    }
    results
}

/// Forward a clear request to every other registered cluster node, summing up
/// how many entries each one cleared.
///
/// Best effort: an unreachable peer is logged, not raised — its cache expires
/// on its own once the grace period elapses.
async fn clear_on_peers(ctx: &AuthenticatedRequestContext, req: &Request) -> u64 {
    // `local_only` stops the peers from fanning out again.
    let separator = if req.original_uri().query().is_some() {
        "&"
    } else {
        "?"
    };
    let path = format!("{}{separator}local_only=true", req.original_uri().path());

    let mut total = 0u64;
    for (hostname, response) in fan_out_to_peers(ctx, req, &path).await {
        if response.status() != StatusCode::OK {
            let status = response.status();
            warn!(node = %hostname, %status, "Failed to clear web approvals on a cluster node");
            continue;
        }
        match parse_forwarded_body::<ClearWebApprovalsResult>(response).await {
            Ok(result) => total = total.saturating_add(result.cleared_count),
            Err(error) => {
                warn!(node = %hostname, %error, "Malformed clear-web-approvals response from a cluster node");
            }
        }
    }
    total
}

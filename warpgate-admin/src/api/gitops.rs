use poem_openapi::param::Query;
use poem_openapi::payload::{Json, PlainText};
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{PaginatorTrait, QuerySelect};
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::{AdminPermission, ProviderId, RowId, WarpgateError};
use warpgate_common_http::errors::bad_request;
use warpgate_core::logging::AuditEvent;
use warpgate_core::resources::sync::{
    DryRun, SyncError, SyncRequest, dry_run, latest, newest_first,
};
use warpgate_core::resources::{OwnedEntity, export, release};
use warpgate_db_entities::ProviderSync::{self, PlanStats, SyncStatus, SyncTrigger};

use super::AdminContext;
use super::limited_json::LimitedJson;
use super::pagination::PaginatedResponse;

pub struct Api;

pub(super) async fn release_managed<E: OwnedEntity>(
    admin: &AdminContext,
    id: E::Id,
) -> Result<(), WarpgateError> {
    admin.require(AdminPermission::ConfigEdit)?;
    if let Some(provider) = release::<E, _>(&admin.services().db, id).await? {
        AuditEvent::ProviderResourceReleased {
            provider: provider.label(),
            kind: format!("{:?}", E::KIND),
            id: id.uuid(),
            actor_user_id: admin.auth.user_id(),
        }
        .emit();
    }
    Ok(())
}

/// Room for the `yaml` of a [`SyncGitopsRequest`], whose line breaks and
/// quotes take two bytes each in JSON.
const SYNC_BODY_LIMIT: usize = 32 * 1024 * 1024;

#[derive(Object)]
struct SyncGitopsRequest {
    /// Prunes even when that deletes most of the managed resources. Has no
    /// effect while pruning is off.
    #[oai(default)]
    force_prune: bool,
    /// Resource documents to use as the full desired state. A sync refuses
    /// them while a source is configured; a dry run doesn't.
    #[oai(validator(max_length = 16000000))]
    yaml: Option<String>,
}

#[derive(Object)]
#[oai(rename = "ProviderSync")]
struct SyncSummary {
    id: Uuid,
    provider: ProviderId,
    triggered_by: SyncTrigger,
    status: SyncStatus,
    started_at: OffsetDateTime,
    checked_at: OffsetDateTime,
    // label / without credentials
    source: String,
    /// The commit, or a hash of the files
    revision: Option<String>,
    // Undocumented: a description here makes the schema wrap the reference,
    // and the client generators then emit a second stats type
    stats: Option<PlanStats>,
    /// mass-deletion guard refuses the sync
    needs_force: bool,
    error: Option<String>,
}

impl From<ProviderSync::Model> for SyncSummary {
    fn from(row: ProviderSync::Model) -> Self {
        Self {
            id: row.id,
            provider: row.provider,
            triggered_by: row.triggered_by,
            status: row.status,
            started_at: row.started_at,
            checked_at: row.checked_at,
            source: row.source,
            revision: row.revision,
            stats: row.plan.as_ref().map(ProviderSync::SyncPlan::stats),
            needs_force: row
                .plan
                .as_ref()
                .is_some_and(ProviderSync::SyncPlan::needs_force),
            error: row.error,
        }
    }
}

#[derive(ApiResponse)]
enum SyncGitopsResponse {
    #[oai(status = 200)]
    Ok(Json<SyncSummary>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
}

#[derive(ApiResponse)]
enum DryRunGitopsResponse {
    #[oai(status = 200)]
    Ok(Json<DryRun>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
}

#[derive(ApiResponse)]
enum ExportGitopsResponse {
    #[oai(status = 200)]
    Ok(PlainText<String>),
}

#[derive(ApiResponse)]
enum GetGitopsHistoryResponse {
    #[oai(status = 200)]
    Ok(Json<PaginatedResponse<SyncSummary>>),
}

#[derive(Object)]
struct GitopsHistoryLatest {
    latest: Option<SyncSummary>,
    latest_success: Option<SyncSummary>,
}

#[derive(ApiResponse)]
enum GetGitopsHistoryLatestResponse {
    #[oai(status = 200)]
    Ok(Json<GitopsHistoryLatest>),
}

#[OpenApi]
impl Api {
    /// Syncs the GitOps source now and waits for the outcome
    #[oai(path = "/gitops/sync", method = "post", operation_id = "sync_gitops")]
    async fn api_sync(
        &self,
        admin: AdminContext,
        body: LimitedJson<SyncGitopsRequest, SYNC_BODY_LIMIT>,
    ) -> Result<SyncGitopsResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;

        let LimitedJson(SyncGitopsRequest { force_prune, yaml }) = body;
        let request = SyncRequest::Admin {
            user_id: admin.auth.user_id(),
            force_prune,
        };
        match admin.services().sync_gitops(request, yaml).await {
            Ok(row) => Ok(SyncGitopsResponse::Ok(Json(row.into()))),
            Err(SyncError::Other(error)) => Err(error),
            Err(error) => Ok(SyncGitopsResponse::BadRequest(bad_request(
                error.to_string(),
            ))),
        }
    }

    /// Fetches and plans the GitOps source like a sync, without applying anything
    #[oai(
        path = "/gitops/dry-run",
        method = "post",
        operation_id = "dry_run_gitops"
    )]
    async fn api_dry_run(
        &self,
        admin: AdminContext,
        body: LimitedJson<SyncGitopsRequest, SYNC_BODY_LIMIT>,
    ) -> Result<DryRunGitopsResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;

        let LimitedJson(SyncGitopsRequest { force_prune, yaml }) = body;
        let services = admin.services();
        let request = SyncRequest::Admin {
            user_id: admin.auth.user_id(),
            force_prune,
        };
        match dry_run(&services.db, &*services.secret_backends, request, yaml).await {
            Ok(dry_run) => Ok(DryRunGitopsResponse::Ok(Json(dry_run))),
            Err(SyncError::Other(error)) => Err(error),
            Err(error) => Ok(DryRunGitopsResponse::BadRequest(bad_request(
                error.to_string(),
            ))),
        }
    }

    /// Every target, group, role and SSH client key that GitOps doesn't
    /// manage yet, as resource documents that adopt them. Contains their
    /// credentials in plain text.
    #[oai(
        path = "/gitops/export",
        method = "get",
        operation_id = "export_gitops_unmanaged"
    )]
    async fn api_export(&self, admin: AdminContext) -> Result<ExportGitopsResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;
        let yaml = export::unmanaged(&admin.services().db).await?;
        AuditEvent::UnmanagedResourcesExported {
            actor_user_id: admin.auth.user_id(),
        }
        .emit();
        Ok(ExportGitopsResponse::Ok(PlainText(yaml)))
    }

    #[oai(
        path = "/gitops/history",
        method = "get",
        operation_id = "get_gitops_history"
    )]
    async fn api_get_history(
        &self,
        admin: AdminContext,
        offset: Query<Option<u64>>,
        #[oai(validator(maximum(value = "1000")))] limit: Query<Option<u64>>,
    ) -> Result<GetGitopsHistoryResponse, WarpgateError> {
        let db = &admin.services().db;
        let query = newest_first();
        let offset = offset.unwrap_or(0);
        let total = query.clone().count(db).await?;
        let items = query
            .offset(offset)
            .limit(limit.unwrap_or(100))
            .all(db)
            .await?;
        Ok(GetGitopsHistoryResponse::Ok(Json(
            PaginatedResponse::from_parts(
                items.into_iter().map(SyncSummary::from).collect(),
                offset,
                total,
            ),
        )))
    }

    #[oai(
        path = "/gitops/history/latest",
        method = "get",
        operation_id = "get_gitops_history_latest"
    )]
    async fn api_get_history_latest(
        &self,
        admin: AdminContext,
    ) -> Result<GetGitopsHistoryLatestResponse, WarpgateError> {
        let db = &admin.services().db;
        let latest_success = latest(db, true).await?;
        let latest = latest(db, false).await?;

        Ok(GetGitopsHistoryLatestResponse::Ok(Json(
            GitopsHistoryLatest {
                latest: latest.map(Into::into),
                latest_success: latest_success.map(Into::into),
            },
        )))
    }
}

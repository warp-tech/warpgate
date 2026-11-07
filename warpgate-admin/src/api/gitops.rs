use poem_openapi::param::Query;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect};
use warpgate_common::{AdminPermission, ProviderId, WarpgateError};
use warpgate_common_http::errors::bad_request;
use warpgate_core::resources::sync::{DryRun, SyncError, SyncRequest, dry_run};
use warpgate_db_entities::ProviderSync::{self, SyncStatus};

use super::AdminContext;
use super::pagination::PaginatedResponse;

pub struct Api;

#[derive(Object)]
struct SyncGitopsRequest {
    /// Deletes what is gone from the source even when that is most of it
    #[oai(default)]
    force_prune: bool,
}

#[derive(ApiResponse)]
enum SyncGitopsResponse {
    #[oai(status = 200)]
    Ok(Json<ProviderSync::Model>),
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
enum GetGitopsHistoryResponse {
    #[oai(status = 200)]
    Ok(Json<PaginatedResponse<ProviderSync::Model>>),
}

#[derive(Object)]
struct GitopsHistoryLatest {
    latest: Option<ProviderSync::Model>,
    latest_success: Option<ProviderSync::Model>,
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
        body: Json<SyncGitopsRequest>,
    ) -> Result<SyncGitopsResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;

        let Json(SyncGitopsRequest { force_prune }) = body;
        match admin
            .services()
            .sync_gitops(SyncRequest::Admin {
                user_id: admin.auth.user_id(),
                force_prune,
            })
            .await
        {
            Ok(row) => Ok(SyncGitopsResponse::Ok(Json(row))),
            Err(error @ SyncError::NotConfigured) => Ok(SyncGitopsResponse::BadRequest(
                bad_request(error.to_string()),
            )),
            Err(SyncError::Other(error)) => Err(error),
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
        body: Json<SyncGitopsRequest>,
    ) -> Result<DryRunGitopsResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;

        let Json(SyncGitopsRequest { force_prune }) = body;
        let services = admin.services();
        let request = SyncRequest::Admin {
            user_id: admin.auth.user_id(),
            force_prune,
        };
        match dry_run(&services.db, &*services.secret_backends, request).await {
            Ok(dry_run) => Ok(DryRunGitopsResponse::Ok(Json(dry_run))),
            Err(error @ SyncError::NotConfigured) => Ok(DryRunGitopsResponse::BadRequest(
                bad_request(error.to_string()),
            )),
            Err(SyncError::Other(error)) => Err(error),
        }
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
        let query = ProviderSync::Entity::find()
            .filter(ProviderSync::Column::Provider.eq(ProviderId::GITOPS))
            .order_by_desc(ProviderSync::Column::StartedAt)
            .order_by_desc(ProviderSync::Column::Id);
        let offset = offset.unwrap_or(0);
        let total = query.clone().count(db).await?;
        let items = query
            .offset(offset)
            .limit(limit.unwrap_or(100))
            .all(db)
            .await?;
        Ok(GetGitopsHistoryResponse::Ok(Json(
            PaginatedResponse::from_parts(items, offset, total),
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
        let base = ProviderSync::Entity::find()
            .filter(ProviderSync::Column::Provider.eq(ProviderId::GITOPS))
            .order_by_desc(ProviderSync::Column::StartedAt)
            .order_by_desc(ProviderSync::Column::Id);

        let latest = base.clone().limit(1).all(db).await?;
        let latest_success = base
            .filter(
                ProviderSync::Column::Status
                    .eq(SyncStatus::Applied)
                    .or(ProviderSync::Column::Status.eq(SyncStatus::Unchanged)),
            )
            .limit(1)
            .all(db)
            .await?;

        Ok(GetGitopsHistoryLatestResponse::Ok(Json(
            GitopsHistoryLatest {
                latest: latest.first().cloned(),
                latest_success: latest_success.first().cloned(),
            },
        )))
    }
}

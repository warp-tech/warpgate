use poem_openapi::param::Query;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect};
use warpgate_common::{AdminPermission, ProviderId, WarpgateError};
use warpgate_common_http::errors::bad_request;
use warpgate_core::resources::sync::SyncError;
use warpgate_db_entities::ProviderSync::{self, SyncTrigger};

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
enum GetGitopsSyncsResponse {
    #[oai(status = 200)]
    Ok(Json<PaginatedResponse<ProviderSync::Model>>),
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
            .sync_gitops(SyncTrigger::Api, force_prune)
            .await
        {
            Ok(row) => Ok(SyncGitopsResponse::Ok(Json(row))),
            Err(error @ SyncError::NotConfigured) => Ok(SyncGitopsResponse::BadRequest(
                bad_request(error.to_string()),
            )),
            Err(SyncError::Other(error)) => Err(error),
        }
    }

    /// Newest first
    #[oai(
        path = "/gitops/syncs",
        method = "get",
        operation_id = "get_gitops_syncs"
    )]
    async fn api_get_syncs(
        &self,
        admin: AdminContext,
        offset: Query<Option<u64>>,
        #[oai(validator(maximum(value = "1000")))] limit: Query<Option<u64>>,
    ) -> Result<GetGitopsSyncsResponse, WarpgateError> {
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
        Ok(GetGitopsSyncsResponse::Ok(Json(
            PaginatedResponse::from_parts(items, offset, total),
        )))
    }
}

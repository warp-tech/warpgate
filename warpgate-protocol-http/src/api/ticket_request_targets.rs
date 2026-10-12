use std::collections::HashSet;

use poem_openapi::param::Query;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::prelude::Expr;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use serde::Serialize;
use warpgate_admin::api::{
    DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, PaginatedResponse, case_insensitive_search_expr,
    count_unordered,
};
use warpgate_common::{Target as TargetConfig, WarpgateError};
use warpgate_common_http::SessionAuthorization;
use warpgate_core::{ConfigProvider, target_access_condition};
use warpgate_db_entities::Target;

use crate::api::auth_scheme::AuthedSession;

pub struct Api;

#[derive(Debug, Serialize, Clone, Object)]
struct TicketRequestTarget {
    pub id: uuid::Uuid,
    pub name: String,
    pub kind: Target::TargetKind,
}

#[derive(ApiResponse)]
enum GetTicketRequestTargetsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<TicketRequestTarget>>),
    #[oai(status = 401)]
    Unauthorized,
    #[oai(status = 403)]
    Forbidden(Json<String>),
}

#[derive(ApiResponse)]
enum GetTicketRequestTargetsPageResponse {
    #[oai(status = 200)]
    Ok(Json<PaginatedResponse<TicketRequestTarget>>),
    #[oai(status = 401)]
    Unauthorized,
    #[oai(status = 403)]
    Forbidden(Json<String>),
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/ticket-request-targets",
        method = "get",
        operation_id = "get_ticket_request_targets"
    )]
    async fn api_get_ticket_request_targets(
        &self,
        ctx: AuthedSession,
    ) -> Result<GetTicketRequestTargetsResponse, WarpgateError> {
        if matches!(
            &ctx.auth,
            warpgate_common_http::RequestAuthorization::Session(
                SessionAuthorization::Ticket { .. }
            )
        ) {
            return Ok(GetTicketRequestTargetsResponse::Unauthorized);
        }

        let services = &ctx.services();

        let policy = ctx.parameters().await?;

        if !policy.ticket_self_service_enabled {
            return Ok(GetTicketRequestTargetsResponse::Forbidden(Json(
                "Self-service tickets are not enabled".into(),
            )));
        }

        let mut targets: Vec<TargetConfig> = services.config_provider.list_targets().await?;

        targets.retain(|t| !t.ticket_requests_disabled);

        if !policy.ticket_request_show_all_targets {
            let authorized_ids = match &ctx.auth {
                warpgate_common_http::RequestAuthorization::AdminToken => HashSet::default(),
                auth => {
                    services
                        .config_provider
                        .authorized_target_ids(auth.user_id())
                        .await?
                }
            };
            targets.retain(|t| authorized_ids.contains(&t.id));
        }

        let result: Vec<TicketRequestTarget> = targets
            .into_iter()
            .map(|t| TicketRequestTarget {
                id: t.id,
                name: t.name,
                kind: (&t.options).into(),
            })
            .collect();

        Ok(GetTicketRequestTargetsResponse::Ok(Json(result)))
    }

    /// Like `get_ticket_request_targets`, but paginated and searchable, with
    /// the filtering done in the database - for when there are many targets.
    #[oai(
        path = "/ticket-request-targets/page",
        method = "get",
        operation_id = "get_ticket_request_targets_page"
    )]
    async fn api_get_ticket_request_targets_page(
        &self,
        ctx: AuthedSession,
        search: Query<Option<String>>,
        offset: Query<Option<u64>>,
        limit: Query<Option<u64>>,
    ) -> Result<GetTicketRequestTargetsPageResponse, WarpgateError> {
        if matches!(
            &ctx.auth,
            warpgate_common_http::RequestAuthorization::Session(
                SessionAuthorization::Ticket { .. }
            )
        ) {
            return Ok(GetTicketRequestTargetsPageResponse::Unauthorized);
        }

        let policy = ctx.parameters().await?;

        if !policy.ticket_self_service_enabled {
            return Ok(GetTicketRequestTargetsPageResponse::Forbidden(Json(
                "Self-service tickets are not enabled".into(),
            )));
        }

        let offset = offset.unwrap_or(0);
        let limit = limit.unwrap_or(DEFAULT_PAGE_SIZE).clamp(1, MAX_PAGE_SIZE);

        let db = &ctx.services().db;
        let mut query = Target::Entity::find()
            .filter(Target::Column::TicketRequestsDisabled.eq(false))
            .order_by_asc(Target::Column::Name);

        if !policy.ticket_request_show_all_targets {
            match &ctx.auth {
                warpgate_common_http::RequestAuthorization::AdminToken => {
                    return Ok(GetTicketRequestTargetsPageResponse::Ok(Json(
                        PaginatedResponse::from_parts(vec![], offset, 0),
                    )));
                }
                auth => {
                    query = query.filter(target_access_condition(db, auth.user_id()).await?);
                }
            }
        }

        if let Some(search) = search.as_deref().filter(|s| !s.is_empty()) {
            query = query.filter(case_insensitive_search_expr(
                search,
                [Expr::col((Target::Entity, Target::Column::Name)).into()],
            ));
        }

        let (total, items) = futures::try_join!(
            count_unordered(query.clone(), db),
            query.offset(offset).limit(limit).all(db),
        )?;
        let items = items
            .into_iter()
            .map(|t| TicketRequestTarget {
                id: t.id,
                name: t.name,
                kind: t.kind,
            })
            .collect();

        Ok(GetTicketRequestTargetsPageResponse::Ok(Json(
            PaginatedResponse::from_parts(items, offset, total),
        )))
    }
}

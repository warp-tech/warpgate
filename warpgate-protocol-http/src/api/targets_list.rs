use std::collections::HashMap;

use poem_openapi::param::Query;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QuerySelect};
use serde::Serialize;
use uuid::Uuid;
use warpgate_admin::api::{DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, PaginatedResponse, count_unordered};
use warpgate_common::{Target as TargetConfig, WarpgateError};
use warpgate_common_http::{RequestAuthorization, SessionAuthorization};
use warpgate_core::{ConfigProvider, target_access_condition};
use warpgate_db_entities::Target::{fuzzy_filter_targets, fuzzy_filter_targets_grouped};
use warpgate_db_entities::TargetGroup::BootstrapThemeColor;
use warpgate_db_entities::{Target, TargetGroup};

use crate::api::auth_scheme::AuthedSession;

pub struct Api;

#[derive(Debug, Serialize, Clone, Object)]
pub struct GroupInfo {
    pub id: uuid::Uuid,
    pub name: String,
    pub color: Option<BootstrapThemeColor>,
}

#[derive(Debug, Serialize, Clone, Object)]
pub struct TargetSnapshot {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub kind: Target::TargetKind,
    pub external_host: Option<String>,
    pub group: Option<GroupInfo>,
    pub default_database_name: Option<String>,
}

impl TargetSnapshot {
    fn new(target: TargetConfig, group: Option<&TargetGroup::Model>) -> Self {
        Self {
            id: target.id,
            kind: (&target.options).into(),
            external_host: target.options.external_host().map(ToString::to_string),
            default_database_name: target
                .options
                .default_database_name()
                .map(ToString::to_string),
            group: group.map(|group| GroupInfo {
                id: group.id,
                name: group.name.clone(),
                color: group.color.clone(),
            }),
            name: target.name,
            description: target.description,
        }
    }
}

#[derive(ApiResponse)]
enum GetTargetsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<TargetSnapshot>>),
}

#[derive(ApiResponse)]
enum GetTargetsPageResponse {
    #[oai(status = 200)]
    Ok(Json<PaginatedResponse<TargetSnapshot>>),
}

#[OpenApi]
impl Api {
    #[oai(path = "/targets", method = "get", operation_id = "get_targets")]
    async fn api_get_all_targets(
        &self,
        ctx: AuthedSession,
        search: Query<Option<String>>,
    ) -> Result<GetTargetsResponse, WarpgateError> {
        // Fetch target groups for group information
        let services = ctx.services();
        let groups: Vec<TargetGroup::Model> = {
            let db = &services.db;
            TargetGroup::Entity::find().all(db).await
        }?;

        let group_map: HashMap<uuid::Uuid, &TargetGroup::Model> =
            groups.iter().map(|g| (g.id, g)).collect();

        let all_targets: Vec<TargetConfig> = services.config_provider.list_targets().await?;

        let mut targets =
            fuzzy_filter_targets(&all_targets, &groups, search.as_deref().unwrap_or_default());

        match &ctx.auth {
            RequestAuthorization::Session(SessionAuthorization::Ticket { target_id, .. }) => {
                targets.retain(|t| t.id == *target_id);
            }
            RequestAuthorization::AdminToken => {
                targets.clear();
            }
            auth => {
                let authorized_ids = services
                    .config_provider
                    .authorized_target_ids(auth.user_id())
                    .await?;
                targets.retain(|t| authorized_ids.contains(&t.id));
            }
        }

        let result: Vec<TargetSnapshot> = targets
            .into_iter()
            .map(|t| {
                let group = t
                    .group_id
                    .and_then(|group_id| group_map.get(&group_id).copied());
                TargetSnapshot::new(t.clone(), group)
            })
            .collect();

        Ok(GetTargetsResponse::Ok(Json(result)))
    }

    /// Like `get_targets`, but paginated, with sorting and access filtering
    /// done in the database - for when there are many targets. A search is
    /// fuzzy-ranked here instead, over every accessible target.
    #[oai(
        path = "/targets/page",
        method = "get",
        operation_id = "get_targets_page"
    )]
    async fn api_get_targets_page(
        &self,
        ctx: AuthedSession,
        search: Query<Option<String>>,
        offset: Query<Option<u64>>,
        limit: Query<Option<u64>>,
    ) -> Result<GetTargetsPageResponse, WarpgateError> {
        let offset = offset.unwrap_or(0);
        let limit = limit.unwrap_or(DEFAULT_PAGE_SIZE).clamp(1, MAX_PAGE_SIZE);

        let db = &ctx.services().db;
        let mut query = Target::Entity::find_grouped();

        match &ctx.auth {
            RequestAuthorization::Session(SessionAuthorization::Ticket { target_id, .. }) => {
                query = query.filter(Target::Column::Id.eq(*target_id));
            }
            RequestAuthorization::AdminToken => {
                return Ok(GetTargetsPageResponse::Ok(Json(
                    PaginatedResponse::from_parts(vec![], offset, 0),
                )));
            }
            auth => {
                query = query.filter(target_access_condition(db, auth.user_id()).await?);
            }
        }

        if let Some(search) = search.as_deref().filter(|s| !s.is_empty()) {
            // Fuzzy ranking can't be done in SQL, so this loads every
            // accessible target and only returns the requested page of them
            let (targets, groups) =
                futures::try_join!(query.all(db), TargetGroup::Entity::find().all(db))?;
            let group_map: HashMap<Uuid, &TargetGroup::Model> =
                groups.iter().map(|g| (g.id, g)).collect();
            let ranked = fuzzy_filter_targets_grouped(&targets, &groups, search);
            let total = ranked.len() as u64;
            let items = ranked
                .into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .map(|target| {
                    let group = target
                        .group_id
                        .and_then(|group_id| group_map.get(&group_id).copied());
                    let target: TargetConfig = target.clone().try_into()?;
                    Ok(TargetSnapshot::new(target, group))
                })
                .collect::<Result<Vec<_>, WarpgateError>>()?;

            return Ok(GetTargetsPageResponse::Ok(Json(
                PaginatedResponse::from_parts(items, offset, total),
            )));
        }

        let (total, items) = futures::try_join!(
            count_unordered(query.clone(), db),
            query
                .select_also(TargetGroup::Entity)
                .offset(offset)
                .limit(limit)
                .all(db),
        )?;
        let items = items
            .into_iter()
            .map(|(target, group)| {
                let target: TargetConfig = target.try_into()?;
                Ok(TargetSnapshot::new(target, group.as_ref()))
            })
            .collect::<Result<Vec<_>, WarpgateError>>()?;

        Ok(GetTargetsPageResponse::Ok(Json(
            PaginatedResponse::from_parts(items, offset, total),
        )))
    }
}

use std::collections::HashMap;

use poem_openapi::param::Query;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::EntityTrait;
use serde::Serialize;
use uuid::Uuid;
use warpgate_common::{Target as TargetConfig, WarpgateError};
use warpgate_common_http::{RequestAuthorization, SessionAuthorization};
use warpgate_core::ConfigProvider;
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

#[derive(ApiResponse)]
enum GetTargetsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<TargetSnapshot>>),
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

        let mut targets: Vec<TargetConfig> = services.config_provider.list_targets().await?;

        if let Some(ref search) = *search {
            let search = search.to_lowercase();
            targets.retain(|t| {
                let group = t.group_id.and_then(|group_id| group_map.get(&group_id));
                t.name.to_lowercase().contains(&search)
                    || group.is_some_and(|g| g.name.to_lowercase().contains(&search))
            });
        }

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
                let group = t.group_id.and_then(|group_id| {
                    group_map.get(&group_id).map(|group| GroupInfo {
                        id: group.id,
                        name: group.name.clone(),
                        color: group.color.clone(),
                    })
                });

                TargetSnapshot {
                    id: t.id,
                    name: t.name.clone(),
                    description: t.description.clone(),
                    kind: (&t.options).into(),
                    external_host: t.options.external_host().map(ToString::to_string),
                    default_database_name: t
                        .options
                        .default_database_name()
                        .map(ToString::to_string),
                    group,
                }
            })
            .collect();

        Ok(GetTargetsResponse::Ok(Json(result)))
    }
}

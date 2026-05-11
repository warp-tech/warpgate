use std::collections::HashMap;

use futures::{StreamExt, stream};
use poem::web::Data;
use poem_openapi::param::Query;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::EntityTrait;
use serde::Serialize;
use warpgate_common::{Target as TargetConfig, TargetOptions, WarpgateError};
use warpgate_common_http::{
    AuthenticatedRequestContext, RequestAuthorization, SessionAuthorization,
};
use warpgate_core::ConfigProvider;
use warpgate_db_entities::TargetGroup::BootstrapThemeColor;
use warpgate_db_entities::{Target, TargetGroup};

use crate::api::AnySecurityScheme;
use crate::common::endpoint_auth;

pub struct Api;

#[derive(Debug, Serialize, Clone, Object)]
pub struct GroupInfo {
    pub id: uuid::Uuid,
    pub name: String,
    pub color: Option<BootstrapThemeColor>,
}

#[derive(Debug, Serialize, Clone, Object)]
pub struct TargetSnapshot {
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
    #[oai(
        path = "/targets",
        method = "get",
        operation_id = "get_targets",
        transform = "endpoint_auth"
    )]
    async fn api_get_all_targets(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        search: Query<Option<String>>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetTargetsResponse, WarpgateError> {
        // Fetch target groups for group information
        let services = ctx.services();
        let groups: Vec<TargetGroup::Model> = {
            let db = services.db.lock().await;
            TargetGroup::Entity::find().all(&*db).await
        }?;

        let group_map: HashMap<uuid::Uuid, &TargetGroup::Model> =
            groups.iter().map(|g| (g.id, g)).collect();

        let mut targets: Vec<TargetConfig> = {
            let mut config_provider = services.config_provider.lock().await;
            config_provider.list_targets().await?
        };

        if let Some(ref search) = *search {
            let search = search.to_lowercase();
            targets.retain(|t| {
                let group = t.group_id.and_then(|group_id| group_map.get(&group_id));
                t.name.to_lowercase().contains(&search)
                    || group.is_some_and(|g| g.name.to_lowercase().contains(&search))
            });
        }

        let auth_clone = ctx.auth.clone();
        let targets: Vec<_> = stream::iter(targets)
            .filter(|t| {
                let services = services.clone();
                let auth = auth_clone.clone();
                let name = t.name.clone();
                async move {
                    if let RequestAuthorization::Session(SessionAuthorization::Ticket {
                        target_name,
                        ..
                    }) = auth
                    {
                        target_name == name
                    } else {
                        let mut config_provider = services.config_provider.lock().await;
                        let Some(username) = auth.username() else {
                            return false;
                        };
                        matches!(
                            config_provider.authorize_target(username, &name).await,
                            Ok(true)
                        )
                    }
                }
            })
            .collect::<Vec<_>>()
            .await;

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
                    name: t.name.clone(),
                    description: t.description.clone(),
                    kind: (&t.options).into(),
                    external_host: match t.options {
                        TargetOptions::Http(ref opt) => opt.external_host.clone(),
                        _ => None,
                    },
                    default_database_name: match t.options {
                        TargetOptions::Postgres(ref opt) => opt.default_database_name.clone(),
                        TargetOptions::MySql(ref opt) => opt.default_database_name.clone(),
                        _ => None,
                    },
                    group,
                }
            })
            .collect();

        Ok(GetTargetsResponse::Ok(Json(result)))
    }
}

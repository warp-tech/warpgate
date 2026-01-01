use std::collections::HashMap;

use futures::{stream, StreamExt};
use poem::web::Data;
use poem_openapi::param::Query;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::EntityTrait;
use serde::Serialize;
use warpgate_common::{TargetOptions, WarpgateError};
use warpgate_core::{ConfigProvider, Services};
use warpgate_db_entities::TargetGroup::BootstrapThemeColor;
use warpgate_db_entities::{Target, TargetGroup};

use crate::api::AnySecurityScheme;
use crate::common::{endpoint_auth, RequestAuthorization, SessionAuthorization};

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
        services: Data<&Services>,
        auth: Data<&RequestAuthorization>,
        search: Query<Option<String>>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetTargetsResponse, WarpgateError> {
        // Fetch target groups for group information
        let groups: Vec<TargetGroup::Model> = {
            let db = services.db.lock().await;
            TargetGroup::Entity::find().all(&*db).await
        }?;

        let group_map: HashMap<uuid::Uuid, &TargetGroup::Model> =
            groups.iter().map(|g| (g.id, g)).collect();

        let mut targets = {
            let mut config_provider = services.config_provider.lock().await;
            config_provider.list_targets().await?
        };

        if let Some(ref search) = *search {
            let search = search.to_lowercase();
            targets.retain(|t| {
                let group = t.group_id.and_then(|group_id| group_map.get(&group_id));
                t.name.to_lowercase().contains(&search)
                    || group
                        .map(|g| g.name.to_lowercase().contains(&search))
                        .unwrap_or(false)
            })
        }

        let targets = stream::iter(targets)
            .filter(|t| {
                let services = services.clone();
                let auth = auth.clone();
                let name = t.name.clone();
                async move {
                    match auth {
                        RequestAuthorization::Session(SessionAuthorization::Ticket {
                            target_name,
                            ..
                        }) => target_name == name,
                        _ => {
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
                    group,
                }
            })
            .collect();

        Ok(GetTargetsResponse::Ok(Json(result)))
    }
}

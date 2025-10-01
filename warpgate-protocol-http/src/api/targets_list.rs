use futures::{stream, StreamExt};
use poem::web::Data;
use poem_openapi::param::Query;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::EntityTrait;
use serde::Serialize;
use warpgate_common::TargetOptions;
use warpgate_core::{ConfigProvider, Services};
use warpgate_db_entities::{Target, TargetGroup};

use crate::api::AnySecurityScheme;
use crate::common::{endpoint_auth, RequestAuthorization, SessionAuthorization};

pub struct Api;

#[derive(Debug, Serialize, Clone, Object)]
pub struct TargetSnapshot {
    pub name: String,
    pub description: String,
    pub kind: Target::TargetKind,
    pub external_host: Option<String>,
    pub group_id: Option<uuid::Uuid>,
    pub group_name: Option<String>,
    pub group_color: Option<String>,
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
    ) -> poem::Result<GetTargetsResponse> {
        let mut targets = {
            let mut config_provider = services.config_provider.lock().await;
            config_provider.list_targets().await?
        };

        if let Some(ref search) = *search {
            let search = search.to_lowercase();
            targets.retain(|t| t.name.to_lowercase().contains(&search))
        }

        let mut targets = stream::iter(targets)
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
        targets.sort_by(|a, b| a.name.cmp(&b.name));

        // Debug: Log target group information
        tracing::info!("Processing {} targets", targets.len());
        for target in &targets {
            tracing::info!("Target: {} (group_id: {:?})", target.name, target.group_id);
        }

        // Fetch target groups for group information
        let groups = {
            let db = services.db.lock().await;
            let result = TargetGroup::Entity::find()
                .all(&*db)
                .await;
            match result {
                Ok(groups) => {
                    tracing::info!("Found {} target groups", groups.len());
                    for group in &groups {
                        tracing::info!("Group: {} (id: {})", group.name, group.id);
                    }
                    groups
                }
                Err(e) => {
                    tracing::error!("Failed to fetch target groups: {}", e);
                    Vec::new()
                }
            }
        };
        let group_map: std::collections::HashMap<uuid::Uuid, &TargetGroup::Model> =
            groups.iter().map(|g| (g.id, g)).collect();

        let result: Vec<TargetSnapshot> = targets
            .into_iter()
            .map(|t| {
                let group_info = t.group_id.and_then(|group_id| {
                    group_map.get(&group_id).map(|group| (group.name.clone(), group.color.clone()))
                });

                let snapshot = TargetSnapshot {
                    name: t.name.clone(),
                    description: t.description.clone(),
                    kind: (&t.options).into(),
                    external_host: match t.options {
                        TargetOptions::Http(ref opt) => opt.external_host.clone(),
                        _ => None,
                    },
                    group_id: t.group_id,
                    group_name: group_info.as_ref().map(|(name, _): &(String, Option<String>)| name.clone()),
                    group_color: group_info.as_ref().and_then(|(_, color): &(String, Option<String>)| color.clone()),
                };

                tracing::info!("Final snapshot for {}: group_id={:?}, group_name={:?}, group_color={:?}",
                    snapshot.name, snapshot.group_id, snapshot.group_name, snapshot.group_color);

                snapshot
            })
            .collect();

        Ok(GetTargetsResponse::Ok(Json(result)))
    }
}

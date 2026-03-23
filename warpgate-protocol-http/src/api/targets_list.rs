use std::collections::HashMap;

use futures::{stream, StreamExt};
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
use warpgate_db_entities::{Parameters, Target, TargetGroup};

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
    pub ticket_max_duration_seconds: Option<i64>,
    pub ticket_max_uses: Option<i16>,
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
        for_ticket_request: Query<Option<bool>>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetTargetsResponse, WarpgateError> {
        // Fetch target groups for group information
        let services = &ctx.services;
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
                    || group
                        .map(|g| g.name.to_lowercase().contains(&search))
                        .unwrap_or(false)
            })
        }

        let is_ticket_request = for_ticket_request.unwrap_or(false);

        // Filter out targets with ticket requests disabled
        if is_ticket_request {
            targets.retain(|t| !t.ticket_requests_disabled);
        }

        // Check if we should skip auth filtering for ticket requests
        let skip_auth_filter = if is_ticket_request {
            let db = services.db.lock().await;
            let params = Parameters::Entity::get(&db).await?;
            params.ticket_self_service_enabled && params.ticket_request_show_all_targets
        } else {
            false
        };

        // Build a set of target names the user is authorized for
        let authorized_names: std::collections::HashSet<String> = {
            let auth_clone = ctx.auth.clone();
            stream::iter(targets.iter())
                .filter_map(|t| {
                    let services = services.clone();
                    let auth = auth_clone.clone();
                    let name = t.name.clone();
                    async move {
                        let authorized = match auth {
                            RequestAuthorization::Session(SessionAuthorization::Ticket {
                                ref target_name,
                                ..
                            }) => *target_name == name,
                            _ => {
                                let mut config_provider =
                                    services.config_provider.lock().await;
                                let Some(username) = auth.username() else {
                                    return None;
                                };
                                matches!(
                                    config_provider.authorize_target(username, &name).await,
                                    Ok(true)
                                )
                            }
                        };
                        if authorized {
                            Some(name)
                        } else {
                            None
                        }
                    }
                })
                .collect::<std::collections::HashSet<_>>()
                .await
        };

        // If not showing all targets, filter to only authorized ones
        let targets: Vec<_> = if skip_auth_filter {
            targets
        } else {
            targets
                .into_iter()
                .filter(|t| authorized_names.contains(&t.name))
                .collect()
        };

        let result: Vec<TargetSnapshot> = targets
            .into_iter()
            .map(|t| {
                let authorized = authorized_names.contains(&t.name);
                let group = t.group_id.and_then(|group_id| {
                    group_map.get(&group_id).map(|group| GroupInfo {
                        id: group.id,
                        name: group.name.clone(),
                        color: group.color.clone(),
                    })
                });

                TargetSnapshot {
                    name: t.name.clone(),
                    // Only expose sensitive details to authorized users
                    description: if authorized {
                        t.description.clone()
                    } else {
                        String::new()
                    },
                    kind: (&t.options).into(),
                    external_host: if authorized {
                        match t.options {
                            TargetOptions::Http(ref opt) => opt.external_host.clone(),
                            _ => None,
                        }
                    } else {
                        None
                    },
                    default_database_name: if authorized {
                        match t.options {
                            TargetOptions::Postgres(ref opt) => {
                                opt.default_database_name.clone()
                            }
                            TargetOptions::MySql(ref opt) => opt.default_database_name.clone(),
                            _ => None,
                        }
                    } else {
                        None
                    },
                    group,
                    ticket_max_duration_seconds: if authorized {
                        t.ticket_max_duration_seconds
                    } else {
                        None
                    },
                    ticket_max_uses: if authorized {
                        t.ticket_max_uses
                    } else {
                        None
                    },
                }
            })
            .collect();

        Ok(GetTargetsResponse::Ok(Json(result)))
    }
}

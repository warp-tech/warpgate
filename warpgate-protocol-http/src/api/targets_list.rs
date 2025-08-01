use futures::{stream, StreamExt};
use poem::web::Data;
use poem_openapi::param::Query;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use serde::Serialize;
use warpgate_common::helpers::locks::DebugLock;
use warpgate_common::TargetOptions;
use warpgate_core::{ConfigProvider, Services};
use warpgate_db_entities::Target;

use crate::api::AnySecurityScheme;
use crate::common::{endpoint_auth, RequestAuthorization, SessionAuthorization};

pub struct Api;

#[derive(Debug, Serialize, Clone, Object)]
pub struct TargetSnapshot {
    pub name: String,
    pub description: String,
    pub kind: Target::TargetKind,
    pub external_host: Option<String>,
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
            let mut config_provider = services.config_provider.lock2().await;
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
                            let mut config_provider = services.config_provider.lock2().await;
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

        Ok(GetTargetsResponse::Ok(Json(
            targets
                .into_iter()
                .map(|t| TargetSnapshot {
                    name: t.name.clone(),
                    description: t.description.clone(),
                    kind: (&t.options).into(),
                    external_host: match t.options {
                        TargetOptions::Http(ref opt) => opt.external_host.clone(),
                        _ => None,
                    },
                })
                .collect(),
        )))
    }
}

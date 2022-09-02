use futures::{stream, StreamExt};
use poem::web::Data;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use serde::Serialize;
use warpgate_common::TargetOptions;
use warpgate_core::Services;
use warpgate_db_entities::Target;

use crate::common::{endpoint_auth, SessionAuthorization};

pub struct Api;

#[derive(Debug, Serialize, Clone, Object)]
pub struct TargetSnapshot {
    pub name: String,
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
        auth: Data<&SessionAuthorization>,
    ) -> poem::Result<GetTargetsResponse> {
        let targets = {
            let mut config_provider = services.config_provider.lock().await;
            config_provider.list_targets().await?
        };
        let mut targets = stream::iter(targets)
            .filter(|t| {
                let services = services.clone();
                let auth = auth.clone();
                let name = t.name.clone();
                async move {
                    match auth {
                        SessionAuthorization::Ticket { target_name, .. } => target_name == name,
                        SessionAuthorization::User(_) => {
                            let mut config_provider = services.config_provider.lock().await;

                            matches!(
                                config_provider
                                    .authorize_target(auth.username(), &name)
                                    .await,
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
                    kind: match t.options {
                        TargetOptions::Ssh(_) => Target::TargetKind::Ssh,
                        TargetOptions::Http(_) => Target::TargetKind::Http,
                        TargetOptions::MySql(_) => Target::TargetKind::MySql,
                        TargetOptions::WebAdmin(_) => Target::TargetKind::WebAdmin,
                    },
                    external_host: match t.options {
                        TargetOptions::Http(ref opt) => opt.external_host.clone(),
                        _ => None,
                    },
                })
                .collect(),
        )))
    }
}

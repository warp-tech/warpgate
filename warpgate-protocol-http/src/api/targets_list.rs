use futures::{stream, StreamExt};
use poem::web::Data;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Enum, Object, OpenApi};
use serde::Serialize;
use warpgate_common::{Services, TargetOptions};

use crate::common::{endpoint_auth, SessionAuthorization};

pub struct Api;

#[derive(Debug, Serialize, Clone, Enum)]
pub enum TargetKind {
    Http,
    MySql,
    Ssh,
    WebAdmin,
}

#[derive(Debug, Serialize, Clone, Object)]
pub struct Target {
    pub name: String,
    pub kind: TargetKind,
    pub external_host: Option<String>,
}

#[derive(ApiResponse)]
enum GetTargetsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<Target>>),
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
                            match config_provider
                                .authorize_target(auth.username(), &name)
                                .await
                            {
                                Ok(true) => true,
                                _ => false,
                            }
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
                .map(|t| Target {
                    name: t.name.clone(),
                    kind: match t.options {
                        TargetOptions::Ssh(_) => TargetKind::Ssh,
                        TargetOptions::Http(_) => TargetKind::Http,
                        TargetOptions::MySql(_) => TargetKind::MySql,
                        TargetOptions::WebAdmin(_) => TargetKind::WebAdmin,
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

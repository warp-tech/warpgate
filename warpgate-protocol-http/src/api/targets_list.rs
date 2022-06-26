use crate::common::{endpoint_auth, SessionUsername};
use futures::stream::{self};
use futures::StreamExt;
use poem::web::Data;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Enum, Object, OpenApi};
use serde::Serialize;
use warpgate_common::{Services, TargetOptions};

pub struct Api;

#[derive(Debug, Serialize, Clone, Enum)]
pub enum TargetKind {
    Http,
    Ssh,
    WebAdmin,
}

#[derive(Debug, Serialize, Clone, Object)]
pub struct Target {
    pub name: String,
    pub kind: TargetKind,
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
        username: Data<&SessionUsername>,
    ) -> poem::Result<GetTargetsResponse> {
        let targets = {
            let mut config_provider = services.config_provider.lock().await;
            config_provider.list_targets().await?
        };
        let mut targets = stream::iter(targets)
            .filter_map(|t| {
                let services = services.clone();
                let username = &username;
                async move {
                    let mut config_provider = services.config_provider.lock().await;
                    match config_provider.authorize_target(&username.0.0, &t.name).await {
                        Ok(true) => Some(t),
                        _ => None,
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
                        TargetOptions::WebAdmin(_) => TargetKind::WebAdmin,
                    },
                })
                .collect(),
        )))
    }
}

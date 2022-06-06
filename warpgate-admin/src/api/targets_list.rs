use crate::helpers::{ApiResult, endpoint_auth};
use poem::web::Data;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, OpenApi};
use std::sync::Arc;
use tokio::sync::Mutex;
use warpgate_common::{ConfigProvider, Target};

pub struct Api;

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
        config_provider: Data<&Arc<Mutex<dyn ConfigProvider + Send>>>,
    ) -> ApiResult<GetTargetsResponse> {
        let mut targets = config_provider.lock().await.list_targets().await?;
        targets.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(GetTargetsResponse::Ok(Json(targets)))
    }
}

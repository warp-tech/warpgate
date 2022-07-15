use std::sync::Arc;

use poem::web::Data;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, OpenApi};
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
    #[oai(path = "/targets", method = "get", operation_id = "get_targets")]
    async fn api_get_all_targets(
        &self,
        config_provider: Data<&Arc<Mutex<dyn ConfigProvider + Send>>>,
    ) -> poem::Result<GetTargetsResponse> {
        let mut targets = config_provider.lock().await.list_targets().await?;
        targets.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(GetTargetsResponse::Ok(Json(targets)))
    }
}

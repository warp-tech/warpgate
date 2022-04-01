use crate::helpers::{authorized, ApiResult};
use poem::session::Session;
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
    #[oai(path = "/targets", method = "get", operation_id = "get_targets")]
    async fn api_get_all_targets(
        &self,
        config_provider: Data<&Arc<Mutex<dyn ConfigProvider + Send>>>,
        session: &Session,
    ) -> ApiResult<GetTargetsResponse> {
        authorized(session, || async move {
            let targets = config_provider.lock().await.list_targets().await?;
            Ok(GetTargetsResponse::Ok(Json(targets)))
        })
        .await
    }
}

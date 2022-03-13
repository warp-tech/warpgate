use crate::helpers::ApiResult;
use poem::web::Data;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, OpenApi};
use std::sync::Arc;
use tokio::sync::Mutex;
use warpgate_common::{ConfigProvider, UserSnapshot};

pub struct Api;

#[derive(ApiResponse)]
enum GetUsersResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<UserSnapshot>>),
}

#[OpenApi]
impl Api {
    #[oai(path = "/users", method = "get", operation_id = "get_users")]
    async fn api_get_all_users(
        &self,
        config_provider: Data<&Arc<Mutex<dyn ConfigProvider + Send>>>,
    ) -> ApiResult<GetUsersResponse> {
        let users = config_provider.lock().await.list_users().await?;
        Ok(GetUsersResponse::Ok(Json(users)))
    }
}

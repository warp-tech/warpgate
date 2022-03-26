use crate::helpers::ApiResult;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, OpenApi, Object};
use serde::Serialize;

pub struct Api;

#[derive(Serialize, Object)]
pub struct InstanceInfo {
    version: String,
}

#[derive(ApiResponse)]
enum InstanceInfoResponse {
    #[oai(status = 200)]
    Ok(Json<InstanceInfo>),
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/instance",
        method = "get",
        operation_id = "get_instance_info"
    )]
    async fn api_get_instance_info(
        &self,
    ) -> ApiResult<InstanceInfoResponse> {
        return Ok(InstanceInfoResponse::Ok(Json(InstanceInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
        })));
    }
}

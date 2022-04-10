use crate::helpers::ApiResult;
use poem::session::Session;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use serde::Serialize;

pub struct Api;

#[derive(Serialize, Object)]
pub struct Info {
    version: String,
    username: Option<String>,
}

#[derive(ApiResponse)]
enum InstanceInfoResponse {
    #[oai(status = 200)]
    Ok(Json<Info>),
}

#[OpenApi]
impl Api {
    #[oai(path = "/info", method = "get", operation_id = "get_info")]
    async fn api_get_info(&self, session: &Session) -> ApiResult<InstanceInfoResponse> {
        Ok(InstanceInfoResponse::Ok(Json(Info {
            version: env!("CARGO_PKG_VERSION").to_string(),
            username: session.get::<String>("username"),
        })))
    }
}

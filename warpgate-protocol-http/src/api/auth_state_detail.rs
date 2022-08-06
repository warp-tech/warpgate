use poem::web::Data;
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use uuid::Uuid;
use warpgate_common::Services;

use crate::common::SessionAuthorization;

pub struct Api;

#[derive(Object)]
pub struct AuthStateDescription {
    pub protocol: String,
}

#[derive(ApiResponse)]
enum GetAuthStateResponse {
    #[oai(status = 200)]
    Ok(Json<AuthStateDescription>),
    #[oai(status = 404)]
    NotFound,
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/auth/state/:id",
        method = "get",
        operation_id = "get_auth_state"
    )]
    async fn api_get_auth_state(
        &self,
        services: Data<&Services>,
        auth: Data<&SessionAuthorization>,
        id: Path<Uuid>,
    ) -> poem::Result<GetAuthStateResponse> {
        let store = services.auth_state_store.lock().await;

        let SessionAuthorization::User(username) = *auth else {
            return Ok(GetAuthStateResponse::NotFound);
        };

        let Some(state_arc) = store.get(&*id) else {
            return Ok(GetAuthStateResponse::NotFound);
        };

        let state = state_arc.lock().await;

        Ok(GetAuthStateResponse::Ok(Json(AuthStateDescription {
            protocol: state.protocol().to_string(),
        })))
    }
}

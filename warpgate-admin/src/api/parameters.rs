use poem::web::Data;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{EntityTrait, Set};
use serde::Serialize;
use warpgate_common::WarpgateError;
use warpgate_core::Services;
use warpgate_db_entities::Parameters;

use super::AnySecurityScheme;

pub struct Api;

#[derive(Serialize, Object)]
struct ParameterValues {
    pub allow_own_credential_management: bool,
}

#[derive(Serialize, Object)]
struct ParameterUpdate {
    pub allow_own_credential_management: Option<bool>,
}

#[derive(ApiResponse)]
enum GetParametersResponse {
    #[oai(status = 200)]
    Ok(Json<ParameterValues>),
}

#[derive(ApiResponse)]
enum UpdateParametersResponse {
    #[oai(status = 201)]
    Done,
}

#[OpenApi]
impl Api {
    #[oai(path = "/parameters", method = "get", operation_id = "get_parameters")]
    async fn api_get(
        &self,
        services: Data<&Services>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetParametersResponse, WarpgateError> {
        let db = services.db.lock().await;
        let parameters = Parameters::Entity::get(&db).await?;

        Ok(GetParametersResponse::Ok(Json(ParameterValues {
            allow_own_credential_management: parameters.allow_own_credential_management,
        })))
    }

    #[oai(
        path = "/parameters",
        method = "patch",
        operation_id = "update_parameters"
    )]
    async fn api_update_parameters(
        &self,
        services: Data<&Services>,
        body: Json<ParameterUpdate>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<UpdateParametersResponse, WarpgateError> {
        let db = services.db.lock().await;

        let mut am = Parameters::ActiveModel {
            id: Set(Parameters::Entity::get(&db).await?.id),
            ..Default::default()
        };

        if let Some(value) = body.allow_own_credential_management {
            am.allow_own_credential_management = Set(value);
        };

        Parameters::Entity::update(am).exec(&*db).await?;

        Ok(UpdateParametersResponse::Done)
    }
}

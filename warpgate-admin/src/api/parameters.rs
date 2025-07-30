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
    pub rate_limit_bytes_per_second: Option<u32>,
}

#[derive(Serialize, Object)]
struct ParameterUpdate {
    pub allow_own_credential_management: bool,
    pub rate_limit_bytes_per_second: Option<u32>,
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
            rate_limit_bytes_per_second: parameters.rate_limit_bytes_per_second.map(|x| x as u32),
        })))
    }

    #[oai(
        path = "/parameters",
        method = "put",
        operation_id = "update_parameters"
    )]
    async fn api_update_parameters(
        &self,
        services: Data<&Services>,
        body: Json<ParameterUpdate>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<UpdateParametersResponse, WarpgateError> {
        let db = services.db.lock().await;

        let am = Parameters::ActiveModel {
            id: Set(Parameters::Entity::get(&db).await?.id),
            allow_own_credential_management: Set(body.allow_own_credential_management),
            rate_limit_bytes_per_second: Set(body.rate_limit_bytes_per_second.map(|x| x as i64)),
        };

        Parameters::Entity::update(am).exec(&*db).await?;
        drop(db);

        // TODO encapsulate
        {
            services
                .rate_limiter_registry
                .lock()
                .await
                .refresh()
                .await?;
            let mut rate_limiter_registry = services.rate_limiter_registry.lock().await;

            for session_state in services.state.lock().await.sessions.values() {
                let mut session_state = session_state.lock().await;
                rate_limiter_registry
                    .update_all_rate_limiters(&mut session_state)
                    .await?;
            }
        }

        Ok(UpdateParametersResponse::Done)
    }
}

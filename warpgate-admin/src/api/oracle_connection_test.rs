use poem_openapi::payload::{Json, PlainText};
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::EntityTrait;
use uuid::Uuid;
use warpgate_common::{AdminPermission, Target as TargetConfig, TargetOptions, WarpgateError};
use warpgate_db_entities::Target;

use super::AdminContext;

pub struct Api;

#[derive(Object)]
struct TestOracleConnectionRequest {
    target_id: Uuid,
}

#[derive(Object)]
struct TestOracleConnectionResponseBody {
    message: String,
}

#[derive(ApiResponse)]
enum TestOracleConnectionResponse {
    #[oai(status = 200)]
    Ok(Json<TestOracleConnectionResponseBody>),
    /// The target does not exist, or it is not an Oracle target.
    #[oai(status = 400)]
    BadRequest(PlainText<String>),
    /// The test itself failed (unreachable, TLS, unknown service, or bad
    /// credentials); the body carries a message for the operator.
    #[oai(status = 500)]
    Error(PlainText<String>),
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/oracle/test-connection",
        method = "post",
        operation_id = "test_oracle_connection"
    )]
    async fn api_test_oracle_connection(
        &self,
        admin: AdminContext,
        body: Json<TestOracleConnectionRequest>,
    ) -> Result<TestOracleConnectionResponse, WarpgateError> {
        admin.require(AdminPermission::TargetsEdit)?;

        let services = admin.services();

        let Some(model) = Target::Entity::find_by_id(body.target_id)
            .one(&services.db)
            .await?
        else {
            return Ok(TestOracleConnectionResponse::BadRequest(PlainText(
                "No such target".into(),
            )));
        };

        // Not redacted: resolving the password needs the real secret reference,
        // and this endpoint already requires `TargetsEdit`.
        let target: TargetConfig = model.try_into()?;
        let TargetOptions::Oracle(options) = target.options else {
            return Ok(TestOracleConnectionResponse::BadRequest(PlainText(
                "Target is not an Oracle target".into(),
            )));
        };

        // Matched manually (not `?`) so the nested error chain can be formatted
        // with `{:#}` into the operator-facing message, like the SSH endpoint.
        match warpgate_protocol_oracle::test_connection(&options, &*services.secret_backends).await {
            Ok(message) => Ok(TestOracleConnectionResponse::Ok(Json(
                TestOracleConnectionResponseBody { message },
            ))),
            Err(err) => Ok(TestOracleConnectionResponse::Error(PlainText(format!(
                "{err:#}"
            )))),
        }
    }
}

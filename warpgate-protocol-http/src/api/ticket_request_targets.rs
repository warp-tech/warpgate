use futures::{StreamExt, stream};
use poem::web::Data;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use serde::Serialize;
use warpgate_common::{Target as TargetConfig, WarpgateError};
use warpgate_common_http::SessionAuthorization;
use warpgate_common_http::auth::AuthenticatedRequestContext;
use warpgate_core::ConfigProvider;
use warpgate_db_entities::{Parameters, Target};

use crate::api::AnySecurityScheme;
use crate::common::endpoint_auth;

pub struct Api;

#[derive(Debug, Serialize, Clone, Object)]
struct TicketRequestTarget {
    pub id: uuid::Uuid,
    pub name: String,
    pub kind: Target::TargetKind,
}

#[derive(ApiResponse)]
enum GetTicketRequestTargetsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<TicketRequestTarget>>),
    #[oai(status = 401)]
    Unauthorized,
    #[oai(status = 403)]
    Forbidden(Json<String>),
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/ticket-request-targets",
        method = "get",
        operation_id = "get_ticket_request_targets",
        transform = "endpoint_auth"
    )]
    async fn api_get_ticket_request_targets(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetTicketRequestTargetsResponse, WarpgateError> {
        if matches!(
            &ctx.auth,
            warpgate_common_http::RequestAuthorization::Session(
                SessionAuthorization::Ticket { .. }
            )
        ) {
            return Ok(GetTicketRequestTargetsResponse::Unauthorized);
        }

        let services = &ctx.services();

        let policy = {
            let db = services.db.lock().await;
            Parameters::Entity::get(&db).await?
        };

        if !policy.ticket_self_service_enabled {
            return Ok(GetTicketRequestTargetsResponse::Forbidden(Json(
                "Self-service tickets are not enabled".into(),
            )));
        }

        let mut targets: Vec<TargetConfig> = {
            let mut config_provider = services.config_provider.lock().await;
            config_provider.list_targets().await?
        };

        targets.retain(|t| !t.ticket_requests_disabled);

        if !policy.ticket_request_show_all_targets {
            let auth_clone = ctx.auth.clone();
            targets = stream::iter(targets)
                .filter(|t| {
                    let auth = auth_clone.clone();
                    let name = t.name.clone();
                    async move {
                        let mut config_provider = services.config_provider.lock().await;
                        let Some(username) = auth.username() else {
                            return false;
                        };
                        matches!(
                            config_provider.authorize_target(username, &name).await,
                            Ok(true)
                        )
                    }
                })
                .collect::<Vec<_>>()
                .await;
        }

        let result: Vec<TicketRequestTarget> = targets
            .into_iter()
            .map(|t| TicketRequestTarget {
                id: t.id,
                name: t.name,
                kind: (&t.options).into(),
            })
            .collect();

        Ok(GetTicketRequestTargetsResponse::Ok(Json(result)))
    }
}

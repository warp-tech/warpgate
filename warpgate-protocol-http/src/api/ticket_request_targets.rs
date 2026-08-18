use std::collections::HashSet;

use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use serde::Serialize;
use warpgate_common::{Target as TargetConfig, WarpgateError};
use warpgate_common_http::SessionAuthorization;
use warpgate_core::ConfigProvider;
use warpgate_db_entities::Target;

use crate::api::auth_scheme::AuthedSession;

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
        operation_id = "get_ticket_request_targets"
    )]
    async fn api_get_ticket_request_targets(
        &self,
        ctx: AuthedSession,
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

        let policy = ctx.parameters().await?;

        if !policy.ticket_self_service_enabled {
            return Ok(GetTicketRequestTargetsResponse::Forbidden(Json(
                "Self-service tickets are not enabled".into(),
            )));
        }

        let mut targets: Vec<TargetConfig> = services.config_provider.list_targets().await?;

        targets.retain(|t| !t.ticket_requests_disabled);

        if !policy.ticket_request_show_all_targets {
            let authorized_ids = match &ctx.auth {
                warpgate_common_http::RequestAuthorization::AdminToken => HashSet::default(),
                auth => {
                    services
                        .config_provider
                        .authorized_target_ids(auth.user_id())
                        .await?
                }
            };
            targets.retain(|t| authorized_ids.contains(&t.id));
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

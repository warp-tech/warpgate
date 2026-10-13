use std::sync::Arc;

use poem::Request;
use poem::session::Session;
use poem::web::{Data, RemoteAddr};
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{Object, OpenApi};
use uuid::Uuid;
use warpgate_common::UserSessionId;
use warpgate_web_ssh::WebSshClientManager;

use crate::api::auth_scheme::AuthedSession;
use crate::api::web_clients::{
    CreateWebClientSessionResponse, DeleteWebClientSessionResponse, GetWebClientSessionResponse,
    create_web_client_session, delete_web_client_session, get_web_client_session,
};

pub struct Api;

#[derive(Object)]
struct CreateWebSshSessionBody {
    target_id: Uuid,
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/web-ssh/sessions",
        method = "post",
        operation_id = "create_web_ssh_session"
    )]
    async fn api_create_web_ssh_session(
        &self,
        remote_addr: &RemoteAddr,
        session: &Session,
        ctx: AuthedSession,
        body: Json<CreateWebSshSessionBody>,
        manager: Data<&Arc<WebSshClientManager>>,
    ) -> poem::Result<CreateWebClientSessionResponse> {
        create_web_client_session(&ctx, session, body.target_id, |authorization| {
            manager.create_session(
                ctx.services(),
                authorization,
                remote_addr.0.as_socket_addr().copied(),
            )
        })
        .await
    }

    #[oai(
        path = "/web-ssh/sessions/:session_id",
        method = "get",
        operation_id = "get_web_ssh_session"
    )]
    async fn api_get_web_ssh_session(
        &self,
        ctx: AuthedSession,
        req: &Request,
        Path(session_id): Path<UserSessionId>,
        manager: Data<&Arc<WebSshClientManager>>,
    ) -> poem::Result<GetWebClientSessionResponse> {
        get_web_client_session(&ctx, req, session_id, &manager).await
    }

    #[oai(
        path = "/web-ssh/sessions/:session_id",
        method = "delete",
        operation_id = "delete_web_ssh_session"
    )]
    async fn api_delete_web_ssh_session(
        &self,
        ctx: AuthedSession,
        req: &Request,
        Path(session_id): Path<UserSessionId>,
        manager: Data<&Arc<WebSshClientManager>>,
    ) -> poem::Result<DeleteWebClientSessionResponse> {
        delete_web_client_session(&ctx, req, session_id, &manager).await
    }
}

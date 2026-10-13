use std::sync::Arc;

use poem::Request;
use poem::session::Session;
use poem::web::{Data, RemoteAddr};
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{Object, OpenApi};
use uuid::Uuid;
use warpgate_common::UserSessionId;
use warpgate_web_desktop::WebDesktopClientManager;

use crate::api::auth_scheme::AuthedSession;
use crate::api::web_clients::{
    CreateWebClientSessionResponse, DeleteWebClientSessionResponse, GetWebClientSessionResponse,
    create_web_client_session, delete_web_client_session, get_web_client_session,
};

pub struct Api;

#[derive(Object)]
struct CreateWebDesktopSessionBody {
    target_id: Uuid,
    /// Initial desktop resolution to request from the target, measured by the browser.
    /// Both must be present to take effect; otherwise a default is used.
    width: Option<u16>,
    height: Option<u16>,
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/web-desktop/sessions",
        method = "post",
        operation_id = "create_web_desktop_session"
    )]
    async fn api_create_web_desktop_session(
        &self,
        remote_addr: &RemoteAddr,
        session: &Session,
        ctx: AuthedSession,
        body: Json<CreateWebDesktopSessionBody>,
        manager: Data<&Arc<WebDesktopClientManager>>,
    ) -> poem::Result<CreateWebClientSessionResponse> {
        create_web_client_session(&ctx, session, body.target_id, |authorization| {
            manager.create_session(
                ctx.services(),
                authorization,
                remote_addr.0.as_socket_addr().copied(),
                body.width.zip(body.height),
            )
        })
        .await
    }

    #[oai(
        path = "/web-desktop/sessions/:session_id",
        method = "get",
        operation_id = "get_web_desktop_session"
    )]
    async fn api_get_web_desktop_session(
        &self,
        ctx: AuthedSession,
        req: &Request,
        Path(session_id): Path<UserSessionId>,
        manager: Data<&Arc<WebDesktopClientManager>>,
    ) -> poem::Result<GetWebClientSessionResponse> {
        get_web_client_session(&ctx, req, session_id, &manager).await
    }

    #[oai(
        path = "/web-desktop/sessions/:session_id",
        method = "delete",
        operation_id = "delete_web_desktop_session"
    )]
    async fn api_delete_web_desktop_session(
        &self,
        ctx: AuthedSession,
        req: &Request,
        Path(session_id): Path<UserSessionId>,
        manager: Data<&Arc<WebDesktopClientManager>>,
    ) -> poem::Result<DeleteWebClientSessionResponse> {
        delete_web_client_session(&ctx, req, session_id, &manager).await
    }
}

use std::collections::HashMap;

use crate::proxy::{proxy_normal_request, proxy_websocket_request};
use crate::AdminServerAddress;
use poem::session::Session;
use poem::web::websocket::WebSocket;
use poem::web::{Data, Html};
use poem::{handler, Body, IntoResponse, Request, Response};
use serde::Deserialize;
use warpgate_admin::{AdminServerSecret, SECRET_HEADER_NAME};
use warpgate_common::{Services, Target, TargetHTTPOptions, TargetOptions};

static TARGET_SESSION_KEY: &str = "target";

#[derive(Deserialize)]
struct QueryParams {
    warpgate_target: Option<String>,
}

#[handler]
pub async fn catchall_endpoint(
    req: &Request,
    ws: Option<WebSocket>,
    session: &Session,
    body: Body,
    services: Data<&Services>,
    admin_server_addr: Data<&AdminServerAddress>,
    admin_server_secret: Data<&AdminServerSecret>,
) -> poem::Result<Response> {
    let params: QueryParams = req.params()?;

    if let Some(target_name) = params.warpgate_target {
        session.set(TARGET_SESSION_KEY, target_name);
    }

    let Some(target_name) = session.get::<String>(TARGET_SESSION_KEY) else {
        return Ok(target_select_view().into_response());
    };

    let target = {
        services
            .config
            .lock()
            .await
            .store
            .targets
            .iter()
            // .filter_map(|t| match t.options {
            //     TargetOptions::Http(ref options) => Some((t, options)),
            //     _ => None,
            // })
            .find(|t| t.name == target_name)
            .map(Clone::clone)
    };

    let admin_options = TargetHTTPOptions {
        url: format!("http://{}", admin_server_addr.0 .0).to_owned(),
        headers: Some(HashMap::from([(
            SECRET_HEADER_NAME.into(),
            (*admin_server_secret).0.expose_secret().into(),
        )])),
    };

    let options = match target {
        Some(Target {
            options: TargetOptions::Http(ref options),
            ..
        }) => options,
        Some(Target {
            options: TargetOptions::WebAdmin(_),
            ..
        }) => &admin_options,
        _ => return Ok(target_select_view().into_response()),
    };

    Ok(match ws {
        Some(ws) => proxy_websocket_request(req, ws, options)
            .await?
            .into_response(),
        None => proxy_normal_request(req, body, options)
            .await?
            .into_response(),
    })
}

pub fn target_select_view() -> impl IntoResponse {
    Html("No target selected")
}

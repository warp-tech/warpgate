use crate::common::{gateway_redirect, SessionExt, SessionUsername};
use crate::proxy::{proxy_normal_request, proxy_websocket_request};
use poem::session::Session;
use poem::web::websocket::WebSocket;
use poem::web::Data;
use poem::{handler, Body, IntoResponse, Request, Response};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::*;
use warpgate_common::{Services, TargetOptions, WarpgateServerHandle};

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
    username: Data<&SessionUsername>,
    services: Data<&Services>,
    server_handle: Option<Data<&Arc<Mutex<WarpgateServerHandle>>>>,
) -> poem::Result<Response> {
    let params: QueryParams = req.params()?;

    if let Some(target_name) = params.warpgate_target {
        session.set_target_name(target_name);
    }

    let Some(target_name) = session.get_target_name() else {
        return Ok(gateway_redirect(req).into_response());
    };

    let target = {
        services
            .config
            .lock()
            .await
            .store
            .targets
            .iter()
            .filter_map(|t| match t.options {
                TargetOptions::Http(ref options) => Some((t, options)),
                _ => None,
            })
            .find(|(t, _)| t.name == target_name)
            .map(|(t, o)| (t.clone(), o.clone()))
    };

    let Some((target, options)) = target else {
        return Ok(gateway_redirect(req).into_response());
    };

    if !services
        .config_provider
        .lock()
        .await
        .authorize_target(&username.0 .0, &target.name)
        .await?
    {
        return Ok(gateway_redirect(req).into_response());
    }

    if let Some(server_handle) = server_handle {
        server_handle.lock().await.set_target(&target).await?;
    }

    let span = info_span!("", target=%target.name);

    Ok(match ws {
        Some(ws) => proxy_websocket_request(req, ws, &options)
            .instrument(span)
            .await?
            .into_response(),
        None => proxy_normal_request(req, body, &options)
            .instrument(span)
            .await?
            .into_response(),
    })
}

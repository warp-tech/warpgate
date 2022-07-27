use std::sync::Arc;

use poem::session::Session;
use poem::web::websocket::WebSocket;
use poem::web::{Data, FromRequest};
use poem::{handler, Body, IntoResponse, Request, Response};
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::*;
use warpgate_common::{Services, Target, TargetHTTPOptions, TargetOptions, WarpgateServerHandle};

use crate::common::{gateway_redirect, SessionExt, SessionUsername};
use crate::proxy::{proxy_normal_request, proxy_websocket_request};

#[derive(Deserialize)]
struct QueryParams {
    #[serde(rename = "warpgate-target")]
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
    let Some((target, options)) = get_target_for_request(req, services.0).await? else {
        return Ok(gateway_redirect(req).into_response());
    };

    session.set_target_name(target.name.clone());

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

async fn get_target_for_request(
    req: &Request,
    services: &Services,
) -> poem::Result<Option<(Target, TargetHTTPOptions)>> {
    let session: &Session = <_>::from_request_without_body(req).await?;
    let params: QueryParams = req.params()?;

    if let Some(target_name) = params.warpgate_target.or(session.get_target_name()) {
        let target = {
            services
                .config
                .lock()
                .await
                .store
                .targets
                .iter()
                .filter(|t| t.name == target_name)
                .filter_map(|t| match t.options {
                    TargetOptions::Http(ref options) => Some((t, options)),
                    _ => None,
                })
                .next()
                .map(|(t, o)| (t.clone(), o.clone()))
        };

        return Ok(target);
    }

    let Some(host) = req.original_uri().host() else {
        return Ok(None);
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
            .filter(|(_, o)| o.external_host.as_deref() == Some(host))
            .next()
            .map(|(t, o)| (t.clone(), o.clone()))
    };

    return Ok(target);
}

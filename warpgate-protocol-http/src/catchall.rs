use std::sync::Arc;

use poem::session::Session;
use poem::web::websocket::WebSocket;
use poem::web::{Data, FromRequest, Redirect};
use poem::{handler, Body, IntoResponse, Request, Response};
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::*;
use warpgate_common::{Services, Target, TargetHTTPOptions, TargetOptions, WarpgateServerHandle};

use crate::common::{SessionAuthorization, SessionExt};
use crate::proxy::{proxy_normal_request, proxy_websocket_request};

#[derive(Deserialize)]
struct QueryParams {
    #[serde(rename = "warpgate-target")]
    warpgate_target: Option<String>,
}

pub fn target_select_redirect() -> Response {
    Redirect::temporary("/@warpgate").into_response()
}

#[handler]
pub async fn catchall_endpoint(
    req: &Request,
    ws: Option<WebSocket>,
    session: &Session,
    body: Body,
    services: Data<&Services>,
    server_handle: Option<Data<&Arc<Mutex<WarpgateServerHandle>>>>,
) -> poem::Result<Response> {
    let Some((target, options)) = get_target_for_request(req, services.0).await? else {
        return Ok(target_select_redirect());
    };

    session.set_target_name(target.name.clone());

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
    let auth: Data<&SessionAuthorization> = <_>::from_request_without_body(req).await?;

    let selected_target_name;
    let need_role_auth;

    let host_based_target_name = if let Some(host) = req.original_uri().host() {
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
            .map(|(t, _)| t.name.clone())
    } else {
        None
    };

    match *auth {
        SessionAuthorization::Ticket { target_name, .. } => {
            selected_target_name = Some(target_name.clone());
            need_role_auth = false;
        }
        SessionAuthorization::User(_) => {
            need_role_auth = true;

            selected_target_name =
                host_based_target_name.or(if let Some(warpgate_target) = params.warpgate_target {
                    Some(warpgate_target)
                } else {
                    session.get_target_name()
                });
        }
    };

    if let Some(target_name) = selected_target_name {
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

        if let Some(target) = target {
            if need_role_auth
                && !services
                    .config_provider
                    .lock()
                    .await
                    .authorize_target(&auth.username(), &target.0.name)
                    .await?
            {
                return Ok(None);
            }

            return Ok(Some(target));
        }
    }

    return Ok(None);
}

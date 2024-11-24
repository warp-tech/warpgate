use std::sync::Arc;

use poem::session::Session;
use poem::web::websocket::WebSocket;
use poem::web::{Data, FromRequest, Redirect};
use poem::{handler, Body, IntoResponse, Request, Response};
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::*;
use warpgate_common::{Target, TargetHTTPOptions, TargetOptions};
use warpgate_core::{Services, WarpgateServerHandle};

use crate::common::{RequestAuthorization, SessionAuthorization, SessionExt};
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
    let target_and_options = get_target_for_request(req, services.0).await?;
    let Some((target, options)) = target_and_options else {
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
    let session = <&Session>::from_request_without_body(req).await?;
    let params: QueryParams = req.params()?;
    let auth = Data::<&RequestAuthorization>::from_request_without_body(req).await?;

    let selected_target_name;
    let need_role_auth;

    let host_based_target_name = if let Some(host) = req.original_uri().host() {
        services
            .config_provider
            .lock()
            .await
            .list_targets()
            .await?
            .iter()
            .filter_map(|t| match t.options {
                TargetOptions::Http(ref options) => Some((t, options)),
                _ => None,
            })
            .find(|(_, o)| o.external_host.as_deref() == Some(host))
            .map(|(t, _)| t.name.clone())
    } else {
        None
    };

    let username = match *auth {
        RequestAuthorization::Session(SessionAuthorization::Ticket {
            target_name,
            username,
        }) => {
            selected_target_name = Some(target_name.clone());
            need_role_auth = false;
            username
        }
        RequestAuthorization::Session(SessionAuthorization::User(username)) => {
            need_role_auth = true;

            selected_target_name =
                host_based_target_name.or(if let Some(warpgate_target) = params.warpgate_target {
                    Some(warpgate_target)
                } else {
                    session.get_target_name()
                });
            username
        }
        RequestAuthorization::AdminToken => return Ok(None),
    };

    if let Some(target_name) = selected_target_name {
        let target = {
            services
                .config_provider
                .lock()
                .await
                .list_targets()
                .await?
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
                    .authorize_target(username, &target.0.name)
                    .await?
            {
                return Ok(None);
            }

            return Ok(Some(target));
        }
    }

    Ok(None)
}

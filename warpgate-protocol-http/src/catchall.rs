use std::sync::Arc;

use poem::session::Session;
use poem::web::websocket::WebSocket;
use poem::web::{Data, FromRequest, Redirect};
use poem::{Body, IntoResponse, Request, Response, handler};
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::{Instrument, debug, info_span};
use warpgate_common::{Target, TargetHTTPOptions, TargetOptions};
use warpgate_common_http::{
    AuthenticatedRequestContext, RequestAuthorization, SessionAuthorization,
};
use warpgate_core::{ConfigProvider, WarpgateServerHandle};

use crate::client_cache::HttpClientCache;
use crate::common::SessionExt;
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
    ctx: Data<&AuthenticatedRequestContext>,
    http_client_cache: Data<&HttpClientCache>,
    server_handle: Option<Data<&Arc<Mutex<WarpgateServerHandle>>>>,
) -> poem::Result<Response> {
    let target_and_options = get_target_for_request(req, &ctx).await?;
    let Some((target, options)) = target_and_options else {
        return Ok(target_select_redirect());
    };

    session.set_target_name(target.name.clone());

    if let Some(server_handle) = server_handle {
        server_handle.lock().await.set_target(&target).await?;
    }

    let span = info_span!("", target=%target.name);

    Ok(match ws {
        Some(ws) => proxy_websocket_request(req, ws, &ctx, &options)
            .instrument(span)
            .await?
            .into_response(),
        None => proxy_normal_request(req, *ctx, body, &target.name, &options, *http_client_cache)
            .instrument(span)
            .await?
            .into_response(),
    })
}

async fn get_target_for_request(
    req: &Request,
    ctx: &AuthenticatedRequestContext,
) -> poem::Result<Option<(Target, TargetHTTPOptions)>> {
    let session = <&Session>::from_request_without_body(req).await?;
    let params: QueryParams = req.params()?;

    let selected_target_name;
    let authorized_user_id;

    let request_host = ctx.trusted_hostname(req);

    let host_based_target = if let Some(host) = request_host {
        let found = ctx
            .services()
            .config_provider
            .get_target_by_hostname(host.as_str())
            .await?;
        if found.is_some() {
            debug!(
                "Domain rebinding detected: host={} -> target={:?}",
                host,
                found.as_ref().map(|target| &target.name)
            );
        }
        found
    } else {
        None
    };

    match &ctx.auth {
        RequestAuthorization::Session(SessionAuthorization::Ticket { target_name, .. }) => {
            selected_target_name = Some(target_name.clone());
            authorized_user_id = None;
        }
        RequestAuthorization::Session(SessionAuthorization::User { user_id, .. }) => {
            authorized_user_id = Some(*user_id);

            selected_target_name = if let Some(warpgate_target) = params.warpgate_target {
                Some(warpgate_target)
            } else if let Some(ref rebound_target) = host_based_target {
                Some(rebound_target.name.clone())
            } else {
                session.get_target_name()
            };
        }
        RequestAuthorization::UserToken { .. } | RequestAuthorization::AdminToken => {
            return Ok(None);
        }
    };

    let domain_rebinding_configured = host_based_target.is_some();
    let final_target_name = selected_target_name
        .or_else(|| host_based_target.as_ref().map(|target| target.name.clone()));

    if let Some(target_name) = final_target_name {
        let target =
            if let Some(target) = host_based_target.filter(|target| target.name == target_name) {
                Some(target)
            } else {
                ctx.services()
                    .config_provider
                    .get_target_by_name(target_name.as_str())
                    .await?
            };

        if let Some(target) = target
            && let TargetOptions::Http(ref options) = target.options
        {
            if let Some(user_id) = authorized_user_id
                && !ctx
                    .services()
                    .config_provider
                    .authorize_target_by_id(user_id, target.id)
                    .await?
            {
                return Ok(None);
            }

            return Ok(Some((target.clone(), options.clone())));
        }
    }

    if domain_rebinding_configured {
        debug!(
            "Domain rebinding was configured for this host but target was not selected. This may indicate the target doesn't exist or user is not authorized."
        );
    }

    Ok(None)
}

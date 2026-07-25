use std::sync::Arc;

use poem::session::Session;
use poem::web::websocket::WebSocket;
use poem::web::{Data, FromRequest, Redirect};
use poem::{Body, IntoResponse, Request, Response, handler};
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::{Instrument, debug, info_span};
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{Target, TargetHTTPOptions, TargetOptions};
use warpgate_common_http::{
    AuthenticatedRequestContext, RequestAuthorization, SessionAuthorization,
};
use warpgate_core::{ConfigProvider, WarpgateServerHandle, authorize_for_target};

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

/// Pairs a target with its HTTP options, discarding targets of other protocols.
fn as_http_target(target: Target) -> Option<(Target, TargetHTTPOptions)> {
    let TargetOptions::Http(ref options) = target.options else {
        return None;
    };
    let options = options.clone();
    Some((target, options))
}

async fn get_target_for_request(
    req: &Request,
    ctx: &AuthenticatedRequestContext,
) -> poem::Result<Option<(Target, TargetHTTPOptions)>> {
    let config_provider = ctx.services().config_provider.as_ref();

    // A ticket is bound to one target row, and it was authorized against that row
    // when the session was established. Resolving by id keeps the request from
    // steering it elsewhere — via query param, host rebinding or session state —
    // and survives the target being renamed.
    if let RequestAuthorization::Session(SessionAuthorization::Ticket { target_id, .. }) = &ctx.auth
    {
        return Ok(config_provider
            .get_target_by_id(*target_id)
            .await?
            .and_then(as_http_target));
    }

    let RequestAuthorization::Session(SessionAuthorization::User { user_id, username }) = &ctx.auth
    else {
        return Ok(None);
    };

    let session = <&Session>::from_request_without_body(req).await?;
    let params: QueryParams = req.params()?;

    let request_host = ctx.trusted_hostname(req);

    let host_based_target = if let Some(host) = request_host {
        let found = config_provider.get_target_by_hostname(host.as_str()).await?;
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

    let selected_target_name = if let Some(warpgate_target) = params.warpgate_target {
        Some(warpgate_target)
    } else if let Some(ref rebound_target) = host_based_target {
        Some(rebound_target.name.clone())
    } else {
        session.get_target_name()
    };

    let domain_rebinding_configured = host_based_target.is_some();
    let final_target_name = selected_target_name
        .or_else(|| host_based_target.as_ref().map(|target| target.name.clone()));

    if let Some(target_name) = final_target_name {
        let target =
            if let Some(target) = host_based_target.filter(|target| target.name == target_name) {
                Some(target)
            } else {
                config_provider.get_target_by_name(target_name.as_str()).await?
            };

        let user_info = AuthStateUserInfo {
            id: *user_id,
            username: username.clone(),
        };

        if let Some(target) = target
            && let Some(authorization) =
                authorize_for_target(config_provider, &user_info, target).await?
            && let Some(target_and_options) = as_http_target(authorization.into_parts().1)
        {
            return Ok(Some(target_and_options));
        }
    }

    if domain_rebinding_configured {
        debug!(
            "Domain rebinding was configured for this host but target was not selected. This may indicate the target doesn't exist or user is not authorized."
        );
    }

    Ok(None)
}

use std::sync::Arc;

use poem::session::Session;
use poem::web::websocket::WebSocket;
use poem::web::{Data, FromRequest, Redirect};
use poem::{Body, IntoResponse, Request, Response, handler};
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::{Instrument, debug, info_span};
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common_http::{
    AuthenticatedRequestContext, RequestAuthorization, SessionAuthorization,
};
use warpgate_core::{
    AuthorizedIdentity, ConfigProvider, TargetAuthorization, WarpgateServerHandle,
    authorize_for_target,
};

use crate::approval_gate::{UngatedTarget, check_admin_approval};
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
    let Some(ungated) = get_target_for_request(req, &ctx).await? else {
        return Ok(target_select_redirect());
    };

    session.set_target_name(ungated.target().name.clone());

    if let Some(server_handle) = server_handle {
        server_handle
            .lock()
            .await
            .set_target(ungated.target())
            .await?;
    }

    // Gated before the protocol branch so the WebSocket upgrade is held too —
    // an upgrade has nowhere to render an interstitial, and letting it through
    // would leave the gate applying only to plain requests. The target the
    // proxy dials only exists on the far side of the gate.
    let (target, options) = match check_admin_approval(req, &ctx, ungated).await? {
        Ok(approved) => approved,
        Err(response) => return Ok(response),
    };

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
) -> poem::Result<Option<UngatedTarget>> {
    let config_provider = ctx.services().config_provider.as_ref();

    // A ticket is bound to one target row, and it was authorized against that row
    // when the session was established. Resolving by id keeps the request from
    // steering it elsewhere — via query param, host rebinding or session state —
    // and survives the target being renamed.
    if let RequestAuthorization::Session(SessionAuthorization::Ticket {
        user_id,
        username,
        target_id,
        ..
    }) = &ctx.auth
    {
        let Some(target) = config_provider.get_target_by_id(*target_id).await? else {
            return Ok(None);
        };
        let authorization = TargetAuthorization::for_ticket_session(
            AuthStateUserInfo {
                id: *user_id,
                username: username.clone(),
            },
            target,
            *target_id,
            crate::common::PROTOCOL_NAME,
        )?;
        return Ok(UngatedTarget::new_http(authorization));
    }

    let RequestAuthorization::Session(SessionAuthorization::User { user_id, username }) = &ctx.auth
    else {
        return Ok(None);
    };

    let session = <&Session>::from_request_without_body(req).await?;
    let params: QueryParams = req.params()?;

    let request_host = ctx.trusted_hostname(req);

    let host_based_target = if let Some(host) = request_host {
        let found = config_provider
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
                config_provider
                    .get_target_by_name(target_name.as_str())
                    .await?
            };

        // Reached only for a `SessionAuthorization::User` (ticket sessions are
        // handled separately above), so the session is the prior-auth evidence.
        let identity = AuthorizedIdentity::for_authenticated_session(
            AuthStateUserInfo {
                id: *user_id,
                username: username.clone(),
            },
            crate::common::PROTOCOL_NAME,
        );

        if let Some(target) = target
            && let Some(authorization) =
                authorize_for_target(config_provider, &identity, target).await?
            && let Some(ungated) = UngatedTarget::new_http(authorization)
        {
            return Ok(Some(ungated));
        }
    }

    if domain_rebinding_configured {
        debug!(
            "Domain rebinding was configured for this host but target was not selected. This may indicate the target doesn't exist or user is not authorized."
        );
    }

    Ok(None)
}

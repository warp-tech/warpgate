use std::sync::Arc;

use poem::session::Session;
use poem::web::websocket::WebSocket;
use poem::web::{Data, FromRequest, Redirect};
use poem::{Body, IntoResponse, Request, Response, handler};
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::{Instrument, debug, info_span};
use warpgate_common::TargetHTTPOptions;
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::{
    AuthenticatedRequestContext, RequestAuthorization, SessionAuthorization, SessionKeepalive,
};
use warpgate_core::{
    AuthorizedIdentity, ConfigProvider, TargetAuthorization, TargetSessionStart,
    authorize_for_target,
};

use crate::client_cache::HttpClientCache;
use crate::common::SessionExt;
use crate::proxy::{proxy_normal_request, proxy_websocket_request};
use crate::session::SessionStore;

#[derive(Deserialize)]
struct QueryParams {
    #[serde(rename = "warpgate-target")]
    warpgate_target: Option<String>,
}

pub fn target_select_redirect() -> Response {
    Redirect::temporary("/@warpgate").into_response()
}

#[handler]
#[allow(clippy::too_many_arguments)]
pub async fn catchall_endpoint(
    req: &Request,
    ws: Option<WebSocket>,
    session: &Session,
    body: Body,
    ctx: Data<&AuthenticatedRequestContext>,
    unauthenticated_ctx: Data<&UnauthenticatedRequestContext>,
    http_client_cache: Data<&HttpClientCache>,
    session_store: Data<&Arc<Mutex<SessionStore>>>,
) -> poem::Result<Response> {
    let Some(authorization) = get_target_for_request(req, &ctx).await? else {
        return Ok(target_select_redirect());
    };

    session.set_target_name(authorization.target().name.clone());

    let RequestAuthorization::Session(_) = &ctx.auth else {
        return Err(poem::Error::from_status(
            poem::http::StatusCode::UNAUTHORIZED,
        ));
    };
    let user_info = authorization.user_info().clone();
    let handle = {
        let mut store = session_store.lock().await;
        match store.handle_for(session) {
            Some(handle) => handle,
            None => match session.get_session_id() {
                // The parent is DB-backed: a node that didn't create it serves
                // it through a local view handle.
                Some(id) => {
                    store
                        .adopt_handle_for(req, &unauthenticated_ctx, id)
                        .await?
                }
                None => store.create_handle_for(req, &unauthenticated_ctx).await?,
            },
        }
    };
    handle.lock().await.set_user_info(user_info.clone()).await?;

    let (target_session_id, approved, target_close_rx) = match handle
        .lock()
        .await
        .start_target_session(authorization)
        .await?
    {
        TargetSessionStart::Started(started) => *started,
        TargetSessionStart::NeedsApproval => {
            return Ok(Response::builder()
                .status(poem::http::StatusCode::SERVICE_UNAVAILABLE)
                .body("Target approval required"));
        }
    };
    let keepalive_guard = Data::<&SessionKeepalive>::from_request_without_body(req)
        .await
        .ok()
        .map(|keepalive| keepalive.guard());

    let span = info_span!("", session=%target_session_id, target=%approved.target().name);

    Ok(match ws {
        Some(ws) => {
            proxy_websocket_request(req, ws, &ctx, approved, target_close_rx)
                .instrument(span)
                .await?
                .into_response()
        }
        None => proxy_normal_request(
            req,
            *ctx,
            body,
            *http_client_cache,
            approved,
            target_close_rx,
            keepalive_guard,
        )
        .instrument(span)
        .await?
        .into_response(),
    })
}

/// Narrows to an HTTP target; any other kind is "no target for this request".
fn is_http_authorization(
    authorization: TargetAuthorization,
) -> Option<TargetAuthorization<TargetHTTPOptions>> {
    authorization.narrow().ok()
}

async fn get_target_for_request(
    req: &Request,
    ctx: &AuthenticatedRequestContext,
) -> poem::Result<Option<TargetAuthorization<TargetHTTPOptions>>> {
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
        return Ok(is_http_authorization(
            TargetAuthorization::for_ticket_session(
                AuthStateUserInfo {
                    id: *user_id,
                    username: username.clone(),
                },
                target,
                *target_id,
                crate::common::PROTOCOL_NAME,
            )?,
        ));
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
            && let Some(authorization) = is_http_authorization(authorization)
        {
            return Ok(Some(authorization));
        }
    }

    if domain_rebinding_configured {
        debug!(
            "Domain rebinding was configured for this host but target was not selected. This may indicate the target doesn't exist or user is not authorized."
        );
    }

    Ok(None)
}

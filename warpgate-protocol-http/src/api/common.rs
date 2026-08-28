use poem::session::Session;
use poem::web::websocket::WebSocket;
use poem::{Endpoint, EndpointExt, FromRequest, IntoResponse, Response};
use sea_orm::{DatabaseConnection, EntityTrait, QueryFilter};
use tracing::info;
use uuid::Uuid;
use warpgate_admin::api::cluster_proxy::{Owner, forward_websocket, node_owner};
use warpgate_common::{Protocol, TargetOptions, UserSessionId, WarpgateError};
use warpgate_common_http::auth::{
    AuthenticatedRequestContext, FullUserAuthorization, web_reauth_required,
};
use warpgate_core::{ConfigProvider, TargetAuthorization, authorize_for_target};
use warpgate_db_entities as entities;

use crate::session::SessionStore;

pub fn emit_unknown_authentication_failed_event(
    session_id: UserSessionId,
    remote_ip: Option<std::net::IpAddr>,
    username: &str,
    credentials: &str,
    reason: &str,
) {
    let client_ip = remote_ip.map_or_else(|| "<unknown>".to_string(), |x| x.to_string());

    info!(
        target: "audit",
        _type = "UserAuthenticationFailed1",
        session = %session_id,
        client_ip = %client_ip,
        username = %username,
        credentials = %credentials,
        reason = %reason,
        "Authentication failed",
    );
}

pub fn logout(session: &Session, session_middleware: &mut SessionStore) {
    session_middleware.remove_session(session);
    session.clear();
    info!("Logged out");
}

/// Outcome of the checks that guard the in-browser clients. Each endpoint maps
/// it onto its own `ApiResponse` enum.
pub enum WebClientTargetAccess {
    Authorized(TargetAuthorization),
    ReauthRequired,
    Forbidden,
    NotFound,
}

/// Gate for the in-browser SSH and desktop clients: a recent enough web login,
/// the global switch, and the user's authorization for the requested target.
pub async fn authorize_web_client_target(
    ctx: &AuthenticatedRequestContext,
    session: &Session,
    target_id: Uuid,
) -> poem::Result<WebClientTargetAccess> {
    // A ticket is authorized for exactly one target; it must not be able to open
    // an in-browser client to any target the *user* can reach. Requiring a
    // full-user proof keeps this endpoint off the ticket path entirely.
    let Some(full) = ctx.auth.as_full_user() else {
        return Ok(WebClientTargetAccess::Forbidden);
    };

    if web_reauth_required(ctx, session).await? {
        return Ok(WebClientTargetAccess::ReauthRequired);
    }

    if !ctx.parameters().await?.web_clients_enabled {
        return Ok(WebClientTargetAccess::Forbidden);
    }

    let config_provider = ctx.services().config_provider.as_ref();
    let Some(target) = config_provider.get_target_by_id(target_id).await? else {
        return Ok(WebClientTargetAccess::NotFound);
    };

    let Some(protocol) = web_client_protocol(&target.options) else {
        return Ok(WebClientTargetAccess::NotFound);
    };

    let identity = full.identity(protocol);

    Ok(authorize_for_target(config_provider, &identity, target)
        .await?
        .map_or(
            WebClientTargetAccess::Forbidden,
            WebClientTargetAccess::Authorized,
        ))
}

/// only the protocols that can be proxied through a web client (SSH, RDP, VNC)
const fn web_client_protocol(options: &TargetOptions) -> Option<Protocol> {
    match options {
        TargetOptions::Ssh(_) => Some(Protocol::Ssh),
        TargetOptions::Vnc(_) => Some(Protocol::Vnc),
        TargetOptions::Rdp(_) => Some(Protocol::Rdp),
        _ => None,
    }
}

/// Resolves the model for the authenticated account. Takes a
/// [`FullUserAuthorization`] rather than a raw `RequestAuthorization` so a
/// target-scoped ticket cannot be resolved to a full account here — the callers
/// that manage credentials and tokens all route through this.
pub async fn get_user(
    auth: &FullUserAuthorization,
    db: &DatabaseConnection,
) -> Result<Option<entities::User::Model>, WarpgateError> {
    let Some(user_model) = entities::User::Entity::find()
        .filter(entities::User::Entity::username_eq_ci(auth.username()))
        .one(db)
        .await?
    else {
        return Ok(None);
    };

    Ok(Some(user_model))
}

/// The node holding a web-client session's live state. Web-client sessions
/// are direct-protocol user sessions, so the session id is the user-session
/// id and its row records the owning node. A missing or ended row resolves
/// `Local`, where the manager lookup then reports not-found.
pub async fn web_client_session_owner(
    ctx: &AuthenticatedRequestContext,
    session_id: UserSessionId,
) -> poem::Result<Owner> {
    let Some(row) = entities::UserSession::Entity::find_by_id(session_id)
        .one(&ctx.services().db)
        .await
        .map_err(WarpgateError::from)?
        .filter(|row| row.ended.is_none())
    else {
        return Ok(Owner::Local);
    };
    node_owner(ctx, row.node_id).await.map_err(Into::into)
}

/// Wraps a web-client websocket endpoint (`:session_id` in its path) with
/// session-owner forwarding: a stream request landing on a node that does not
/// hold the session's live state is forwarded to the node that does.
pub fn forward_ws_to_session_owner<E: Endpoint + 'static>(
    ep: E,
) -> impl Endpoint<Output = Response> {
    ep.around(|ep, req| async move {
        let Some(ctx) = req.data::<AuthenticatedRequestContext>().cloned() else {
            return ep.call(req).await.map(IntoResponse::into_response);
        };
        let session_id = req
            .raw_path_param("session_id")
            .and_then(|raw| raw.parse::<Uuid>().ok())
            .map(UserSessionId);
        let Some(session_id) = session_id else {
            return ep.call(req).await.map(IntoResponse::into_response);
        };
        match web_client_session_owner(&ctx, session_id).await? {
            Owner::Local => ep.call(req).await.map(IntoResponse::into_response),
            Owner::Remote(remote) => {
                let ws = WebSocket::from_request_without_body(&req).await?;
                forward_websocket(&ctx, &req, ws, remote, &ctx.services().cluster_token).await
            }
        }
    })
}

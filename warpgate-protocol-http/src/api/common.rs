use poem::session::Session;
use sea_orm::{DatabaseConnection, EntityTrait, QueryFilter};
use tracing::info;
use uuid::Uuid;
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{Protocol, TargetOptions, UserSessionId, WarpgateError};
use warpgate_common_http::auth::{
    AuthenticatedRequestContext, FullUserAuthorization, web_reauth_required,
};
use warpgate_core::{
    AuthorizedIdentity, ConfigProvider, TargetAuthorization, authorize_for_target,
};
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

    // The in-browser client's session runs under the target's own protocol,
    // not the browser's HTTP, and the authorization must carry that protocol
    // to match it. A kind with no in-browser client reads as absent.
    let Some(protocol) = web_client_protocol(&target.options) else {
        return Ok(WebClientTargetAccess::NotFound);
    };

    // The session already authenticated as a full user (checked above), so this
    // is a legitimate out-of-band identity for the authorization check.
    let identity = AuthorizedIdentity::for_authenticated_session(
        AuthStateUserInfo {
            id: full.user_id(),
            username: full.username().to_owned(),
        },
        protocol,
    );

    Ok(authorize_for_target(config_provider, &identity, target)
        .await?
        .map_or(
            WebClientTargetAccess::Forbidden,
            WebClientTargetAccess::Authorized,
        ))
}

/// The protocol an in-browser client for this target kind runs under, or
/// `None` for kinds that have no in-browser client.
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

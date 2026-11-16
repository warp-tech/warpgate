//! The bearer-token gate every SCIM route sits behind.

use std::net::IpAddr;
use std::sync::Arc;

use poem::{Endpoint, Request};
use sea_orm::{ActiveModelTrait, Set};
use time::OffsetDateTime;
use tracing::{Instrument, warn};
use uuid::Uuid;
use warpgate_common_http::authorization_token;
use warpgate_common_http::logging::get_client_ip;
use warpgate_db_entities::ScimToken;

use super::context;
use crate::protocol::ScimError;

/// The token a request authenticated with, attached as request data.
#[derive(Clone, Debug)]
pub struct ScimPrincipal {
    pub token_id: Uuid,
    pub label: String,
    pub sso_provider: Option<String>,
}

/// `last_used` is written at most this often per token.
const LAST_USED_GRANULARITY: time::Duration = time::Duration::seconds(60);

/// Rejects anything but a valid, unexpired SCIM token presented as a bearer
/// token. Cookies and `X-Warpgate-Token` are deliberately not accepted here.
/// A blocked IP is refused before the lookup, so it learns nothing about
/// which tokens exist.
pub async fn bearer_gate<E: Endpoint>(ep: Arc<E>, mut req: Request) -> poem::Result<E::Output> {
    let ctx = context(&req).await?.0.clone();
    let services = ctx.services();

    if let Some(ip) = get_client_ip(&req, services)
        .await
        .and_then(|ip| ip.parse::<IpAddr>().ok())
        && services
            .login_protection
            .check_ip_blocked(&ip)
            .await
            .map_err(ScimError::Internal)?
            .is_some()
    {
        warn!(%ip, "SCIM request from a blocked IP");
        return Err(ScimError::unauthorized().into());
    }

    let Some(secret) = authorization_token(&req, "Bearer").map(str::to_owned) else {
        return Err(ScimError::unauthorized().into());
    };
    let Some(token) = ScimToken::Entity::find_by_secret(&services.db, &secret)
        .await
        .map_err(|e| ScimError::Internal(e.into()))?
    else {
        warn!("SCIM request with an invalid or expired token");
        return Err(ScimError::unauthorized().into());
    };

    let now = OffsetDateTime::now_utc();
    if token
        .last_used
        .is_none_or(|last| now - last >= LAST_USED_GRANULARITY)
    {
        ScimToken::ActiveModel {
            id: Set(token.id),
            last_used: Set(Some(now)),
            ..Default::default()
        }
        .update(&services.db)
        .await
        .map_err(|e| ScimError::Internal(e.into()))?;
    }

    let span = tracing::info_span!("scim", scim_token = %token.label);
    req.set_data(ScimPrincipal {
        token_id: token.id,
        label: token.label,
        sso_provider: token.sso_provider,
    });
    ep.call(req).instrument(span).await
}

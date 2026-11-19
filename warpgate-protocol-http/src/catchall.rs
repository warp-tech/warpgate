use std::sync::Arc;

use poem::session::Session;
use poem::web::websocket::WebSocket;
use poem::web::{Data, FromRequest, Redirect};
use poem::{Body, IntoResponse, Request, Response, handler};
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::{Instrument, debug, info_span, warn};
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{Target, TargetHTTPOptions, WarpgateError};
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::{
    AuthenticatedRequestContext, RequestAuthorization, SessionAuthorization, SessionKeepalive,
};
use warpgate_core::{
    ConfigProvider, TargetAuthorization, TargetSessionStart, authorize_for_target,
};

use crate::approval_gate::resolve_admin_approval;
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

    // A host-bound target is selected by its host. A remembered name would
    // only be refused on other hosts.
    if bound_host(authorization.target()).is_none() {
        session.set_target_name(authorization.target().name.clone());
    }

    let RequestAuthorization::Session(_) = &ctx.auth else {
        return Err(poem::Error::from_status(
            poem::http::StatusCode::UNAUTHORIZED,
        ));
    };

    let (handle, close_rx) = {
        let mut store = session_store.lock().await;
        let handle = store.handle_for_request(req, &unauthenticated_ctx).await?;
        let id = handle.lock().await.user_session_id();
        let close_rx = store.close_receiver_by_id(id).ok_or_else(|| {
            poem::Error::from_status(poem::http::StatusCode::INTERNAL_SERVER_ERROR)
        })?;
        (handle, close_rx)
    };

    // start_target_session already sets/checks session user info
    let started = handle
        .lock()
        .await
        .start_target_session(authorization)
        .await;
    let admitted = match started {
        Err(WarpgateError::UserSessionEnded) => {
            // got revoked in the meantime
            session.purge();
            return Err(poem::Error::from_status(
                poem::http::StatusCode::UNAUTHORIZED,
            ));
        }
        Ok(TargetSessionStart::Started(started)) => started,
        Err(error) => return Err(error.into()),
        Ok(TargetSessionStart::NeedsApproval(authorization)) => {
            // Fail early, before we get to websocket
            match resolve_admin_approval(req, &ctx, &handle, authorization).await? {
                Ok(started) => started,
                Err(response) => return Ok(response),
            }
        }
    };
    let keepalive_guard = Data::<&SessionKeepalive>::from_request_without_body(req)
        .await
        .ok()
        .map(|keepalive| keepalive.guard());

    // `session` field is UserSession, not this
    let span = info_span!("", target_session=%admitted.id(), target=%admitted.target().name);

    Ok(match ws {
        Some(ws) => proxy_websocket_request(req, ws, &ctx, admitted, close_rx)
            .instrument(span)
            .await?
            .into_response(),
        None => proxy_normal_request(
            req,
            *ctx,
            body,
            *http_client_cache,
            admitted,
            close_rx,
            keepalive_guard,
        )
        .instrument(span)
        .await?
        .into_response(),
    })
}

fn bound_host(target: &Target) -> Option<&str> {
    target
        .options
        .external_host()
        .filter(|host| !host.is_empty())
}

/// Whether `target` may be served on the request host.
///
/// A host-bound target relies on the same-origin policy for isolation. Its
/// content must not be served on another host, and its host must not serve
/// another target. `host_owner` is the target bound to the request host.
fn target_belongs_on_host(
    target: &Target,
    request_host: Option<&str>,
    host_owner: Option<&Target>,
) -> bool {
    match bound_host(target) {
        Some(bound) => request_host.is_some_and(|host| host.eq_ignore_ascii_case(bound)),
        None => host_owner.is_none(),
    }
}

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
        ticket_id,
        ..
    }) = &ctx.auth
    {
        let Some(target) = config_provider.get_target_by_id(*target_id).await? else {
            return Ok(None);
        };

        if target.id != *target_id {
            return Err(WarpgateError::InconsistentState(
                "ticket session target does not match the ticket's target".into(),
            )
            .into());
        }

        let request_host = ctx.trusted_hostname(req);
        let host_owner = match (&request_host, bound_host(&target)) {
            (Some(host), None) => config_provider.get_target_by_hostname(host).await?,
            _ => None,
        };
        if !target_belongs_on_host(&target, request_host.as_deref(), host_owner.as_ref()) {
            debug!(target=%target.name, host=?request_host, "Ticket target refused on this host");
            return Ok(None);
        }

        return Ok(is_http_authorization(
            TargetAuthorization::for_ticket_session(
                AuthStateUserInfo {
                    id: *user_id,
                    username: username.clone(),
                },
                target,
                *ticket_id,
                crate::common::PROTOCOL_NAME,
            )?,
        ));
    }

    let RequestAuthorization::Session(SessionAuthorization::User { .. }) = &ctx.auth else {
        return Ok(None);
    };

    let session = <&Session>::from_request_without_body(req).await?;
    let params: QueryParams = req.params()?;

    let request_host = ctx.trusted_hostname(req);

    let host_based_target = if let Some(host) = &request_host {
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
    let host_owner = host_based_target.clone();
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
        let Some(full) = ctx.auth.as_full_user() else {
            return Ok(None);
        };
        let identity = full.identity(crate::common::PROTOCOL_NAME);

        let target = target.filter(|target| {
            let belongs =
                target_belongs_on_host(target, request_host.as_deref(), host_owner.as_ref());
            if !belongs {
                warn!(target=%target.name, host=?request_host, "Target refused on this host");
            }
            belongs
        });

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

#[cfg(test)]
mod tests {
    use warpgate_common::{TargetOptions, Tls};

    use super::*;

    fn target(external_host: Option<&str>) -> Target {
        Target {
            id: uuid::Uuid::new_v4(),
            name: "t".into(),
            description: String::new(),
            allow_roles: vec![],
            options: TargetOptions::Http(TargetHTTPOptions {
                url: "http://127.0.0.1".into(),
                tls: Tls::default(),
                headers: Default::default(),
                external_host: external_host.map(Into::into),
            }),
            rate_limit_bytes_per_second: None,
            group_id: None,
            ticket_max_duration_seconds: None,
            ticket_requests_disabled: false,
            ticket_require_approval: false,
            require_approval: false,
            ticket_max_uses: None,
        }
    }

    #[test]
    fn bound_target_is_served_only_on_its_host() {
        let bound = target(Some("app.example.com"));
        assert!(target_belongs_on_host(
            &bound,
            Some("APP.example.com"),
            Some(&bound)
        ));
        // the control plane, another target's host, no host at all
        assert!(!target_belongs_on_host(&bound, Some("example.com"), None));
        assert!(!target_belongs_on_host(
            &bound,
            Some("other.example.com"),
            Some(&target(Some("other.example.com")))
        ));
        assert!(!target_belongs_on_host(&bound, None, None));
    }

    #[test]
    fn unbound_target_is_not_served_on_a_bound_host() {
        let unbound = target(None);
        assert!(target_belongs_on_host(&unbound, Some("example.com"), None));
        assert!(target_belongs_on_host(&unbound, None, None));
        assert!(!target_belongs_on_host(
            &unbound,
            Some("app.example.com"),
            Some(&target(Some("app.example.com")))
        ));
        // an empty `external_host` counts as unbound
        assert!(target_belongs_on_host(
            &target(Some("")),
            Some("example.com"),
            None
        ));
    }
}

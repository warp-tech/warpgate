use std::net::IpAddr;

use poem::session::Session;
use poem::web::{Data, FromRequest};
use poem::{Endpoint, Middleware, Request};
use serde::Deserialize;
use uuid::Uuid;
use warpgate_common::Secret;
use warpgate_common_http::SessionAuthorization;
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::logging::get_client_ip;
use warpgate_core::authorize_and_spend_ticket;

use crate::common::SessionExt;

/// Request-data marker for a header-borne ticket: the request runs on a
/// detached session that is never stored, so the user session registered for
/// it is kept alive by the node's `SessionStore` entry rather than by a
/// stored cookie.
#[derive(Clone, Copy)]
pub(crate) struct TemporaryTicketSession;

/// What consecutive header-ticket requests are recognised by. The database id
/// distinguishes separate tickets issued to the same user for the same target
/// without keeping the secret around to key on.
pub(crate) type TicketSessionKey = (Uuid, Uuid, Option<Uuid>);

/// The ticket identity of a request that carries a header-borne ticket, or
/// `None` for anything cookie-backed.
pub(crate) fn ticket_session_key(req: &Request, session: &Session) -> Option<TicketSessionKey> {
    req.data::<TemporaryTicketSession>()?;
    match session.get_auth()? {
        SessionAuthorization::Ticket {
            user_id,
            target_id,
            ticket_id,
            ..
        } => Some((user_id, target_id, ticket_id)),
        SessionAuthorization::User { .. } => None,
    }
}

pub struct TicketMiddleware {}

impl TicketMiddleware {
    pub const fn new() -> Self {
        Self {}
    }
}

pub struct TicketMiddlewareEndpoint<E: Endpoint> {
    inner: E,
}

impl<E: Endpoint> Middleware<E> for TicketMiddleware {
    type Output = TicketMiddlewareEndpoint<E>;

    fn transform(&self, inner: E) -> Self::Output {
        TicketMiddlewareEndpoint { inner }
    }
}

#[derive(Deserialize)]
struct QueryParams {
    #[serde(rename = "warpgate-ticket")]
    ticket: Option<String>,
}

impl<E: Endpoint> Endpoint for TicketMiddlewareEndpoint<E> {
    type Output = E::Output;

    async fn call(&self, mut req: Request) -> poem::Result<Self::Output> {
        let mut session_is_temporary = false;
        let ctx = Data::<&UnauthenticatedRequestContext>::from_request_without_body(&req)
            .await?
            .clone();

        let params: QueryParams = req.params()?;
        let mut ticket_value = params.ticket;

        for h in req.headers().get_all(http::header::AUTHORIZATION) {
            let header_value = h.to_str().unwrap_or("").to_string();
            if let Some((token_type, token_value)) = header_value.split_once(' ')
                && &token_type.to_lowercase() == "warpgate"
            {
                ticket_value = Some(token_value.to_string());
                session_is_temporary = true;
            }
        }

        if session_is_temporary {
            // ticket/token requests get a fake temp session
            // which is never persisted into the store
            req.extensions_mut().insert(Session::default());
            req.set_data(TemporaryTicketSession);
        }
        let session = <&Session>::from_request_without_body(&req).await?.clone();

        if let Some(ticket) = ticket_value {
            let ticket_secret = Secret::new(ticket);
            let client_ip: Option<IpAddr> = get_client_ip(&req, ctx.services())
                .await
                .and_then(|s| s.parse().ok());
            if let Some(authorization) = authorize_and_spend_ticket(
                &ctx.services().db,
                &ctx.services().login_protection,
                &ticket_secret,
                client_ip,
                crate::common::PROTOCOL_NAME,
            )
            .await?
            {
                session.set_auth(SessionAuthorization::Ticket {
                    user_id: authorization.user_info().id,
                    username: authorization.user_info().username.clone(),
                    target_id: authorization.target().id,
                    ticket_id: authorization.ticket_id(),
                });
            }
        }

        self.inner.call(req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temporary_ticket_sessions_are_keyed_by_ticket_id() {
        let user_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();
        let first_ticket_id = Uuid::new_v4();
        let second_ticket_id = Uuid::new_v4();
        let mut req = Request::builder().finish();
        req.set_data(TemporaryTicketSession);
        let session = Session::default();
        session.set_auth(SessionAuthorization::Ticket {
            user_id,
            username: "alice".into(),
            target_id,
            ticket_id: Some(first_ticket_id),
        });
        let first_key = ticket_session_key(&req, &session);

        session.set_auth(SessionAuthorization::Ticket {
            user_id,
            username: "alice".into(),
            target_id,
            ticket_id: Some(second_ticket_id),
        });

        assert_ne!(first_key, ticket_session_key(&req, &session));
    }
}

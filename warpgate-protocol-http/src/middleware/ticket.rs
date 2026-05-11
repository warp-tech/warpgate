use poem::session::Session;
use poem::web::{Data, FromRequest};
use poem::{Endpoint, Middleware, Request};
use serde::Deserialize;
use warpgate_common::Secret;
use warpgate_common_http::SessionAuthorization;
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_core::{authorize_ticket, consume_ticket};

use crate::common::SessionExt;

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

    async fn call(&self, req: Request) -> poem::Result<Self::Output> {
        let mut session_is_temporary = false;
        let session = <&Session>::from_request_without_body(&req).await?;
        let session = session.clone();

        let ctx = Data::<&UnauthenticatedRequestContext>::from_request_without_body(&req).await?;

        {
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

            if let Some(ticket) = ticket_value
                && let Some((_ticket_model, target, user_info)) = {
                    let ticket_secret = Secret::new(ticket);
                    if let Some((ticket, target, user_info)) =
                        authorize_ticket(&ctx.services().db, &ticket_secret).await?
                    {
                        consume_ticket(&ctx.services().db, &ticket.id).await?;
                        Some((ticket, target, user_info))
                    } else {
                        None
                    }
                }
            {
                session.set_auth(SessionAuthorization::Ticket {
                    user_id: user_info.id,
                    username: user_info.username,
                    target_name: target.name,
                });
            }
        }

        let resp = self.inner.call(req).await;

        if session_is_temporary {
            session.clear();
        }

        resp
    }
}

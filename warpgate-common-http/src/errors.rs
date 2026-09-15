//! Client-facing rendering of request errors.

use std::sync::Arc;

use poem::http::{Method, Uri};
use poem::{Endpoint, IntoResponse, Request, Response};
use uuid::Uuid;
use warpgate_common::{UserFacingReason, WarpgateError};

use crate::ext::is_navigation_request;
use crate::internal_page::internal_page;

pub fn render_error(error: poem::Error, method: &Method, uri: &Uri, as_document: bool) -> Response {
    let status = error.status();
    let reason = match error.downcast_ref::<WarpgateError>() {
        Some(error) => error.user_facing_reason(),
        None if status.is_server_error() => status.canonical_reason().unwrap_or("Error").to_owned(),
        None => return error.into_response(),
    };
    let message = if status.is_server_error() {
        let correlation_id = Uuid::new_v4();
        tracing::error!(
            correlation_id = %correlation_id,
            %method,
            %uri,
            // {:#} for single line format
            error = %format!("{error:#}"),
            "Request failed with an internal error"
        );
        format!("{reason} (reference: {correlation_id})")
    } else {
        reason
    };
    if !as_document {
        return message.with_status(status).into_response();
    }
    internal_page("Request failed", &message, None, None)
        .with_status(status)
        .into_response()
}

/// [`render_error`] as a layer, for `.around()`.
///
/// Belongs at the very outside of an app: middleware that runs before
/// routing fails the same way handlers do, and an inner wrapper never sees
/// it. It can also sit inside a middleware that only runs its own
/// post-processing on `Ok` (poem's `ServerSession` persists nothing after an
/// `Err`), so that a handler's side effects survive its failure.
pub async fn render_errors<E: Endpoint + 'static>(
    ep: Arc<E>,
    req: Request,
) -> poem::Result<Response> {
    let as_document = is_navigation_request(&req);
    let method = req.method().clone();
    let uri = req.original_uri().clone();
    Ok(match ep.call(req).await {
        Ok(response) => response.into_response(),
        Err(error) => render_error(error, &method, &uri, as_document),
    })
}

#[cfg(test)]
mod tests {
    use poem::error::ResponseError;
    use poem::http::StatusCode;
    use poem::{Endpoint, EndpointExt, Request, Response, handler};
    use warpgate_common::WarpgateError;

    use super::{Method, Uri, render_error, render_errors};

    const LEAK: &str = "no such table: credentials";

    fn root() -> Uri {
        Uri::from_static("/")
    }

    async fn body_of(response: poem::Response) -> String {
        response.into_body().into_string().await.unwrap()
    }

    /// The measured case: `GET /@warpgate/api/info` laundering a `DbErr`
    /// through `.context()` handed the whole chain to an anonymous caller.
    #[tokio::test]
    async fn a_laundered_foreign_error_is_flattened() {
        let laundered = || -> poem::Error {
            anyhow::anyhow!("{LEAK}")
                .context("loading LDAP servers")
                .into()
        };
        // Asserted first, or this test would pass on a fixture that never
        // carried the text and would prove nothing about the boundary.
        assert!(body_of(laundered().into_response()).await.contains(LEAK));

        let body = body_of(render_error(laundered(), &Method::GET, &root(), false)).await;
        assert!(
            !body.contains(LEAK),
            "the raw error reached the client: {body}"
        );
        assert!(
            body.starts_with("Internal Server Error (reference: "),
            "no correlation id to hand an operator: {body}"
        );
    }

    #[tokio::test]
    async fn a_warpgate_error_renders_its_canonical_reason() {
        let wrapped: poem::Error = WarpgateError::Other(LEAK.into()).into();
        let body = body_of(render_error(wrapped, &Method::GET, &root(), false)).await;
        assert!(
            !body.contains(LEAK),
            "the raw error reached the client: {body}"
        );
        assert!(body.starts_with("Internal Server Error (reference: "));

        let kept: poem::Error = WarpgateError::UserNotFound("alice".into()).into();
        let response = render_error(kept, &Method::GET, &root(), false);
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_of(response).await, "user alice not found");
    }

    /// A 4xx body is where the API's contract lives -- poem-openapi's own
    /// parse and validation messages among it.
    #[tokio::test]
    async fn a_client_error_keeps_its_message() {
        let refused = poem::Error::from_string("field `name` is required", StatusCode::BAD_REQUEST);
        let body = body_of(render_error(refused, &Method::GET, &root(), false)).await;
        assert_eq!(body, "field `name` is required");
    }

    /// The MFA setup gate is a 403 that redirects navigations and carries a
    /// header the SPA keys off; both live in its `as_response`.
    #[tokio::test]
    async fn a_foreign_client_error_keeps_its_own_response() {
        #[derive(Debug, thiserror::Error)]
        #[error("setup required")]
        struct Gate;

        impl ResponseError for Gate {
            fn status(&self) -> StatusCode {
                StatusCode::FORBIDDEN
            }

            fn as_response(&self) -> Response {
                Response::builder()
                    .status(StatusCode::TEMPORARY_REDIRECT)
                    .header("x-marker", "1")
                    .header("location", "/setup")
                    .finish()
            }
        }

        let response = render_error(Gate.into(), &Method::GET, &root(), true);
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(response.header("x-marker"), Some("1"));
        assert_eq!(response.header("location"), Some("/setup"));
    }

    #[tokio::test]
    async fn each_failure_gets_its_own_reference() {
        let first = body_of(render_error(
            anyhow::anyhow!("{LEAK}").into(),
            &Method::GET,
            &root(),
            false,
        ))
        .await;
        let second = body_of(render_error(
            anyhow::anyhow!("{LEAK}").into(),
            &Method::GET,
            &root(),
            false,
        ))
        .await;
        assert_ne!(first, second, "the reference is not per-failure: {first}");
    }

    #[tokio::test]
    async fn the_status_survives_the_flattening() {
        let gateway: poem::Error = poem::error::BadGateway(std::io::Error::other(LEAK));
        let response = render_error(gateway, &Method::GET, &root(), false);
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(
            body_of(response)
                .await
                .starts_with("Bad Gateway (reference: ")
        );
    }

    #[tokio::test]
    async fn a_document_request_gets_a_page_with_the_message_escaped() {
        let refused: poem::Error =
            WarpgateError::UserNotFound("<script>alert(1)</script>".into()).into();
        let response = render_error(refused, &Method::GET, &root(), true);
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.content_type(), Some("text/html; charset=utf-8"));
        let body = body_of(response).await;
        assert!(body.contains("<h1>Request failed</h1>"));
        assert!(
            !body.contains("<script>"),
            "the message was not escaped: {body}"
        );
        assert!(body.contains("&lt;script&gt;"));
    }

    /// Only a client that asks for HTML gets a page; kubectl, curl and the
    /// SPA's `fetch` all send no `Accept: text/html`.
    #[tokio::test]
    async fn only_an_html_accepting_client_gets_a_page() {
        #[handler]
        fn always_fails() -> poem::Result<&'static str> {
            Err(WarpgateError::UserNotFound("someone".into()).into())
        }
        let app = always_fails.around(render_errors);

        let plain = app.call(Request::default()).await.unwrap();
        assert_ne!(plain.content_type(), Some("text/html; charset=utf-8"));
        assert_eq!(body_of(plain).await, "user someone not found");

        let browser = Request::builder()
            .header("accept", "text/html,application/xhtml+xml,*/*;q=0.8")
            .finish();
        let page = app.call(browser).await.unwrap();
        assert_eq!(page.content_type(), Some("text/html; charset=utf-8"));
    }
}

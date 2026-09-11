//! The last thing between a server-side failure and the client that caused it.

use std::sync::Arc;

use poem::web::Html;
use poem::{Endpoint, IntoResponse, Request, Response};
use uuid::Uuid;
use warpgate_common::{UserFacingReason, WarpgateError};

use crate::ext::is_navigation_request;

fn client_facing_reason(error: &poem::Error) -> String {
    let status = error.status();
    let reason = match error.downcast_ref::<WarpgateError>() {
        Some(error) => error.user_facing_reason(),
        None if status.is_server_error() => status.canonical_reason().unwrap_or("Error").to_owned(),
        None => error.to_string(),
    };
    if !status.is_server_error() {
        return reason;
    }
    let correlation_id = Uuid::new_v4();
    tracing::error!(
        correlation_id = %correlation_id,
        // {:#} for single line format
        error = %format!("{error:#}"),
        "Request failed with an internal error"
    );
    format!("{reason} (reference: {correlation_id})")
}

pub fn render_error(error: &poem::Error, as_document: bool) -> Response {
    let status = error.status();
    let message = client_facing_reason(error);
    if !as_document {
        return message.with_status(status).into_response();
    }
    let message = html_escape::encode_text(&message);
    Html(format!(
        r#"<!DOCTYPE html>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol";
            }}

            img {{
                width: 100px;
            }}

            main {{
                width: 400px;
                margin: 200px auto;
            }}
        </style>
        <main>
            <img src="/@warpgate/assets/brand.svg" />
            <h1>Request failed</h1>
            <p>{message}</p>
        </main>
        "#
    ))
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
    Ok(match ep.call(req).await {
        Ok(response) => response.into_response(),
        Err(error) => render_error(&error, as_document),
    })
}

/// [`render_errors`] for a listener no browser ever reaches.
///
/// `is_navigation_request` answers "no `Sec-Fetch-Mode`" with "navigation",
/// which is right for a gateway that still has to serve old browsers and
/// wrong for an API a `kubectl` speaks to: every failing request would be
/// answered with a styled page.
pub async fn render_errors_plain<E: Endpoint + 'static>(
    ep: Arc<E>,
    req: Request,
) -> poem::Result<Response> {
    Ok(match ep.call(req).await {
        Ok(response) => response.into_response(),
        Err(error) => render_error(&error, false),
    })
}

#[cfg(test)]
mod tests {
    use poem::http::StatusCode;
    use warpgate_common::WarpgateError;

    use super::{render_error, render_errors, render_errors_plain};

    const LEAK: &str = "no such table: credentials";

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

        let body = body_of(render_error(&laundered(), false)).await;
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
        let body = body_of(render_error(&wrapped, false)).await;
        assert!(
            !body.contains(LEAK),
            "the raw error reached the client: {body}"
        );
        assert!(body.starts_with("Internal Server Error (reference: "));

        let kept: poem::Error = WarpgateError::UserNotFound("alice".into()).into();
        let response = render_error(&kept, false);
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_of(response).await, "user alice not found");
    }

    /// A 4xx body is where the API's contract lives -- poem-openapi's own
    /// parse and validation messages among it.
    #[tokio::test]
    async fn a_client_error_keeps_its_message() {
        let refused = poem::Error::from_string("field `name` is required", StatusCode::BAD_REQUEST);
        let body = body_of(render_error(&refused, false)).await;
        assert_eq!(body, "field `name` is required");
    }

    #[tokio::test]
    async fn each_failure_gets_its_own_reference() {
        let first = body_of(render_error(&anyhow::anyhow!("{LEAK}").into(), false)).await;
        let second = body_of(render_error(&anyhow::anyhow!("{LEAK}").into(), false)).await;
        assert_ne!(first, second, "the reference is not per-failure: {first}");
    }

    #[tokio::test]
    async fn the_status_survives_the_flattening() {
        let gateway: poem::Error = poem::error::BadGateway(std::io::Error::other(LEAK));
        let response = render_error(&gateway, false);
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
        let response = render_error(&refused, true);
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

    /// The `kubectl` case. A client that sends no `Sec-Fetch-Mode` is read as
    /// a navigation by the shared classifier, so the layer the gateway uses
    /// would answer a machine with a styled page. Asserted through the layer
    /// rather than through `render_error(_, false)`, because what is at stake
    /// is which of the two the Kubernetes listener is wired to.
    #[tokio::test]
    async fn a_header_less_client_is_not_handed_a_page() {
        use poem::{Endpoint, EndpointExt, handler};

        #[handler]
        fn always_fails() -> poem::Result<&'static str> {
            Err(WarpgateError::UserNotFound("someone".into()).into())
        }

        // First the control: the gateway's own layer does hand this exact
        // request a document, or the assertion below would hold for a request
        // that was never classified as a navigation at all.
        let as_document = always_fails
            .around(render_errors)
            .call(poem::Request::default())
            .await
            .unwrap();
        assert_eq!(
            as_document.content_type(),
            Some("text/html; charset=utf-8"),
            "the premise is gone: a header-less request is no longer a navigation"
        );

        let plain = always_fails
            .around(render_errors_plain)
            .call(poem::Request::default())
            .await
            .unwrap();
        assert_eq!(plain.status(), StatusCode::UNAUTHORIZED);
        assert_ne!(plain.content_type(), Some("text/html; charset=utf-8"));
        let body = body_of(plain).await;
        assert!(!body.contains("<!DOCTYPE html>"), "got a page: {body}");
        assert!(body.contains("someone"), "the message was lost: {body}");
    }
}

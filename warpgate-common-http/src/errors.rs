//! The last thing between a server-side failure and the client that caused it.

use std::sync::Arc;

use poem::{Endpoint, IntoResponse, Request, Response};
use uuid::Uuid;
use warpgate_common::WarpgateError;

/// Replaces the body of a 5xx that was rendered from an error's own `Display`.
///
/// [`WarpgateError::as_response`] only runs for an error that reaches poem
/// *as* a `WarpgateError`. Poem renders every other error itself, through a
/// `Display` that forwards to whatever actually failed -- an `anyhow` source
/// as `{err:#}`, so the entire chain. `.context()` and
/// `poem::error::InternalServerError` both land there.
///
/// A 5xx body was never a promise to the caller, so it is safe to replace.
/// 4xx is left alone: that is where the API's contract lives.
///
/// An error still carrying a `WarpgateError` is left to `as_response()`,
/// which is the reviewed decision for those variants. One laundered through
/// `.context()` answers that check while rendering through `Display`, so it
/// slips past and is fixed at its call site instead.
pub fn flatten_internal_error(error: poem::Error) -> poem::Error {
    if !error.status().is_server_error() || error.downcast_ref::<WarpgateError>().is_some() {
        return error;
    }

    let correlation_id = Uuid::new_v4();
    // `%` rather than `?`: `poem::Error`'s `Display` renders an `anyhow`
    // source with `{err:#}`, so the whole causal chain lands on ONE line,
    // where `Debug` would spread it over several and leave a log search for
    // the correlation id showing only the first. Same convention as
    // `WarpgateError::as_response`. This is the only place that detail is
    // written down, and it is the half an operator needs in exchange for
    // what the caller no longer gets.
    tracing::error!(
        correlation_id = %correlation_id,
        error = %error,
        "Request failed with an internal error"
    );
    poem::Error::from_string(
        format!(
            "{} (reference: {correlation_id})",
            error.status().canonical_reason().unwrap_or("Error")
        ),
        error.status(),
    )
}

/// [`flatten_internal_error`] as a layer, for `.around()`.
///
/// Belongs at the very outside of an app: middleware that runs before
/// routing fails the same way handlers do, and an inner wrapper never sees it.
pub async fn flatten_internal_errors<E: Endpoint + 'static>(
    ep: Arc<E>,
    req: Request,
) -> poem::Result<Response> {
    match ep.call(req).await {
        Ok(response) => Ok(response.into_response()),
        Err(error) => Err(flatten_internal_error(error)),
    }
}

#[cfg(test)]
mod tests {
    use poem::error::ResponseError;
    use poem::http::StatusCode;
    use warpgate_common::WarpgateError;

    use super::flatten_internal_error;

    const LEAK: &str = "no such table: credentials";

    async fn body_of(error: poem::Error) -> String {
        error
            .into_response()
            .into_body()
            .into_string()
            .await
            .unwrap()
    }

    /// The measured case: `GET /@warpgate/api/info` laundering a `DbErr`
    /// through `.context()` handed the whole chain to an anonymous caller.
    #[tokio::test]
    async fn a_laundered_foreign_error_is_flattened() {
        let laundered: poem::Error = anyhow::anyhow!("{LEAK}")
            .context("loading LDAP servers")
            .into();
        // Asserted first, or this test would pass on a fixture that never
        // carried the text and would prove nothing about the boundary.
        assert!(body_of(laundered).await.contains(LEAK));

        let laundered: poem::Error = anyhow::anyhow!("{LEAK}")
            .context("loading LDAP servers")
            .into();
        let body = body_of(flatten_internal_error(laundered)).await;
        assert!(
            !body.contains(LEAK),
            "the raw error reached the client: {body}"
        );
        assert!(
            body.starts_with("Internal Server Error (reference: "),
            "no correlation id to hand an operator: {body}"
        );
    }

    /// Without this the flattening could quietly swallow the half of
    /// `as_response()` that exists to keep talking to the caller.
    #[tokio::test]
    async fn a_warpgate_error_is_left_to_as_response() {
        let kept: poem::Error = WarpgateError::ExternalHostUnknown.into();
        let body = body_of(flatten_internal_error(kept)).await;
        assert_eq!(body, WarpgateError::ExternalHostUnknown.to_string());
    }

    /// A 4xx body is where the API's contract lives -- poem-openapi's own
    /// parse and validation messages among it.
    #[tokio::test]
    async fn a_client_error_keeps_its_message() {
        let refused = poem::Error::from_string("field `name` is required", StatusCode::BAD_REQUEST);
        let body = body_of(flatten_internal_error(refused)).await;
        assert_eq!(body, "field `name` is required");
    }

    #[tokio::test]
    async fn each_failure_gets_its_own_reference() {
        let first = body_of(flatten_internal_error(anyhow::anyhow!("{LEAK}").into())).await;
        let second = body_of(flatten_internal_error(anyhow::anyhow!("{LEAK}").into())).await;
        assert_ne!(first, second, "the reference is not per-failure: {first}");
    }

    #[tokio::test]
    async fn the_status_survives_the_flattening() {
        let gateway: poem::Error = poem::error::BadGateway(std::io::Error::other(LEAK));
        let flattened = flatten_internal_error(gateway);
        assert_eq!(flattened.status(), StatusCode::BAD_GATEWAY);
        assert!(
            body_of(flattened)
                .await
                .starts_with("Bad Gateway (reference: ")
        );
    }
}

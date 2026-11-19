use std::sync::Arc;

use poem::http::Method;
use poem::{Endpoint, Request};
use warpgate_common_http::read_body_limited_with_timeout;

use crate::ADMIN_API_MOUNT;
use crate::api::gitops_webhook;

const BODY_LIMIT: usize = 64 * 1024;

/// Whether the route takes more than [`BODY_LIMIT`]. Its body is then left
/// unread here and the handler reads it under its own limit, the admin API
/// only after `AdminContext` has accepted the caller. `path` is relative to
/// the `/@warpgate` mount.
fn limits_its_own_body(method: &Method, path: &str) -> bool {
    match path.strip_prefix(ADMIN_API_MOUNT) {
        Some(path) => warpgate_admin::api::SELF_LIMITED_ROUTES
            .iter()
            .any(|(route_method, route)| route_method == method && *route == path),
        None => method == Method::POST && path == gitops_webhook::PATH,
    }
}

/// Immediately buffer and limit request body
/// for local API and not for proxying
pub async fn limit_request_body<E: Endpoint + 'static>(
    ep: Arc<E>,
    mut req: Request,
) -> poem::Result<E::Output> {
    if !limits_its_own_body(req.method(), req.uri().path()) {
        let body = req.take_body();
        let body = read_body_limited_with_timeout(req.headers(), body, BODY_LIMIT).await?;
        req.set_body(body);
    }
    ep.call(req).await
}

#[cfg(test)]
mod tests {
    use futures::{StreamExt, stream};
    use poem::http::Method;
    use poem::test::TestClient;
    use poem::{Body, EndpointExt, Route, handler, post};

    use super::{BODY_LIMIT, limit_request_body};

    #[handler]
    fn body_length(body: Vec<u8>) -> String {
        body.len().to_string()
    }

    fn client() -> TestClient<impl poem::Endpoint> {
        TestClient::new(
            Route::new().nest(
                "/@warpgate",
                Route::new()
                    .at("/", post(body_length).get(body_length))
                    .at("/api/gitops/webhook", post(body_length).put(body_length))
                    .at(
                        "/admin/api/parameters/logo",
                        post(body_length).put(body_length),
                    )
                    .around(limit_request_body),
            ),
        )
    }

    #[tokio::test]
    async fn leaves_the_body_of_a_self_limited_route_unread() {
        let body = vec![0u8; BODY_LIMIT + 1];
        for (method, path) in [
            (Method::POST, "/@warpgate/api/gitops/webhook"),
            (Method::PUT, "/@warpgate/admin/api/parameters/logo"),
        ] {
            let resp = client()
                .request(method, path)
                .body(body.clone())
                .send()
                .await;
            resp.assert_status_is_ok();
            resp.assert_text(body.len().to_string()).await;
        }
        // The same paths under a method they are not listed with
        for (method, path) in [
            (Method::PUT, "/@warpgate/api/gitops/webhook"),
            (Method::POST, "/@warpgate/admin/api/parameters/logo"),
        ] {
            let resp = client()
                .request(method, path)
                .body(body.clone())
                .send()
                .await;
            resp.assert_status(http::StatusCode::PAYLOAD_TOO_LARGE);
        }
    }

    #[tokio::test]
    async fn refuses_an_oversized_content_length_without_reading() {
        let resp = client()
            .post("/@warpgate/")
            .header("content-length", (BODY_LIMIT + 1).to_string())
            .body("{}")
            .send()
            .await;
        resp.assert_status(http::StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn refuses_an_oversized_chunked_body() {
        let chunks = (0..=BODY_LIMIT / 4096).map(|_| Ok::<_, std::io::Error>(vec![0u8; 4096]));
        let resp = client()
            .post("/@warpgate/")
            .body(Body::from_bytes_stream(stream::iter(chunks)))
            .send()
            .await;
        resp.assert_status(http::StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test(start_paused = true)]
    async fn gives_up_on_a_stalled_body() {
        let stalled =
            stream::iter([Ok::<_, std::io::Error>(vec![0u8; 16])]).chain(stream::pending());
        let resp = client()
            .post("/@warpgate/")
            .body(Body::from_bytes_stream(stalled))
            .send()
            .await;
        resp.assert_status(http::StatusCode::REQUEST_TIMEOUT);
    }

    #[tokio::test]
    async fn passes_a_get_without_content_length() {
        let resp = client().get("/@warpgate/").send().await;
        resp.assert_status_is_ok();
        resp.assert_text("0").await;
    }

    #[tokio::test]
    async fn passes_a_login_body_intact() {
        let login = r#"{"username":"admin","password":"123"}"#;
        let resp = client()
            .post("/@warpgate/")
            .header("content-type", "application/json")
            .header("content-length", login.len().to_string())
            .body(login)
            .send()
            .await;
        resp.assert_status_is_ok();
        resp.assert_text(login.len().to_string()).await;
    }
}

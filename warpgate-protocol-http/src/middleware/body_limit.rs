use std::sync::Arc;

use poem::{Endpoint, Request};
use warpgate_common_http::{AuthenticatedRequestContext, read_body_limited_with_timeout};

const ANONYMOUS_BODY_LIMIT: usize = 64 * 1024;
const AUTHENTICATED_BODY_LIMIT: usize = 8 * 1024 * 1024;

/// Immediately buffer and limit request body
/// for local API and not for proxying
pub async fn limit_request_body<E: Endpoint + 'static>(
    ep: Arc<E>,
    mut req: Request,
) -> poem::Result<E::Output> {
    let limit = if req.data::<AuthenticatedRequestContext>().is_some() {
        AUTHENTICATED_BODY_LIMIT
    } else {
        ANONYMOUS_BODY_LIMIT
    };
    let body = req.take_body();
    let body = read_body_limited_with_timeout(req.headers(), body, limit).await?;
    req.set_body(body);
    ep.call(req).await
}

#[cfg(test)]
mod tests {
    use futures::{StreamExt, stream};
    use poem::test::TestClient;
    use poem::{Body, EndpointExt, handler, post};

    use super::{ANONYMOUS_BODY_LIMIT, limit_request_body};

    #[handler]
    fn body_length(body: Vec<u8>) -> String {
        body.len().to_string()
    }

    fn client() -> TestClient<impl poem::Endpoint> {
        TestClient::new(
            post(body_length)
                .get(body_length)
                .around(limit_request_body),
        )
    }

    #[tokio::test]
    async fn refuses_an_oversized_content_length_without_reading() {
        let resp = client()
            .post("/")
            .header("content-length", (ANONYMOUS_BODY_LIMIT + 1).to_string())
            .body("{}")
            .send()
            .await;
        resp.assert_status(http::StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn refuses_an_oversized_chunked_body() {
        let chunks =
            (0..=ANONYMOUS_BODY_LIMIT / 4096).map(|_| Ok::<_, std::io::Error>(vec![0u8; 4096]));
        let resp = client()
            .post("/")
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
            .post("/")
            .body(Body::from_bytes_stream(stalled))
            .send()
            .await;
        resp.assert_status(http::StatusCode::REQUEST_TIMEOUT);
    }

    #[tokio::test]
    async fn passes_a_get_without_content_length() {
        let resp = client().get("/").send().await;
        resp.assert_status_is_ok();
        resp.assert_text("0").await;
    }

    #[tokio::test]
    async fn passes_a_login_body_intact() {
        let login = r#"{"username":"admin","password":"123"}"#;
        let resp = client()
            .post("/")
            .header("content-type", "application/json")
            .header("content-length", login.len().to_string())
            .body(login)
            .send()
            .await;
        resp.assert_status_is_ok();
        resp.assert_text(login.len().to_string()).await;
    }
}

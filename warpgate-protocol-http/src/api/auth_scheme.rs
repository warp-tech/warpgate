use poem::Request;
use poem_openapi::SecurityScheme;
use poem_openapi::auth::ApiKey;
use warpgate_common_http::AuthenticatedRequestContext;

async fn authenticated_context(req: &Request, _key: ApiKey) -> Option<AuthenticatedRequestContext> {
    req.data::<AuthenticatedRequestContext>().cloned()
}

#[derive(SecurityScheme)]
#[oai(
    rename = "TokenSecurityScheme",
    ty = "api_key",
    key_name = "X-Warpgate-Token",
    key_in = "header",
    checker = "authenticated_context"
)]
pub(crate) struct TokenAuth(AuthenticatedRequestContext);

#[derive(SecurityScheme)]
#[oai(
    rename = "CookieSecurityScheme",
    ty = "api_key",
    key_name = "warpgate-http-session",
    key_in = "cookie",
    checker = "authenticated_context"
)]
pub(crate) struct CookieAuth(AuthenticatedRequestContext);

/// Auth gate - both a check and a AuthenticatedRequestContext extractor at once
#[derive(SecurityScheme)]
pub(crate) enum AuthedSession {
    Token(TokenAuth),
    Cookie(CookieAuth),
}

impl AuthedSession {
    pub fn ctx(&self) -> &AuthenticatedRequestContext {
        match self {
            Self::Token(t) => &t.0,
            Self::Cookie(c) => &c.0,
        }
    }
}

impl std::ops::Deref for AuthedSession {
    type Target = AuthenticatedRequestContext;

    fn deref(&self) -> &Self::Target {
        self.ctx()
    }
}

#[cfg(test)]
mod tests {
    use poem::test::TestClient;
    use poem_openapi::payload::PlainText;
    use poem_openapi::{OpenApi, OpenApiService};

    use super::AuthedSession;

    struct TestApi;

    #[OpenApi]
    impl TestApi {
        #[oai(path = "/guarded", method = "get")]
        async fn guarded(&self, _auth: AuthedSession) -> PlainText<String> {
            PlainText("reached".into())
        }
    }

    // The authenticated context is present as request data only when authenticated
    // (see `inject_request_authorization`). Without it, the gate must reject — whether or
    // not a session cookie happens to be present. The accept path needs a real `Services`
    // and is covered by the e2e suite.
    fn client() -> TestClient<impl poem::Endpoint> {
        TestClient::new(OpenApiService::new(TestApi, "test", "1.0"))
    }

    #[tokio::test]
    async fn rejects_unauthenticated_request_with_session_cookie() {
        let resp = client()
            .get("/guarded")
            .header("cookie", "warpgate-http-session=anything")
            .send()
            .await;
        resp.assert_status(http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rejects_request_with_no_credentials() {
        let resp = client().get("/guarded").send().await;
        resp.assert_status(http::StatusCode::UNAUTHORIZED);
    }
}

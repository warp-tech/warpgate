use poem::Request;
use poem_openapi::SecurityScheme;
use poem_openapi::auth::ApiKey;
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_db_entities as entities;

use super::common::get_user;

#[allow(clippy::unused_async)]
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
pub struct TokenAuth(AuthenticatedRequestContext);

#[derive(SecurityScheme)]
#[oai(
    rename = "CookieSecurityScheme",
    ty = "api_key",
    key_name = "warpgate-http-session",
    key_in = "cookie",
    checker = "authenticated_context"
)]
pub struct CookieAuth(AuthenticatedRequestContext);

/// Requests forwarded by a cluster peer are authenticated by the peer's TLS
/// client certificate at the listener (plus the forwarded user identity
/// resolved into the request authorization — see
/// `cluster_request_authorization`). The node id header only lets this scheme
/// fire: the checker reads the context that `inject_request_authorization`
/// attaches, so a header alone never authenticates.
#[derive(SecurityScheme)]
#[oai(
    rename = "ClusterSecurityScheme",
    ty = "api_key",
    key_name = "x-warpgate-cluster-node",
    key_in = "header",
    checker = "authenticated_context"
)]
pub struct ClusterAuth(AuthenticatedRequestContext);

/// Auth gate - both a check and a AuthenticatedRequestContext extractor at once
#[derive(SecurityScheme)]
pub enum AuthedSession {
    Token(TokenAuth),
    Cookie(CookieAuth),
    Cluster(ClusterAuth),
}

impl AuthedSession {
    pub const fn ctx(&self) -> &AuthenticatedRequestContext {
        match self {
            Self::Token(t) => &t.0,
            Self::Cookie(c) => &c.0,
            Self::Cluster(c) => &c.0,
        }
    }
}

impl std::ops::Deref for AuthedSession {
    type Target = AuthenticatedRequestContext;

    fn deref(&self) -> &Self::Target {
        self.ctx()
    }
}

/// AuthenticatedRequestContext with user already loaded
#[derive(Clone)]
pub struct UserAccess {
    ctx: AuthenticatedRequestContext,
    pub user: entities::User::Model,
}

impl std::ops::Deref for UserAccess {
    type Target = AuthenticatedRequestContext;

    fn deref(&self) -> &Self::Target {
        &self.ctx
    }
}

mod sec_scheme_checkers {
    use super::*;

    pub async fn full_user(req: &Request, _key: ApiKey) -> Option<UserAccess> {
        let ctx = req.data::<AuthenticatedRequestContext>().cloned()?;
        let full = ctx.auth.as_full_user()?;
        let user = get_user(&full, &ctx.services().db).await.ok()??;
        Some(UserAccess { ctx, user })
    }

    pub async fn web_session_user(req: &Request, key: ApiKey) -> Option<UserAccess> {
        // checks the auth kind because a token caller can send a junk session cookie to trigger the cookie scheme
        full_user(req, key)
            .await
            .filter(|access| access.auth.is_session())
    }
}

#[derive(SecurityScheme)]
#[oai(
    rename = "TokenSecurityScheme",
    ty = "api_key",
    key_name = "X-Warpgate-Token",
    key_in = "header",
    checker = "sec_scheme_checkers::full_user"
)]
pub struct FullUserTokenAuth(UserAccess);

#[derive(SecurityScheme)]
#[oai(
    rename = "CookieSecurityScheme",
    ty = "api_key",
    key_name = "warpgate-http-session",
    key_in = "cookie",
    checker = "sec_scheme_checkers::full_user"
)]
pub struct FullUserCookieAuth(UserAccess);

#[derive(SecurityScheme)]
#[oai(
    rename = "ClusterSecurityScheme",
    ty = "api_key",
    key_name = "x-warpgate-cluster-node",
    key_in = "header",
    checker = "sec_scheme_checkers::full_user"
)]
pub struct FullUserClusterAuth(UserAccess);

#[derive(SecurityScheme)]
pub enum FullUser {
    Token(FullUserTokenAuth),
    Cookie(FullUserCookieAuth),
    Cluster(FullUserClusterAuth),
}

impl std::ops::Deref for FullUser {
    type Target = UserAccess;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Token(t) => &t.0,
            Self::Cookie(c) => &c.0,
            Self::Cluster(c) => &c.0,
        }
    }
}

#[derive(SecurityScheme)]
#[oai(
    rename = "CookieSecurityScheme",
    ty = "api_key",
    key_name = "warpgate-http-session",
    key_in = "cookie",
    checker = "sec_scheme_checkers::web_session_user"
)]
pub struct WebSessionCookieAuth(UserAccess);

#[derive(SecurityScheme)]
#[oai(
    rename = "ClusterSecurityScheme",
    ty = "api_key",
    key_name = "x-warpgate-cluster-node",
    key_in = "header",
    checker = "sec_scheme_checkers::web_session_user"
)]
pub struct WebSessionClusterAuth(UserAccess);

/// FullUser except no token auth for sensitive endpoints
#[derive(SecurityScheme)]
pub enum WebSessionUser {
    Cookie(WebSessionCookieAuth),
    Cluster(WebSessionClusterAuth),
}

impl std::ops::Deref for WebSessionUser {
    type Target = UserAccess;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Cookie(c) => &c.0,
            Self::Cluster(c) => &c.0,
        }
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

    #[tokio::test]
    async fn rejects_cluster_node_header_without_a_verified_peer() {
        let resp = client()
            .get("/guarded")
            .header("x-warpgate-cluster-node", "anything")
            .send()
            .await;
        resp.assert_status(http::StatusCode::UNAUTHORIZED);
    }
}

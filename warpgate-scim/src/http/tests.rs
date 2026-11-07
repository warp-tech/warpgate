//! Routing and the gate's refusals, without a database: the accept path needs
//! the running services and is covered by the store tests plus the e2e suite.
#![allow(clippy::indexing_slicing, clippy::panic)]

use poem::http::StatusCode;
use poem::test::TestClient;

use super::scim_app;

#[tokio::test]
async fn without_the_request_context_nothing_is_served() {
    // The context is request data the gateway injects; its absence is a server
    // misconfiguration, never an open door.
    let client = TestClient::new(scim_app());
    let resp = client
        .get("/Users")
        .header("authorization", "Bearer anything")
        .send()
        .await;
    resp.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
}

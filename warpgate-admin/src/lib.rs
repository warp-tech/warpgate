#![feature(decl_macro, proc_macro_hygiene, async_stream)]
use anyhow::Result;
use futures::stream;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use warpgate_common::State;
use rocket::{get, Config};
use rocket::serde::json::Json;
use rocket_okapi::{openapi, openapi_get_routes, JsonSchema};
use rocket_okapi::swagger_ui::{make_swagger_ui, SwaggerUIConfig};
use rocket::fs::{FileServer, relative, Options};
use futures::StreamExt;

pub struct AdminServer {
    state: Arc<Mutex<State>>,
}

use serde::Serialize;


#[derive(Serialize, JsonSchema)]
struct TargetSnapshotData {
    hostname: String,
    port: u16,
}

#[derive(Serialize, JsonSchema)]
struct SessionData {
    id: u64,
    username: Option<String>,
    target: Option<TargetSnapshotData>,
}

#[derive(Serialize, JsonSchema)]
struct IndexResponse {
    sessions: Vec<SessionData>,
}

#[openapi]
#[get("/api/sessions")]
async fn my_controller(
    state: &rocket::State<Arc<Mutex<State>>>
) -> Json<IndexResponse> {
    let state = state.lock().await;

    let sessions = stream::iter(state.sessions.iter()).then(|(id, s)| async move {
        let session = s.lock().await;
        SessionData {
            id: *id,
            username: session.username.clone(),
            target: match &session.target {
                Some(target) => Some(TargetSnapshotData {
                    hostname: target.hostname.clone(),
                    port: target.port.clone(),
                }),
                None => None,
            },
        }
    });
    let sessions = sessions.collect::<Vec<_>>().await;

    Json(IndexResponse { sessions })
}

fn get_docs() -> SwaggerUIConfig {
    SwaggerUIConfig {
        url: "/openapi.json".to_string(),
        ..Default::default()
    }
}

impl AdminServer {
    pub fn new(state: Arc<Mutex<State>>) -> Self {
        AdminServer { state }
    }

    pub async fn run(self, address: SocketAddr) -> Result<()> {
        let state = self.state.clone();

        let mut rocket = rocket::custom(Config {
            address: address.ip(),
            port: address.port(),
            ..Default::default()
        })
            .manage(state)
            .mount("/", openapi_get_routes![my_controller])
            .mount("/swagger", make_swagger_ui(&get_docs()));

        let path = relative!("frontend/dist");
        rocket = rocket.mount("/", FileServer::new(path, Options::Index));

        rocket.launch().await?;

        Ok(())
    }
}

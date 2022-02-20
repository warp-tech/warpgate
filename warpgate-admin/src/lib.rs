#![feature(decl_macro, proc_macro_hygiene, async_stream)]
use anyhow::Result;
use futures::stream;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use warpgate_common::State;
use rocket::{get, delete, Config};
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
struct TargetData {
    host: String,
    port: u16,
}

#[derive(Serialize, JsonSchema)]
struct UserData {
    username: String,
}


#[derive(Serialize, JsonSchema)]
struct SessionData {
    id: u64,
    user: Option<UserData>,
    target: Option<TargetData>,
}

#[derive(Serialize, JsonSchema)]
struct IndexResponse {
    sessions: Vec<SessionData>,
}

#[openapi]
#[get("/api/sessions")]
async fn api_get_all_sessions(
    state: &rocket::State<Arc<Mutex<State>>>
) -> Json<IndexResponse> {
    let state = state.lock().await;

    let sessions = stream::iter(state.sessions.iter()).then(|(id, s)| async move {
        let session = s.lock().await;
        SessionData {
            id: *id,
            user: session.user.as_ref().map(|user| {
                UserData {
                    username: user.username.clone(),
                }
            }),
            target: session.target.as_ref().map(|target|
                TargetData {
                    host: target.host.clone(),
                    port: target.port.clone(),
                }
            ),
        }
    });
    let sessions = sessions.collect::<Vec<_>>().await;

    Json(IndexResponse { sessions })
}


#[openapi]
#[delete("/api/sessions")]
async fn api_close_all_sessions(
    state: &rocket::State<Arc<Mutex<State>>>
) -> Json<()> {
    let state = state.lock().await;

    for s in state.sessions.values() {
        let mut session = s.lock().await;
        session.handle.close();
    }

    Json(())
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
            .mount("/", openapi_get_routes![
                api_get_all_sessions,
                api_close_all_sessions,
            ])
            .mount("/swagger", make_swagger_ui(&get_docs()));

        let path = relative!("frontend/dist");
        rocket = rocket.mount("/", FileServer::new(path, Options::Index));

        rocket.launch().await?;

        Ok(())
    }
}

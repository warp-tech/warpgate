#![feature(decl_macro, proc_macro_hygiene, async_stream)]
use anyhow::Result;
use futures::stream;
use futures::StreamExt;
use helpers::{ApiError, ApiResult, EmptyResponse, UuidParam};
use rocket::fs::{relative, FileServer, Options};
use rocket::serde::json::Json;
use rocket::{delete, get, Config};
use rocket_okapi::swagger_ui::{make_swagger_ui, SwaggerUIConfig};
use rocket_okapi::{openapi, openapi_get_routes, JsonSchema};
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use warpgate_common::{SessionId, SessionState, State};

mod helpers;

pub struct AdminServer {
    state: Arc<Mutex<State>>,
}

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
    id: SessionId,
    user: Option<UserData>,
    target: Option<TargetData>,
}

#[derive(Serialize, JsonSchema)]
struct IndexResponse {
    sessions: Vec<SessionData>,
}

impl SessionData {
    fn new(id: SessionId, session: &SessionState) -> Self {
        Self {
            id,
            user: session.user.as_ref().map(|user| UserData {
                username: user.username.clone(),
            }),
            target: session.target.as_ref().map(|target| TargetData {
                host: target.host.clone(),
                port: target.port.clone(),
            }),
        }
    }
}

#[openapi]
#[get("/sessions")]
async fn api_get_all_sessions(state: &rocket::State<Arc<Mutex<State>>>) -> Json<Vec<SessionData>> {
    let state = state.lock().await;

    let sessions = stream::iter(state.sessions.iter()).then(|(id, s)| async move {
        let session = s.lock().await;
        SessionData::new(*id, &session)
    });
    let sessions = sessions.collect::<Vec<_>>().await;

    Json(sessions)
}

#[openapi]
#[get("/sessions/<id>")]
async fn api_get_session(
    state: &rocket::State<Arc<Mutex<State>>>,
    id: UuidParam,
) -> ApiResult<SessionData> {
    let state = state.lock().await;
    let session = state.sessions.get(id.as_ref()).ok_or(ApiError::NotFound)?;
    let session = session.lock().await;
    Ok(Json(SessionData::new(id.into(), &session)))
}

#[openapi]
#[delete("/sessions")]
async fn api_close_all_sessions(state: &rocket::State<Arc<Mutex<State>>>) -> Json<EmptyResponse> {
    let state = state.lock().await;

    for s in state.sessions.values() {
        let mut session = s.lock().await;
        session.handle.close();
    }

    Json(EmptyResponse {})
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

        let settings = rocket_okapi::settings::OpenApiSettings::new();
        // settings.schema_settings.option_nullable = true;

        let mut rocket = rocket::custom(Config {
            address: address.ip(),
            port: address.port(),
            ..Default::default()
        })
        .manage(state)
        .mount(
            "/api",
            openapi_get_routes![
                settings: api_get_all_sessions,
                api_get_session,
                api_close_all_sessions,
            ],
        )
        .mount("/swagger", make_swagger_ui(&get_docs()));

        let path = relative!("frontend/dist");
        rocket = rocket.mount("/", FileServer::new(path, Options::Index));

        rocket.launch().await?;

        Ok(())
    }
}

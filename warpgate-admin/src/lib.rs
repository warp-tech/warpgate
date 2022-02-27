#![feature(decl_macro, proc_macro_hygiene, async_stream)]
use anyhow::Result;
use helpers::{ApiError, ApiResult, EmptyResponse};
use rocket::fs::{relative, FileServer, Options};
use rocket::serde::json::Json;
use rocket::{delete, get, Config};
use rocket_okapi::swagger_ui::{make_swagger_ui, SwaggerUIConfig};
use rocket_okapi::{openapi, openapi_get_routes, JsonSchema};
use sea_orm::{EntityTrait, QueryOrder};
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use warpgate_common::{SessionSnapshot, State, UUID};
mod helpers;

pub struct AdminServer {
    state: Arc<Mutex<State>>,
}

#[derive(Serialize, JsonSchema)]
struct IndexResponse {
    sessions: Vec<SessionSnapshot>,
}

#[openapi]
#[get("/sessions")]
async fn api_get_all_sessions(
    state: &rocket::State<Arc<Mutex<State>>>,
) -> ApiResult<Vec<SessionSnapshot>> {
    use warpgate_db_entities::Session;

    let state = state.lock().await;
    let sessions: Vec<Session::Model> = Session::Entity::find()
        .order_by_desc(Session::Column::Started)
        .all(&state.db)
        .await
        .or(Err(ApiError::ServerError))?;
    let sessions = sessions
        .into_iter()
        .map(|s| s.into())
        .collect::<Vec<SessionSnapshot>>();
    Ok(Json(sessions))
}

#[openapi]
#[get("/sessions/<id>")]
async fn api_get_session(
    state: &rocket::State<Arc<Mutex<State>>>,
    id: UUID,
) -> ApiResult<SessionSnapshot> {
    use warpgate_db_entities::Session;

    let state = state.lock().await;

    let session = Session::Entity::find_by_id(id.into())
        .one(&state.db)
        .await
        .or(Err(ApiError::ServerError))?
        .ok_or(ApiError::NotFound)?;

    Ok(Json(session.into()))
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

#![feature(decl_macro, proc_macro_hygiene, async_stream)]
use anyhow::Result;
use futures::stream;
use futures::StreamExt;
use rocket::fs::{relative, FileServer, Options};
use rocket::http::Status;
use rocket::request::FromParam;
use rocket::response::{self, Responder};
use rocket::serde::json::Json;
use rocket::{delete, get, Config, Request};
use rocket_okapi::gen::OpenApiGenerator;
use rocket_okapi::okapi::openapi3::{Responses, Parameter};
use rocket_okapi::request::OpenApiFromParam;
use rocket_okapi::response::OpenApiResponderInner;
use rocket_okapi::swagger_ui::{make_swagger_ui, SwaggerUIConfig};
use rocket_okapi::{openapi, openapi_get_routes, JsonSchema, OpenApiError};
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use warpgate_common::{SessionId, SessionState, State};

pub struct AdminServer {
    state: Arc<Mutex<State>>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub enum ApiError {
    NotFound,
    InvalidRequestParameter,
}

pub type ApiResult<T> = Result<Json<T>, ApiError>;

#[derive(Debug, Serialize, JsonSchema)]
pub struct EmptyResponse {}

impl<'r, 'o: 'r> Responder<'r, 'o> for ApiError {
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'o> {
        match self {
            ApiError::NotFound => return Err(Status::NotFound),
            ApiError::InvalidRequestParameter => return Err(Status::BadRequest),
        };
    }
}

fn add_404_error(
    gen: &mut OpenApiGenerator,
    responses: &mut Responses,
) -> Result<(), OpenApiError> {
    let response = Json::<EmptyResponse>::responses(gen)?
        .responses
        .remove("200")
        .unwrap();
    responses
        .responses
        .entry("404".to_owned())
        .or_insert_with(|| response);
    Ok(())
}

impl OpenApiResponderInner for ApiError {
    fn responses(gen: &mut OpenApiGenerator) -> Result<Responses, OpenApiError> {
        let mut responses = Responses::default();
        add_404_error(gen, &mut responses)?;
        Ok(responses)
    }
}

struct UuidParam(uuid::Uuid);

impl<'a> FromParam<'a> for UuidParam {
    type Error = ApiError;

    fn from_param(param: &'a str) -> Result<Self, Self::Error> {
        Ok(UuidParam(
            uuid::Uuid::parse_str(param).map_err(|_| ApiError::InvalidRequestParameter)?,
        ))
    }
}

impl OpenApiFromParam<'_> for UuidParam {
    fn path_parameter(gen: &mut OpenApiGenerator, name: String) -> Result<Parameter, OpenApiError> {
        String::path_parameter(gen, name)
    }
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
    let session = state.sessions.get(&id.0).ok_or(ApiError::NotFound)?;
    let session = session.lock().await;
    Ok(Json(SessionData::new(id.0, &session)))
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

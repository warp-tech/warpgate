use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use http::header::Entry;
use poem::middleware::CookieJarManagerEndpoint;
use poem::session::{
    CookieConfig, ServerSession as PoemSessionMiddleware, ServerSessionEndpoint, Session,
    SessionStorage,
};
use poem::web::cookie::Cookie;
use poem::web::{Data, RemoteAddr};
use poem::{Endpoint, FromRequest, IntoResponse, Middleware, Request, Response};
use serde_json::Value;
use tokio::sync::Mutex;
use tracing::*;
use warpgate_common::{Services, SessionId, SessionStateInit, WarpgateServerHandle};

use crate::common::{COOKIE_MAX_AGE, PROTOCOL_NAME, SESSION_MAX_AGE};
use crate::session_handle::{
    HttpSessionHandle, SessionHandleCommand, WarpgateServerHandleFromRequest,
};

#[derive(Clone)]
pub struct SharedSessionStorage(pub Arc<Mutex<Box<dyn SessionStorage>>>);

static POEM_SESSION_ID_SESSION_KEY: &str = "poem_session_id";

#[async_trait]
impl SessionStorage for SharedSessionStorage {
    async fn load_session(
        &self,
        session_id: &str,
    ) -> poem::Result<Option<BTreeMap<String, Value>>> {
        self.0.lock().await.load_session(session_id).await.map(|o| {
            o.map(|mut s| {
                s.insert(
                    POEM_SESSION_ID_SESSION_KEY.to_string(),
                    session_id.to_string().into(),
                );
                s
            })
        })
    }

    async fn update_session(
        &self,
        session_id: &str,
        entries: &BTreeMap<String, Value>,
        expires: Option<Duration>,
    ) -> poem::Result<()> {
        self.0
            .lock()
            .await
            .update_session(session_id, entries, expires)
            .await
    }

    async fn remove_session(&self, session_id: &str) -> poem::Result<()> {
        self.0.lock().await.remove_session(session_id).await
    }
}

pub struct SessionStore {
    session_handles: HashMap<SessionId, Arc<Mutex<WarpgateServerHandle>>>,
    session_timestamps: HashMap<SessionId, Instant>,
    this: Weak<Mutex<SessionStore>>,
}

static SESSION_ID_SESSION_KEY: &str = "session_id";
static REQUEST_COUNTER_SESSION_KEY: &str = "request_counter";

impl SessionStore {
    pub fn new() -> Arc<Mutex<Self>> {
        Arc::new_cyclic(|me| {
            Mutex::new(Self {
                session_handles: HashMap::new(),
                session_timestamps: HashMap::new(),
                this: me.clone(),
            })
        })
    }

    pub async fn process_request(&mut self, req: Request) -> poem::Result<Request> {
        let session: &Session = <_>::from_request_without_body(&req).await?;

        let request_counter = session.get::<u64>(REQUEST_COUNTER_SESSION_KEY).unwrap_or(0);
        session.set(REQUEST_COUNTER_SESSION_KEY, request_counter + 1);

        if let Some(session_id) = session.get::<SessionId>(SESSION_ID_SESSION_KEY) {
            self.session_timestamps.insert(session_id, Instant::now());
            // } else if request_counter == 5 {
            // Start logging sessions when they've got 5 requests
            // self.create_handle_for(&req).await?;
        };

        Ok(req)
    }

    pub async fn create_handle_for(
        &mut self,
        req: &Request,
    ) -> poem::Result<WarpgateServerHandleFromRequest> {
        let session: &Session = <_>::from_request_without_body(&req).await?;

        if let Some(handle) = self.handle_for(session) {
            return Ok(handle.into());
        }

        let services = Data::<&Services>::from_request_without_body(&req).await?;
        let remote_address: &RemoteAddr = <_>::from_request_without_body(&req).await?;
        let session_storage =
            Data::<&SharedSessionStorage>::from_request_without_body(&req).await?;

        let (session_handle, mut session_handle_rx) = HttpSessionHandle::new();

        let server_handle = services
            .state
            .lock()
            .await
            .register_session(
                &PROTOCOL_NAME,
                SessionStateInit {
                    remote_address: remote_address.0.as_socket_addr().cloned(),
                    handle: Box::new(session_handle),
                },
            )
            .await?;

        let id = server_handle.lock().await.id();
        self.session_handles.insert(id, server_handle.clone());

        session.set(SESSION_ID_SESSION_KEY, id);

        let Some(this) = self.this.upgrade() else {
            return Err(anyhow::anyhow!("Invalid session state").into())
        };
        tokio::spawn({
            let session_storage = (*session_storage).clone();
            let poem_session_id: Option<String> = session.get(POEM_SESSION_ID_SESSION_KEY);
            let id = id.clone();
            async move {
                while let Some(command) = session_handle_rx.recv().await {
                    match command {
                        SessionHandleCommand::Close => {
                            if let Some(ref poem_session_id) = poem_session_id {
                                let _ = session_storage.remove_session(&poem_session_id).await;
                            }
                            info!(%id, "Removed HTTP session");
                            let mut that = this.lock().await;
                            that.session_handles.remove(&id);
                            that.session_timestamps.remove(&id);
                        }
                    }
                }
                Ok::<_, anyhow::Error>(())
            }
        });

        self.session_timestamps.insert(id, Instant::now());

        Ok(server_handle.into())
    }

    pub fn handle_for(&self, session: &Session) -> Option<Arc<Mutex<WarpgateServerHandle>>> {
        session
            .get::<SessionId>(SESSION_ID_SESSION_KEY)
            .and_then(|id| self.session_handles.get(&id).cloned())
    }

    pub fn remove_session(&mut self, session: &Session) {
        if let Some(id) = session.get::<SessionId>(SESSION_ID_SESSION_KEY) {
            self.session_handles.remove(&id);
            self.session_timestamps.remove(&id);
        }
    }

    pub async fn vacuum(&mut self) {
        let now = Instant::now();
        let mut to_remove = vec![];
        for (id, timestamp) in self.session_timestamps.iter() {
            if now.duration_since(*timestamp) > SESSION_MAX_AGE {
                to_remove.push(*id);
            }
        }
        for id in to_remove {
            self.session_handles.remove(&id);
            self.session_timestamps.remove(&id);
        }
    }
}

pub struct SessionMiddleware {
    inner: PoemSessionMiddleware<SharedSessionStorage>,
}

impl SessionMiddleware {
    pub fn new(session_storage: SharedSessionStorage) -> Self {
        Self {
            inner: PoemSessionMiddleware::new(
                CookieConfig::default()
                    .secure(false)
                    .max_age(COOKIE_MAX_AGE)
                    .name("warpgate-http-session"),
                session_storage,
            ),
        }
    }
}

pub struct SessionMiddlewareEndpoint<E: Endpoint> {
    inner: E,
}

impl<E: Endpoint> Middleware<E> for SessionMiddleware {
    type Output = SessionMiddlewareEndpoint<
        CookieJarManagerEndpoint<ServerSessionEndpoint<SharedSessionStorage, E>>,
    >;

    fn transform(&self, ep: E) -> Self::Output {
        SessionMiddlewareEndpoint {
            inner: self.inner.transform(ep),
        }
    }
}

#[async_trait]
impl<E: Endpoint> Endpoint for SessionMiddlewareEndpoint<E> {
    type Output = Response;

    async fn call(&self, req: Request) -> poem::Result<Self::Output> {
        let host = req.original_uri().host().map(|x| x.to_string());
        let mut resp = self.inner.call(req).await?.into_response();
        if let Some(host) = host {
            if let Entry::Occupied(mut entry) = resp.headers_mut().entry(http::header::SET_COOKIE) {
                if let Ok(cookie_str) = entry.get().to_str() {
                    if let Ok(mut cookie) = Cookie::parse(cookie_str) {
                        cookie.set_domain(host);
                        if let Ok(value) = cookie.to_string().parse() {
                            entry.insert(value);
                        }
                    }
                }
            }
        }
        Ok(resp)
    }
}

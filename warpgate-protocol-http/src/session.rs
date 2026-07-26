use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use poem::session::{MemoryStorage, Session, SessionStorage};
use poem::web::{Data, RemoteAddr};
use poem::{FromRequest, Request};
use serde_json::Value;
use tokio::sync::{Mutex, broadcast};
use tracing::info;
use warpgate_common::SessionId;
use warpgate_common_http::SessionKeepalive;
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_core::{SessionStateInit, State, WarpgateServerHandle};

use crate::common::PROTOCOL_NAME;
use crate::session_handle::{HttpSessionHandle, SessionHandleCommand};

#[derive(Clone)]
pub struct SharedSessionStorage(pub Arc<Mutex<Box<MemoryStorage>>>);

static POEM_SESSION_ID_SESSION_KEY: &str = "poem_session_id";

impl SessionStorage for SharedSessionStorage {
    async fn load_session<'a>(
        &'a self,
        session_id: &'a str,
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

    /// Insert or update a session.
    async fn update_session<'a>(
        &'a self,
        session_id: &'a str,
        entries: &'a BTreeMap<String, Value>,
        expires: Option<Duration>,
    ) -> poem::Result<()> {
        self.0
            .lock()
            .await
            .update_session(session_id, entries, expires)
            .await
    }

    /// Remove a session by session id.
    async fn remove_session<'a>(&'a self, session_id: &'a str) -> poem::Result<()> {
        self.0.lock().await.remove_session(session_id).await
    }
}

struct SessionEntry {
    handle: Arc<Mutex<WarpgateServerHandle>>,
    close_sender: broadcast::Sender<()>,
    last_activity: Instant,
    keepalive: Weak<()>,
}

fn is_session_expired(
    last_activity: Instant,
    keepalive: &Weak<()>,
    now: Instant,
    max_age: Duration,
) -> bool {
    now.duration_since(last_activity) > max_age && keepalive.strong_count() == 0
}

pub struct SessionStore {
    sessions: HashMap<SessionId, SessionEntry>,
    this: Weak<Mutex<Self>>,
}

static SESSION_ID_SESSION_KEY: &str = "session_id";
static REQUEST_COUNTER_SESSION_KEY: &str = "request_counter";

impl SessionStore {
    pub fn new() -> Arc<Mutex<Self>> {
        Arc::new_cyclic(|me| {
            Mutex::new(Self {
                sessions: HashMap::new(),
                this: me.clone(),
            })
        })
    }

    pub async fn process_request(&mut self, mut req: Request) -> poem::Result<Request> {
        let session = <&Session>::from_request_without_body(&req).await?;

        let request_counter = session.get::<u64>(REQUEST_COUNTER_SESSION_KEY).unwrap_or(0);
        session.set(REQUEST_COUNTER_SESSION_KEY, request_counter + 1);

        if let Some(session_id) = session.get::<SessionId>(SESSION_ID_SESSION_KEY) {
            if let Some(entry) = self.sessions.get_mut(&session_id) {
                entry.last_activity = Instant::now();
            }
            req.set_data(SessionKeepalive::new(self.keepalive(session_id)));
            // } else if request_counter == 5 {
            // Start logging sessions when they've got 5 requests
            // self.create_handle_for(&req).await?;
        }

        Ok(req)
    }

    pub async fn create_handle_for(
        &mut self,
        req: &Request,
        ctx: &UnauthenticatedRequestContext,
    ) -> poem::Result<Arc<Mutex<WarpgateServerHandle>>> {
        let session = <&Session>::from_request_without_body(req).await?;

        if let Some(handle) = self.handle_for(session) {
            return Ok(handle);
        }

        let remote_address = <&RemoteAddr>::from_request_without_body(req).await?;
        let session_storage = Data::<&SharedSessionStorage>::from_request_without_body(req).await?;

        let (session_handle, mut session_handle_rx) = HttpSessionHandle::new();

        let server_handle = State::register_session(
            &ctx.services().state,
            PROTOCOL_NAME,
            SessionStateInit {
                remote_address: remote_address.0.as_socket_addr().copied(),
                handle: Box::new(session_handle),
            },
        )
        .await?;

        let id = server_handle.lock().await.id();
        let (session_close_sender, _) = broadcast::channel(1);
        self.sessions.insert(
            id,
            SessionEntry {
                handle: server_handle.clone(),
                close_sender: session_close_sender,
                last_activity: Instant::now(),
                keepalive: Weak::new(),
            },
        );

        session.set(SESSION_ID_SESSION_KEY, id);

        let Some(this) = self.this.upgrade() else {
            return Err(anyhow::anyhow!("Invalid session state").into());
        };
        tokio::spawn({
            let session_storage = (*session_storage).clone();
            let poem_session_id: Option<String> = session.get(POEM_SESSION_ID_SESSION_KEY);
            async move {
                while let Some(command) = session_handle_rx.recv().await {
                    match command {
                        SessionHandleCommand::Close => {
                            if let Some(ref poem_session_id) = poem_session_id {
                                let _ = session_storage.remove_session(poem_session_id).await;
                            }
                            info!(%id, "Removed HTTP session");
                            let mut that = this.lock().await;
                            that.remove_session_by_id(id);
                        }
                    }
                }
                Ok::<_, anyhow::Error>(())
            }
        });

        Ok(server_handle)
    }

    pub fn handle_for(&self, session: &Session) -> Option<Arc<Mutex<WarpgateServerHandle>>> {
        session
            .get::<SessionId>(SESSION_ID_SESSION_KEY)
            .and_then(|id| self.sessions.get(&id))
            .map(|entry| entry.handle.clone())
    }

    pub fn close_receiver_for(&self, session: &Session) -> Option<broadcast::Receiver<()>> {
        session
            .get::<SessionId>(SESSION_ID_SESSION_KEY)
            .and_then(|id| self.sessions.get(&id))
            .map(|entry| entry.close_sender.subscribe())
    }

    /// Get a token that prevents the session from getting cleaned up
    /// until it's dropped. For an unknown (already removed) session id the
    /// token is returned unstored — there is nothing left to keep alive.
    fn keepalive(&mut self, id: SessionId) -> Arc<()> {
        let Some(entry) = self.sessions.get_mut(&id) else {
            return Arc::new(());
        };
        if let Some(token) = entry.keepalive.upgrade() {
            return token;
        }
        let token = Arc::new(());
        entry.keepalive = Arc::downgrade(&token);
        token
    }

    pub fn remove_session(&mut self, session: &Session) {
        if let Some(id) = session.get::<SessionId>(SESSION_ID_SESSION_KEY) {
            self.remove_session_by_id(id);
        }
    }

    pub async fn vacuum(&mut self, session_max_age: Duration) {
        let now = Instant::now();
        let to_remove: Vec<SessionId> = self
            .sessions
            .iter()
            .filter(|(_, entry)| {
                is_session_expired(entry.last_activity, &entry.keepalive, now, session_max_age)
            })
            .map(|(id, _)| *id)
            .collect();
        for id in to_remove {
            info!(%id, "Expiring idle HTTP session");
            // Closing the handle also drops the browser-side session, so the client
            // reauthenticates instead of keeping a cookie whose session no longer exists.
            if let Some(handle) = self.sessions.get(&id).map(|entry| entry.handle.clone()) {
                handle
                    .lock()
                    .await
                    .session_state()
                    .lock()
                    .await
                    .handle
                    .close();
            }
            self.remove_session_by_id(id);
        }
    }

    fn remove_session_by_id(&mut self, id: SessionId) {
        if let Some(entry) = self.sessions.remove(&id) {
            let _ = entry.close_sender.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_session_expires() {
        let now = Instant::now();
        let stale = now - Duration::from_secs(60);
        assert!(is_session_expired(
            stale,
            &Weak::new(),
            now,
            Duration::from_secs(1)
        ));
        assert!(!is_session_expired(
            now,
            &Weak::new(),
            now,
            Duration::from_secs(1)
        ));
    }

    #[test]
    fn live_connection_spares_session() {
        let now = Instant::now();
        let stale = now - Duration::from_secs(60);

        let token = Arc::new(());
        let keepalive = Arc::downgrade(&token);
        assert!(!is_session_expired(
            stale,
            &keepalive,
            now,
            Duration::from_secs(1)
        ));

        drop(token);
        assert!(is_session_expired(
            stale,
            &keepalive,
            now,
            Duration::from_secs(1)
        ));
    }
}

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use anyhow::Context;
use poem::error::InternalServerError;
use poem::session::{Session, SessionStorage};
use poem::web::{Data, RemoteAddr};
use poem::{FromRequest, Request};
use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::OnConflict;
use sea_orm::{ColumnTrait, Condition, DatabaseConnection, EntityTrait, QueryFilter};
use serde_json::Value;
use time::OffsetDateTime;
use tokio::sync::{Mutex, broadcast, mpsc};
use tracing::info;
use warpgate_common::{UserSessionId, WarpgateError};
use warpgate_common_http::{SessionAuthorization, SessionKeepalive};
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_core::{State, UserSessionStateInit, WarpgateServerHandle};
use warpgate_db_entities::HttpSession;

use crate::common::{PROTOCOL_NAME, SessionExt};
use crate::session_handle::{HttpSessionHandle, SessionHandleCommand};

#[derive(Clone)]
pub struct SharedSessionStorage(pub DatabaseConnection);

static POEM_SESSION_ID_SESSION_KEY: &str = "poem_session_id";

impl SharedSessionStorage {
    /// Replaces `session`'s contents with the stored row.
    ///
    /// Forwarding a request to a peer leaves this node holding the copy of the
    /// browser session it loaded before the hop, and the session middleware
    /// writes that copy back at the end of the request — over whatever the peer
    /// stored meanwhile, such as the authorization from a login the peer just
    /// completed. Adopting the stored row makes that write-back a no-op.
    pub async fn adopt_stored(&self, session: &Session) -> poem::Result<()> {
        let Some(id) = session.get::<String>(POEM_SESSION_ID_SESSION_KEY) else {
            return Ok(());
        };
        let Some(entries) = self.load_session(&id).await? else {
            session.purge();
            return Ok(());
        };
        // Leaving the session untouched keeps its status `Unchanged`, so a
        // forwarded request the peer did not alter costs no write-back.
        if entries == session.entries() {
            return Ok(());
        }
        session.clear();
        for (key, value) in entries {
            session.set(&key, value);
        }
        Ok(())
    }

    pub async fn gc(&self, max_age: Duration) -> Result<(), WarpgateError> {
        let now = OffsetDateTime::now_utc();
        let expired = Condition::any()
            .add(HttpSession::Column::Expires.lt(now))
            .add(HttpSession::Column::Updated.lt(now - max_age));
        let rows = HttpSession::Entity::find()
            .filter(expired.clone())
            .all(&self.0)
            .await?;
        for row in rows {
            self.end_user_session_in(&row.data).await?;
        }
        HttpSession::Entity::delete_many()
            .filter(expired)
            .exec(&self.0)
            .await?;
        Ok(())
    }

    async fn end_user_session_in(&self, data: &str) -> Result<(), WarpgateError> {
        let entries: BTreeMap<String, Value> = serde_json::from_str(data)?;
        let Some(id) = entries
            .get(SESSION_ID_SESSION_KEY)
            .and_then(|value| serde_json::from_value::<UserSessionId>(value.clone()).ok())
        else {
            return Ok(());
        };
        warpgate_core::db::mark_user_session_and_targets_ended(&self.0, id).await
    }
}

impl SessionStorage for SharedSessionStorage {
    async fn load_session<'a>(
        &'a self,
        session_id: &'a str,
    ) -> poem::Result<Option<BTreeMap<String, Value>>> {
        let Some(model) = HttpSession::Entity::find_by_id(session_id.to_owned())
            .one(&self.0)
            .await
            .context("HTTP session not found")?
        else {
            return Ok(None);
        };

        if model
            .expires
            .is_some_and(|e| e <= OffsetDateTime::now_utc())
        {
            return Ok(None);
        }

        let mut entries: BTreeMap<String, Value> =
            serde_json::from_str(&model.data).map_err(InternalServerError)?;
        // Expose the poem session id so the Warpgate-session teardown path can
        // evict this browser session (see `create_handle_for`).
        entries.insert(
            POEM_SESSION_ID_SESSION_KEY.to_string(),
            session_id.to_string().into(),
        );
        Ok(Some(entries))
    }

    /// Insert or update a session.
    async fn update_session<'a>(
        &'a self,
        session_id: &'a str,
        entries: &'a BTreeMap<String, Value>,
        expires: Option<Duration>,
    ) -> poem::Result<()> {
        let now = OffsetDateTime::now_utc();
        let data = serde_json::to_string(entries).map_err(InternalServerError)?;
        let model = HttpSession::ActiveModel {
            id: Set(session_id.to_owned()),
            expires: Set(expires.map(|d| now + d)),
            data: Set(data),
            updated: Set(now),
        };
        // `exec_without_returning` avoids the last-insert-id path, which MySQL
        // upserts of a non-auto-increment PK misbehave on.
        HttpSession::Entity::insert(model)
            .on_conflict(
                OnConflict::column(HttpSession::Column::Id)
                    .update_columns([
                        HttpSession::Column::Expires,
                        HttpSession::Column::Data,
                        HttpSession::Column::Updated,
                    ])
                    .to_owned(),
            )
            .exec_without_returning(&self.0)
            .await
            .map_err(InternalServerError)?;
        Ok(())
    }

    /// Remove a session by session id. Idempotent: removing an absent id is Ok.
    async fn remove_session<'a>(&'a self, session_id: &'a str) -> poem::Result<()> {
        if let Some(row) = HttpSession::Entity::find_by_id(session_id.to_owned())
            .one(&self.0)
            .await
            .map_err(InternalServerError)?
        {
            self.end_user_session_in(&row.data)
                .await
                .map_err(InternalServerError)?;
        }
        HttpSession::Entity::delete_by_id(session_id.to_owned())
            .exec(&self.0)
            .await
            .map_err(InternalServerError)?;
        Ok(())
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
    sessions: HashMap<UserSessionId, SessionEntry>,
    this: Weak<Mutex<Self>>,
}

pub const SESSION_ID_SESSION_KEY: &str = "session_id";
const SESSION_TOUCH_SESSION_KEY: &str = "touched_at";
const SESSION_TOUCH_DEBOUNCE_SECONDS: i64 = 60;

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

        if !session.is_empty() {
            let now = OffsetDateTime::now_utc().unix_timestamp();
            let touched = session.get::<i64>(SESSION_TOUCH_SESSION_KEY).unwrap_or(0);
            if now - touched >= SESSION_TOUCH_DEBOUNCE_SECONDS {
                session.set(SESSION_TOUCH_SESSION_KEY, now);
            }
        }

        if let Some(session_id) = session.get_session_id() {
            if let Some(entry) = self.sessions.get_mut(&session_id) {
                entry.last_activity = Instant::now();
            }
            req.set_data(SessionKeepalive::new(self.keepalive(session_id)));
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

        let (session_handle, session_handle_rx) = HttpSessionHandle::new();
        let server_handle = State::register_user_session(
            &ctx.services().state,
            PROTOCOL_NAME,
            Self::state_init_for(req, session_handle).await?,
        )
        .await?;

        let id = server_handle.lock().await.id();
        session.set(SESSION_ID_SESSION_KEY, id);
        self.install_entry(req, id, server_handle.clone(), session_handle_rx)
            .await?;
        Ok(server_handle)
    }

    /// A node-local handle over a browser session created on another node: the
    /// parent row is validated once here. Per-request liveness comes from the
    /// cookie-session storage row, which a close deletes cluster-wide.
    pub async fn adopt_handle_for(
        &mut self,
        req: &Request,
        ctx: &UnauthenticatedRequestContext,
        id: UserSessionId,
    ) -> poem::Result<Arc<Mutex<WarpgateServerHandle>>> {
        if let Some(entry) = self.sessions.get(&id) {
            return Ok(entry.handle.clone());
        }

        let session = <&Session>::from_request_without_body(req).await?;
        let unauthorized = || poem::Error::from_status(poem::http::StatusCode::UNAUTHORIZED);
        let row = warpgate_db_entities::UserSession::Entity::find_by_id(id.0)
            .one(&ctx.services().db)
            .await
            .map_err(WarpgateError::from)?
            .filter(|row| row.ended.is_none() && row.protocol == PROTOCOL_NAME.to_string())
            .ok_or_else(unauthorized)?;
        let auth_user_id = match session.get_auth() {
            Some(SessionAuthorization::User { user_id, .. })
            | Some(SessionAuthorization::Ticket { user_id, .. }) => Some(user_id),
            None => None,
        };
        if row.user_id != auth_user_id {
            return Err(unauthorized());
        }

        let (session_handle, session_handle_rx) = HttpSessionHandle::new();
        let server_handle = State::adopt_user_session(
            &ctx.services().state,
            id,
            PROTOCOL_NAME,
            Self::state_init_for(req, session_handle).await?,
        )
        .await;
        self.install_entry(req, id, server_handle.clone(), session_handle_rx)
            .await?;
        Ok(server_handle)
    }

    async fn state_init_for(
        req: &Request,
        session_handle: HttpSessionHandle,
    ) -> poem::Result<UserSessionStateInit> {
        let remote_address = <&RemoteAddr>::from_request_without_body(req).await?;
        Ok(UserSessionStateInit {
            remote_address: remote_address.0.as_socket_addr().copied(),
            handle: Box::new(session_handle),
        })
    }

    async fn install_entry(
        &mut self,
        req: &Request,
        id: UserSessionId,
        server_handle: Arc<Mutex<WarpgateServerHandle>>,
        mut session_handle_rx: mpsc::UnboundedReceiver<SessionHandleCommand>,
    ) -> poem::Result<()> {
        let session = <&Session>::from_request_without_body(req).await?;
        let session_storage = Data::<&SharedSessionStorage>::from_request_without_body(req).await?;

        let (session_close_sender, _) = broadcast::channel(1);
        self.sessions.insert(
            id,
            SessionEntry {
                handle: server_handle,
                close_sender: session_close_sender,
                last_activity: Instant::now(),
                keepalive: Weak::new(),
            },
        );

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
        Ok(())
    }

    pub fn handle_for(&self, session: &Session) -> Option<Arc<Mutex<WarpgateServerHandle>>> {
        session
            .get_session_id()
            .and_then(|id| self.sessions.get(&id))
            .map(|entry| entry.handle.clone())
    }

    pub fn close_receiver_for(&self, session: &Session) -> Option<broadcast::Receiver<()>> {
        session
            .get_session_id()
            .and_then(|id| self.sessions.get(&id))
            .map(|entry| entry.close_sender.subscribe())
    }

    /// Get a token that prevents the session from getting cleaned up
    /// until it's dropped. For an unknown (already removed) session id the
    /// token is returned unstored — there is nothing left to keep alive.
    fn keepalive(&mut self, id: UserSessionId) -> Arc<()> {
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
        if let Some(id) = session.get_session_id() {
            self.remove_session_by_id(id);
        }
    }

    pub fn vacuum(&mut self, session_max_age: Duration) {
        let now = Instant::now();
        let to_remove: Vec<UserSessionId> = self
            .sessions
            .iter()
            .filter(|(_, entry)| {
                is_session_expired(entry.last_activity, &entry.keepalive, now, session_max_age)
            })
            .map(|(id, _)| *id)
            .collect();
        for id in to_remove {
            // Another node may still be serving this DB-backed browser session.
            // Shared storage GC is the authority for global idle expiration.
            info!(%id, "Detaching idle local HTTP session handle");
            self.remove_session_by_id(id);
        }
    }

    /// Detaches the parent's local handle. Its target sessions are owned by
    /// the parent state and drop with it, which is what aborts the requests
    /// served through them.
    fn remove_session_by_id(&mut self, id: UserSessionId) {
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

#[cfg(test)]
mod db_tests {
    use sea_orm::Database;
    use uuid::Uuid;
    use warpgate_db_entities::UserSession;

    use super::*;

    async fn storage() -> SharedSessionStorage {
        warpgate_db_entities::Parameters::set_config_migration_values(
            warpgate_db_entities::Parameters::ConfigMigrationValues::default(),
        );
        let db = Database::connect("sqlite::memory:").await.unwrap();
        warpgate_db_migrations::migrate_database(&db).await.unwrap();
        SharedSessionStorage(db)
    }

    fn entries(auth: &str) -> BTreeMap<String, Value> {
        let mut m = BTreeMap::new();
        m.insert("auth".to_string(), Value::from(auth));
        m
    }

    fn expired_row(id: &str) -> HttpSession::ActiveModel {
        let past = OffsetDateTime::now_utc() - Duration::from_secs(60);
        HttpSession::ActiveModel {
            id: Set(id.to_string()),
            expires: Set(Some(past)),
            data: Set("{}".to_string()),
            updated: Set(past),
        }
    }

    #[tokio::test]
    async fn load_absent_is_none() {
        let s = storage().await;
        assert!(s.load_session("nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn roundtrip_injects_poem_id() {
        let s = storage().await;
        s.update_session("id1", &entries("stamp"), Some(Duration::from_secs(3600)))
            .await
            .unwrap();
        let loaded = s.load_session("id1").await.unwrap().unwrap();
        assert_eq!(loaded.get("auth"), Some(&Value::from("stamp")));
        assert_eq!(
            loaded.get(POEM_SESSION_ID_SESSION_KEY),
            Some(&Value::from("id1"))
        );
    }

    #[tokio::test]
    async fn update_upserts() {
        let s = storage().await;
        s.update_session("id1", &entries("a"), Some(Duration::from_secs(3600)))
            .await
            .unwrap();
        s.update_session("id1", &entries("b"), Some(Duration::from_secs(3600)))
            .await
            .unwrap();
        let loaded = s.load_session("id1").await.unwrap().unwrap();
        assert_eq!(loaded.get("auth"), Some(&Value::from("b")));
    }

    #[tokio::test]
    async fn adopt_stored_replaces_the_local_copy() {
        let s = storage().await;
        s.update_session("id1", &entries("peer"), Some(Duration::from_secs(3600)))
            .await
            .unwrap();

        // What a forwarding node still holds: the copy it loaded before the hop.
        let session = Session::default();
        session.set(POEM_SESSION_ID_SESSION_KEY, "id1");
        session.set("auth", "stale");
        session.set("dropped_by_peer", true);

        s.adopt_stored(&session).await.unwrap();

        assert_eq!(session.get::<String>("auth").as_deref(), Some("peer"));
        assert_eq!(session.get::<bool>("dropped_by_peer"), None);
    }

    #[tokio::test]
    async fn adopt_stored_purges_a_session_the_peer_removed() {
        let s = storage().await;
        let session = Session::default();
        session.set(POEM_SESSION_ID_SESSION_KEY, "id1");

        s.adopt_stored(&session).await.unwrap();

        assert_eq!(session.status(), poem::session::SessionStatus::Purged);
    }

    #[tokio::test]
    async fn remove_is_idempotent() {
        let s = storage().await;
        s.update_session("id1", &entries("a"), Some(Duration::from_secs(3600)))
            .await
            .unwrap();
        s.remove_session("id1").await.unwrap();
        assert!(s.load_session("id1").await.unwrap().is_none());
        // Removing an already-absent id is not an error.
        s.remove_session("id1").await.unwrap();
    }

    #[tokio::test]
    async fn removing_http_session_ends_its_user_session() {
        let s = storage().await;
        let id = Uuid::new_v4();
        UserSession::Entity::insert(UserSession::ActiveModel {
            id: Set(id),
            username: Set(Some("alice".into())),
            user_id: Set(Some(Uuid::new_v4())),
            remote_address: Set("127.0.0.1:443".into()),
            started: Set(OffsetDateTime::now_utc()),
            ended: Set(None),
            protocol: Set("HTTP".into()),
            node_id: Set(Uuid::new_v4()),
        })
        .exec(&s.0)
        .await
        .unwrap();
        let mut data = entries("a");
        data.insert(
            SESSION_ID_SESSION_KEY.into(),
            serde_json::to_value(id).unwrap(),
        );
        s.update_session("id1", &data, Some(Duration::from_secs(3600)))
            .await
            .unwrap();

        s.remove_session("id1").await.unwrap();

        assert!(
            UserSession::Entity::find_by_id(id)
                .one(&s.0)
                .await
                .unwrap()
                .unwrap()
                .ended
                .is_some()
        );
    }

    #[tokio::test]
    async fn expired_row_refused_on_read() {
        let s = storage().await;
        HttpSession::Entity::insert(expired_row("old"))
            .exec(&s.0)
            .await
            .unwrap();
        // Load-time check refuses it even before a GC sweep runs.
        assert!(s.load_session("old").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn gc_sweeps_expired() {
        let s = storage().await;
        HttpSession::Entity::insert(expired_row("old"))
            .exec(&s.0)
            .await
            .unwrap();
        s.update_session("live", &entries("a"), Some(Duration::from_secs(3600)))
            .await
            .unwrap();
        s.gc(Duration::from_secs(86400)).await.unwrap();
        assert!(
            HttpSession::Entity::find_by_id("old".to_string())
                .one(&s.0)
                .await
                .unwrap()
                .is_none()
        );
        assert!(s.load_session("live").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn gc_age_fallback_sweeps_stale_null_expires() {
        let s = storage().await;
        let stale = OffsetDateTime::now_utc() - Duration::from_secs(3600);
        let null_row = |id: &str, updated| HttpSession::ActiveModel {
            id: Set(id.to_string()),
            expires: Set(None),
            data: Set("{}".to_string()),
            updated: Set(updated),
        };
        HttpSession::Entity::insert(null_row("stale", stale))
            .exec(&s.0)
            .await
            .unwrap();
        HttpSession::Entity::insert(null_row("fresh", OffsetDateTime::now_utc()))
            .exec(&s.0)
            .await
            .unwrap();

        s.gc(Duration::from_secs(1800)).await.unwrap();

        // Untouched longer than the cap → reaped even with null expiry.
        assert!(s.load_session("stale").await.unwrap().is_none());
        // Recently written → kept.
        assert!(s.load_session("fresh").await.unwrap().is_some());
    }
}

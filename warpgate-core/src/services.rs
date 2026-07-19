use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use tokio::sync::{Mutex, broadcast, oneshot};
use tracing::warn;
use uuid::Uuid;
use warpgate_common::auth::{ApprovalKind, AuthCredential, AuthResult, CredentialKind};
use warpgate_common::{GlobalParams, Secret, SessionId, WarpgateConfig, WarpgateError};
use warpgate_db_entities::{Parameters, Target};

use crate::approvals::{AdminApprovalStatuses, ApprovalActor, ApprovalDecision};
use crate::auth_state::AuthState;
use crate::cluster::Cluster;
use crate::db::{connect_to_db_and_migrate, populate_db};
use crate::login_protection::LoginProtectionService;
use crate::rate_limiting::RateLimiterRegistry;
use crate::recordings::SessionRecordings;
use crate::{
    AuthStateStore, ConfigProviderEnum, DatabaseConfigProvider, ListenerStatusRegistry, State,
};

#[derive(Clone)]
pub struct Services {
    pub db: DatabaseConnection,
    pub recordings: Arc<Mutex<SessionRecordings>>,
    pub config: Arc<Mutex<WarpgateConfig>>,
    pub cluster: Arc<Cluster>,
    pub state: Arc<Mutex<State>>,
    pub config_provider: Arc<ConfigProviderEnum>,
    pub auth_state_store: Arc<Mutex<AuthStateStore>>,
    pub admin_token: Arc<Option<Secret<String>>>,
    pub cluster_token: Arc<Secret<String>>,
    pub rate_limiter_registry: Arc<Mutex<RateLimiterRegistry>>,
    pub login_protection: Arc<LoginProtectionService>,
    pub global_params: Arc<GlobalParams>,
    pub listener_status: ListenerStatusRegistry,
    /// Approval-request signal senders, held here (cloned from the store) so
    /// request sites can fire them without taking the store lock.
    pub(crate) web_auth_request_tx: broadcast::Sender<Uuid>,
    pub(crate) admin_approval_request_tx: broadcast::Sender<Uuid>,
    /// Sessions on this node blocked in `require_admin_approval`, keyed by
    /// session id. Administrator approval is a gate on the connection rather
    /// than a credential, so the waiter is a plain channel — there is no auth
    /// state for a decision to mutate.
    pub(crate) pending_admin_approvals:
        Arc<Mutex<HashMap<SessionId, oneshot::Sender<(ApprovalDecision, ApprovalActor)>>>>,
    /// Gate outcomes for sessions that observe the gate rather than parking on
    /// it. Shared with [`State`], which drops a session's entry on teardown.
    pub(crate) admin_approval_statuses: AdminApprovalStatuses,
}

/// Upsert the token without conflicts from multiple nodes
/// starting at the same time
async fn resolve_cluster_token(db: &DatabaseConnection) -> Result<Secret<String>> {
    // Ensures the row exists before the conditional update.
    let params = Parameters::Entity::get(db).await?;
    if let Some(token) = params.cluster_token {
        return Ok(Secret::new(token));
    }

    Parameters::Entity::update_many()
        .col_expr(
            Parameters::Column::ClusterToken,
            Expr::value(Secret::<String>::random().expose_secret().clone()),
        )
        .filter(Parameters::Column::ClusterToken.is_null())
        .exec(db)
        .await?;

    Parameters::Entity::get(db)
        .await?
        .cluster_token
        .map(Secret::new)
        .ok_or_else(|| anyhow::anyhow!("cluster token missing after generation"))
}

impl Services {
    pub async fn new(
        mut config: WarpgateConfig,
        admin_token: Option<String>,
        params: GlobalParams,
    ) -> Result<Self> {
        let db = connect_to_db_and_migrate(&config, &params).await?;
        populate_db(&db, &mut config).await?;
        let recordings = SessionRecordings::new(db.clone(), &params);
        let recordings = Arc::new(Mutex::new(recordings));

        let cluster = Arc::new(Cluster::new(db.clone(), config.store.http.listen.port()).await?);
        cluster.start().await?;

        let config = Arc::new(Mutex::new(config));

        let config_provider = Arc::new(DatabaseConfigProvider::new(&db).into());

        let login_protection = Arc::new(LoginProtectionService::new(db.clone()).await?);

        let auth_state_store = Arc::new(Mutex::new(AuthStateStore::new()));
        let admin_approval_statuses = AdminApprovalStatuses::default();
        let (web_auth_request_tx, admin_approval_request_tx) =
            auth_state_store.lock().await.request_signal_senders();

        tokio::spawn({
            let auth_state_store = auth_state_store.clone();
            let db = db.clone();
            async move {
                loop {
                    // A session held for administrator approval must stay
                    // resolvable for the whole configured window, so states are
                    // kept at least that long rather than for the auth-state
                    // TIMEOUT. Falling back to TIMEOUT on a lookup failure only
                    // shortens retention, never extends it.
                    let lifetime = crate::approvals::request_lifetime(&db)
                        .await
                        .unwrap_or_else(|error| {
                            warn!("Failed to read the approval window: {error}");
                            *crate::auth_state_store::TIMEOUT
                        });
                    auth_state_store.lock().await.vacuum(lifetime);
                    // Approval requests are normally deleted by their resolver
                    // or their waiter; rows whose owning node died are aged out
                    // here.
                    if let Err(error) = crate::approvals::reap_stale(&db).await {
                        warn!("Failed to reap stale session approval requests: {error}");
                    }
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
            }
        });

        let rate_limiter_registry = RateLimiterRegistry::new(db.clone());
        rate_limiter_registry.refresh().await?;
        let rate_limiter_registry = Arc::new(Mutex::new(rate_limiter_registry));

        // Opt-in usage analytics reporter. Always spawned; it re-reads consent
        // from the DB on every run and reports nothing unless enabled.
        crate::analytics::start(db.clone());

        // Background cleanup task — always started; cleanup_expired() skips
        // work (and logs its own summary) when there is something to do, and
        // re-reads the enabled flag from the DB on each run.
        {
            let login_protection = login_protection.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(3600));
                loop {
                    interval.tick().await;
                    if let Err(e) = login_protection.cleanup_expired().await {
                        warn!("Login protection cleanup failed: {e}");
                    }
                }
            });
        }

        Ok(Self {
            db: db.clone(),
            recordings,
            config: config.clone(),
            state: State::new(
                &db,
                &rate_limiter_registry,
                cluster.node_id,
                admin_approval_statuses.clone(),
            ),
            cluster,
            rate_limiter_registry,
            config_provider,
            auth_state_store,
            admin_token: Arc::new(admin_token.map(Secret::new)),
            cluster_token: Arc::new(resolve_cluster_token(&db).await?),
            login_protection,
            global_params: Arc::new(params),
            listener_status: Arc::default(),
            web_auth_request_tx,
            admin_approval_request_tx,
            pending_admin_approvals: Arc::default(),
            admin_approval_statuses,
        })
    }

    /// Resolves the user/policy (without the store lock) and inserts a new
    /// [`AuthState`] under a brief store lock. This is the only sanctioned way
    /// to create an auth state, so the "no DB I/O while holding the store lock"
    /// invariant is enforced structurally rather than by convention.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_auth_state(
        &self,
        session_id: Option<&SessionId>,
        username: &str,
        protocol: &str,
        target_name: &str,
        supported_credential_types: &[CredentialKind],
        remote_ip: Option<IpAddr>,
        rate_limit_credential_type: Option<&str>,
    ) -> Result<(Uuid, Arc<Mutex<AuthState>>), WarpgateError> {
        let (user, policy) = AuthStateStore::resolve_user_and_policy(
            &self.config_provider,
            &self.login_protection,
            username,
            protocol,
            supported_credential_types,
            remote_ip,
            rate_limit_credential_type,
        )
        .await?;

        let (id, state_arc) = self.auth_state_store.lock().await.create(
            session_id,
            (&user).into(),
            protocol,
            target_name,
            policy,
            remote_ip,
        );

        // A policy needing nothing but the self-approval (an SSH user with no
        // password or key) never reaches `add_auth_credential`, so it would
        // otherwise go unadvertised.
        let result = state_arc.lock().await.verify();
        self.advertise_if_awaiting_approval(&state_arc, &result)
            .await?;

        Ok((id, state_arc))
    }

    /// Adds a validated credential to the auth state. Part of the sole
    /// sanctioned mutation path for auth states (the raw mutators are
    /// crate-private).
    pub async fn add_auth_credential(
        &self,
        state_arc: &Arc<Mutex<AuthState>>,
        credential: AuthCredential,
    ) -> Result<AuthResult, WarpgateError> {
        let result = state_arc.lock().await.add_valid_credential(credential);
        self.advertise_if_awaiting_approval(state_arc, &result)
            .await?;
        Ok(result)
    }

    /// Advertises a pending self-approval once the login is actually waiting on
    /// one — that is, when the approval is the *only* factor still outstanding.
    ///
    /// Every credential any protocol adds funnels through here, so the request
    /// row exists however the login was driven. Advertising per-protocol instead
    /// would silently leave whichever protocol forgot with an approval the
    /// resolve endpoints can never find.
    ///
    /// Requiring it to be the sole remaining need is what keeps the row honest:
    /// it means "a human must act now". Advertising while a password is still
    /// outstanding would publish a request nobody can yet fulfil, and make the
    /// approval page describe a login that hasn't got that far.
    async fn advertise_if_awaiting_approval(
        &self,
        state_arc: &Arc<Mutex<AuthState>>,
        result: &AuthResult,
    ) -> Result<(), WarpgateError> {
        if matches!(
            result,
            AuthResult::Need(kinds)
                if kinds.len() == 1 && kinds.contains(&CredentialKind::WebUserApproval)
        ) {
            self.request_approval(state_arc).await?;
        }
        Ok(())
    }

    /// Rejects the auth state and purges any pending approval request for it.
    pub async fn reject_auth_state(
        &self,
        state_arc: &Arc<Mutex<AuthState>>,
    ) -> Result<AuthResult, WarpgateError> {
        let (session_id, result) = {
            let mut state = state_arc.lock().await;
            (state.session_id().copied(), state.reject())
        };
        if let Some(session_id) = session_id {
            crate::approvals::delete_request(&self.db, session_id, ApprovalKind::User).await?;
        }
        Ok(result)
    }

    /// Binds the auth state to a session.
    pub async fn set_auth_state_session_id(
        &self,
        state_arc: &Arc<Mutex<AuthState>>,
        session_id: SessionId,
    ) {
        state_arc.lock().await.set_session_id(session_id);
    }

    /// Validates `credential` against the user's stored credentials and, when
    /// valid, adds it to the auth state. Returns the per-credential validity.
    pub async fn validate_and_add_credential(
        &self,
        state_arc: &Arc<Mutex<AuthState>>,
        credential: &AuthCredential,
    ) -> Result<bool, WarpgateError> {
        use crate::ConfigProvider;

        let username = state_arc.lock().await.user_info().username.clone();
        let credential_valid = self
            .config_provider
            .validate_credential(&username, credential)
            .await?;

        if credential_valid {
            self.add_auth_credential(state_arc, credential.clone())
                .await?;
        } else {
            state_arc
                .lock()
                .await
                .emit_authentication_failed_event(Some(credential), "invalid credential");
        }

        Ok(credential_valid)
    }

    /// Whether connections to this target must be approved by an administrator.
    pub async fn target_requires_approval(&self, target_name: &str) -> Result<bool, WarpgateError> {
        Ok(Target::Entity::find()
            .filter(Target::Column::Name.eq(target_name))
            .one(&self.db)
            .await?
            .is_some_and(|t| t.require_approval))
    }

    /// How long a session held for administrator approval waits before being
    /// auto-rejected. Falls back to the auth-state timeout when unset.
    pub async fn admin_approval_timeout(&self) -> Result<Duration, WarpgateError> {
        crate::approvals::admin_approval_timeout(&self.db).await
    }

    /// Configured administrator-approval caching window, or `None` if disabled.
    pub async fn admin_approval_grace_period(&self) -> Result<Option<Duration>, WarpgateError> {
        Ok(Parameters::Entity::get(&self.db)
            .await?
            .admin_approval_grace_period_seconds
            .filter(|s| *s > 0)
            .and_then(|s| u64::try_from(s).ok())
            .map(Duration::from_secs))
    }

    /// If there is a matching remembered self-approval within `grace`, accept
    /// it as a valid credential.
    async fn try_approval_bypass(
        &self,
        state_arc: &Arc<Mutex<AuthState>>,
        grace: Duration,
    ) -> Result<bool, WarpgateError> {
        let Some(key) = state_arc.lock().await.approval_match_key() else {
            return Ok(false);
        };

        if !self
            .auth_state_store
            .lock()
            .await
            .matching_approval_is_fresh(&key, grace)
        {
            return Ok(false);
        }

        let mut state = state_arc.lock().await;

        // A concurrent change may have satisfied or cancelled the requirement.
        let needed_kind = CredentialKind::WebUserApproval;
        if !matches!(state.verify(), AuthResult::Need(ref kinds) if kinds.contains(&needed_kind)) {
            return Ok(false);
        }

        let _ = state.add_valid_credential(AuthCredential::WebUserApproval);
        state.emit_web_approval_bypassed_event();
        let session_id = state.session_id().copied();
        drop(state);

        // The factor is satisfied without anyone resolving the request, so the
        // row would otherwise linger, advertising an approval already granted.
        if let Some(session_id) = session_id {
            crate::approvals::delete_request(&self.db, session_id, ApprovalKind::User).await?;
        }
        Ok(true)
    }

    /// Configured web-approval caching window, or `None` if caching is disabled.
    pub async fn web_approval_grace_period(&self) -> Result<Option<Duration>, WarpgateError> {
        Ok(Parameters::Entity::get(&self.db)
            .await?
            .web_approval_grace_period_seconds
            .filter(|s| *s > 0)
            .and_then(|s| u64::try_from(s).ok())
            .map(Duration::from_secs))
    }

    /// If a matching web approval is still within the grace period, satisfies the
    /// pending `WebUserApproval` requirement and logs an audit event
    pub async fn try_web_approval_bypass(
        &self,
        state_arc: &Arc<Mutex<AuthState>>,
    ) -> Result<bool, WarpgateError> {
        let Some(grace) = self.web_approval_grace_period().await? else {
            return Ok(false);
        };
        self.try_approval_bypass(state_arc, grace).await
    }
}

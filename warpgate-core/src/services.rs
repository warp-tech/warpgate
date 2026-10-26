use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, JoinType, PaginatorTrait, QueryFilter,
    QuerySelect, RelationTrait, TransactionTrait,
};
use time::OffsetDateTime;
use tokio::sync::{Mutex, broadcast};
use tracing::warn;
use uuid::Uuid;
use warpgate_common::auth::{AuthState, CredentialKind};
use warpgate_common::{
    GlobalParams, Protocol, Secret, UserSessionId, WarpgateConfig, WarpgateError,
};
use warpgate_db_entities::Parameters::MfaEnforcement;
use warpgate_db_entities::{
    OtpCredential, Parameters, SsoCredential, TargetSession, Ticket, TicketRequest, UserSession,
};

use crate::auth_state_store::ApprovalRequestSink;
use crate::cluster::{Cluster, ClusterNotification};
use crate::db::connect_to_db_and_migrate;
use crate::helpers::i64_seconds_to_duration;
use crate::login_protection::LoginProtectionService;
use crate::rate_limiting::RateLimiterRegistry;
use crate::recordings::SessionRecordings;
use crate::resources::AdmittedSessions;
use crate::{
    AuthStateStore, ConfigProvider, ConfigProviderEnum, DatabaseConfigProvider,
    ListenerStatusRegistry, SecretBackendRegistry, SessionsFilter, State,
};

#[derive(Clone)]
pub struct Services {
    pub db: DatabaseConnection,
    pub recordings: Arc<SessionRecordings>,
    pub config: Arc<Mutex<WarpgateConfig>>,
    pub cluster: Arc<Cluster>,
    pub state: Arc<Mutex<State>>,
    pub config_provider: Arc<ConfigProviderEnum>,
    pub auth_state_store: Arc<Mutex<AuthStateStore>>,
    pub admin_token: Arc<Option<Secret<String>>>,
    pub rate_limiter_registry: Arc<Mutex<RateLimiterRegistry>>,
    pub login_protection: Arc<LoginProtectionService>,
    pub global_params: Arc<GlobalParams>,
    pub listener_status: ListenerStatusRegistry,
    pub secret_backends: Arc<SecretBackendRegistry>,
}

/// How often a node picks up self approvals decided elsewhere. One query per
/// node, so the interval is set by how long a user should wait after clicking.
const APPROVAL_SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// Session changes arrive in bursts (a scan opening connections, a mass
/// close); everything within this window becomes one cluster notification.
const SESSION_CHANGE_COALESCE_WINDOW: Duration = Duration::from_millis(100);

const TICKET_EXPIRY_SWEEP_INTERVAL: Duration = Duration::from_secs(5);

impl Services {
    pub async fn close_sessions(&self, scope: SessionsFilter) -> Result<(), WarpgateError> {
        scope.revoke(&self.db).await?;
        State::close_local_sessions(&self.state, &scope).await;
        self.cluster.close_sessions_on_peers(&scope).await;
        Ok(())
    }

    pub async fn close_admitted_sessions(
        &self,
        sessions: AdmittedSessions,
    ) -> Result<(), WarpgateError> {
        if sessions.0.is_empty() {
            return Ok(());
        }
        self.close_sessions(SessionsFilter::Sessions { ids: sessions.0 })
            .await
    }

    pub async fn delete_ticket_closing_sessions(
        &self,
        ticket_id: Uuid,
    ) -> Result<(), WarpgateError> {
        let admitted = TargetSession::open_user_sessions_admitted_by_tickets(
            &self.db,
            Ticket::Column::Id.eq(ticket_id),
        )
        .await?;

        let txn = self.db.begin().await?;
        TicketRequest::Entity::delete_many()
            .filter(TicketRequest::Column::TicketId.eq(Some(ticket_id)))
            .exec(&txn)
            .await?;
        Ticket::Entity::delete_by_id(ticket_id).exec(&txn).await?;
        txn.commit().await?;

        self.close_admitted_sessions(AdmittedSessions(admitted))
            .await
    }

    pub async fn close_sessions_of_expired_tickets(&self) -> Result<(), WarpgateError> {
        let ids = TargetSession::open_user_sessions_admitted_by_tickets(
            &self.db,
            Ticket::Column::Expiry.lt(OffsetDateTime::now_utc()),
        )
        .await?;
        self.close_admitted_sessions(AdmittedSessions(ids)).await
    }

    /// Close sessions whose role-based access has ended: their user no longer
    /// holds an active role assignment (not expired, not revoked) that grants
    /// the target. Ticket-admitted sessions are left to the ticket sweep.
    pub async fn close_sessions_without_role_access(&self) -> Result<(), WarpgateError> {
        let open: Vec<(UserSessionId, Uuid, Option<Uuid>)> = TargetSession::Entity::find()
            .join(
                JoinType::InnerJoin,
                TargetSession::Relation::UserSession.def(),
            )
            .filter(TargetSession::Column::Ended.is_null())
            .filter(TargetSession::Column::TicketId.is_null())
            .select_only()
            .column(TargetSession::Column::UserSessionId)
            .column(TargetSession::Column::TargetId)
            .column(UserSession::Column::UserId)
            .into_tuple()
            .all(&self.db)
            .await?;
        let mut allowed: HashMap<Uuid, HashSet<Uuid>> = HashMap::new();
        let mut lost: HashSet<UserSessionId> = HashSet::new();
        for (session, target, user) in open {
            // Sessions without a user (e.g. the admin token) are not role-admitted.
            let Some(user) = user else { continue };
            if lost.contains(&session) {
                continue;
            }
            let targets = match allowed.entry(user) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => {
                    entry.insert(self.config_provider.authorized_target_ids(user).await?)
                }
            };
            if !targets.contains(&target) {
                lost.insert(session);
            }
        }
        self.close_admitted_sessions(AdmittedSessions(lost.into_iter().collect()))
            .await
    }

    pub async fn new(
        config: WarpgateConfig,
        admin_token: Option<String>,
        params: GlobalParams,
    ) -> Result<Self> {
        let db = connect_to_db_and_migrate(&config, &params).await?;
        let recordings = Arc::new(SessionRecordings::new(db.clone(), &params));

        let cluster = Arc::new(Cluster::new(db.clone(), config.store.http.listen.port()).await?);

        let config = Arc::new(Mutex::new(config));

        let config_provider = Arc::new(DatabaseConfigProvider::new(&db).into());

        let login_protection = Arc::new(LoginProtectionService::new(db.clone()).await?);

        let auth_state_store = Arc::new(Mutex::new(AuthStateStore::new(ApprovalRequestSink {
            db: db.clone(),
            cluster: cluster.clone(),
        })));

        tokio::spawn({
            let auth_state_store = auth_state_store.clone();
            let db = db.clone();
            async move {
                loop {
                    auth_state_store.lock().await.vacuum();
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

        let secret_backends = Arc::new(SecretBackendRegistry::new(db.clone()));

        let services = Self {
            db: db.clone(),
            recordings,
            config: config.clone(),
            state: State::new(&db, &rate_limiter_registry, cluster.node_id),
            cluster,
            rate_limiter_registry,
            config_provider,
            auth_state_store,
            admin_token: Arc::new(admin_token.map(Secret::new)),
            login_protection,
            global_params: Arc::new(params),
            listener_status: Arc::default(),
            secret_backends,
        };

        {
            let mut rx = services.state.lock().await.subscribe();
            let cluster = services.cluster.clone();
            tokio::spawn(async move {
                // A missed burst still means "changed" - one notification covers it
                while let Ok(()) | Err(broadcast::error::RecvError::Lagged(_)) = rx.recv().await {
                    tokio::time::sleep(SESSION_CHANGE_COALESCE_WINDOW).await;
                    while !matches!(
                        rx.try_recv(),
                        Err(broadcast::error::TryRecvError::Empty
                            | broadcast::error::TryRecvError::Closed)
                    ) {}
                    cluster.notify_global(ClusterNotification::SessionsChanged);
                }
            });
        }

        {
            let services = services.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(TICKET_EXPIRY_SWEEP_INTERVAL);
                loop {
                    interval.tick().await;
                    if let Err(error) = services.close_sessions_of_expired_tickets().await {
                        warn!("Failed to close sessions of expired tickets: {error}");
                    }
                    if let Err(error) = services.close_sessions_without_role_access().await {
                        warn!("Failed to close sessions without role access: {error}");
                    }
                }
            });
        }

        // Asynchronously detect user approvals received by other nodes
        // and apply them to our AuthStates
        {
            let services = services.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(APPROVAL_SWEEP_INTERVAL);
                loop {
                    interval.tick().await;
                    if let Err(error) = services.apply_decided_user_approvals().await {
                        warn!("Failed to apply resolved session approvals: {error}");
                    }
                }
            });
        }

        Ok(services)
    }

    pub async fn admin_approval_timeout(&self) -> Result<Duration, WarpgateError> {
        crate::approvals::admin_approval_timeout(&self.db).await
    }

    pub async fn admin_approval_grace_period(&self) -> Result<Option<Duration>, WarpgateError> {
        Ok(Parameters::Entity::get(&self.db)
            .await?
            .admin_approval_grace_period_seconds
            .and_then(i64_seconds_to_duration))
    }

    /// Resolves the user/policy (without the store lock) and inserts a new
    /// [`AuthState`] under a brief store lock. This is the only sanctioned way
    /// to create an auth state, so the "no DB I/O while holding the store lock"
    /// invariant is enforced structurally rather than by convention.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_auth_state(
        &self,
        session_id: &UserSessionId,
        username: &str,
        protocol: Protocol,
        target_name: &str,
        supported_credential_types: &[CredentialKind],
        remote_ip: Option<IpAddr>,
        rate_limit_credential_type: Option<&str>,
    ) -> Result<Arc<Mutex<AuthState>>, WarpgateError> {
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

        // Link user session to this node which is gonna hold the auth state
        UserSession::Entity::update_many()
            .col_expr(
                UserSession::Column::AuthStateNodeId,
                Expr::value(self.cluster.node_id),
            )
            .filter(UserSession::Column::Id.eq(*session_id))
            .exec(&self.db)
            .await?;

        Ok(self.auth_state_store.lock().await.create(
            session_id,
            &user,
            protocol,
            target_name,
            policy,
            remote_ip,
        ))
    }

    async fn user_has_sso_credential(&self, user_id: Uuid) -> Result<bool, WarpgateError> {
        Ok(SsoCredential::Entity::find()
            .filter(SsoCredential::Column::UserId.eq(user_id))
            .count(&self.db)
            .await?
            > 0)
    }

    async fn user_has_otp_credential(&self, user_id: Uuid) -> Result<bool, WarpgateError> {
        Ok(OtpCredential::Entity::find()
            .filter(OtpCredential::Column::UserId.eq(user_id))
            .count(&self.db)
            .await?
            > 0)
    }

    /// User's SSO credential can override MFA enforcement if configured
    pub async fn effective_mfa_enforcement(
        &self,
        parameters: &Parameters::Model,
        user_id: Uuid,
    ) -> Result<MfaEnforcement, WarpgateError> {
        let has_sso = self.user_has_sso_credential(user_id).await?;
        Ok(parameters.effective_mfa_enforcement_for_user(has_sso))
    }

    pub async fn mfa_required_factor(
        &self,
        parameters: &Parameters::Model,
        user_id: Uuid,
        protocol: Protocol,
    ) -> Result<Option<CredentialKind>, WarpgateError> {
        if parameters.mfa_enforcement == MfaEnforcement::Off {
            // quick exit without querying for creds
            return Ok(None);
        }
        let has_sso = self.user_has_sso_credential(user_id).await?;
        let has_totp = self.user_has_otp_credential(user_id).await?;
        Ok(parameters.mfa_required_factor(protocol, has_sso, has_totp))
    }

    pub async fn mfa_setup_required(
        &self,
        parameters: &Parameters::Model,
        user_id: Uuid,
    ) -> Result<bool, WarpgateError> {
        if self.effective_mfa_enforcement(parameters, user_id).await? == MfaEnforcement::Off {
            return Ok(false);
        }
        Ok(!self.user_has_otp_credential(user_id).await?)
    }

    /// Configured web-approval caching window, or `None` if caching is disabled.
    pub async fn web_approval_grace_period(&self) -> Result<Option<Duration>, WarpgateError> {
        crate::approvals::web_approval_grace_period(&self.db).await
    }

    /// If a matching web approval is still within the grace period, satisfies the
    /// pending `WebUserApproval` requirement and logs an audit event.
    pub async fn try_web_approval_bypass(
        &self,
        state_arc: &Arc<Mutex<AuthState>>,
    ) -> Result<bool, WarpgateError> {
        crate::approvals::try_web_approval_bypass(&self.db, &self.cluster, state_arc).await
    }
}

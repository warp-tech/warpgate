use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter};
use tokio::sync::Mutex;
use tracing::warn;
use uuid::Uuid;
use warpgate_common::auth::{AuthState, CredentialKind};
use warpgate_common::{
    GlobalParams, Protocol, Secret, UserSessionId, WarpgateConfig, WarpgateError,
};
use warpgate_db_entities::Parameters::MfaEnforcement;
use warpgate_db_entities::{OtpCredential, Parameters, SsoCredential, UserSession};

use crate::cluster::Cluster;
use crate::db::connect_to_db_and_migrate;
use crate::login_protection::LoginProtectionService;
use crate::rate_limiting::RateLimiterRegistry;
use crate::recordings::SessionRecordings;
use crate::{
    AuthStateStore, ConfigProviderEnum, DatabaseConfigProvider, ListenerStatusRegistry, State,
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
    pub cluster_token: Arc<Secret<String>>,
    pub rate_limiter_registry: Arc<Mutex<RateLimiterRegistry>>,
    pub login_protection: Arc<LoginProtectionService>,
    pub global_params: Arc<GlobalParams>,
    pub listener_status: ListenerStatusRegistry,
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

        let auth_state_store = Arc::new(Mutex::new(AuthStateStore::new()));

        tokio::spawn({
            let auth_state_store = auth_state_store.clone();
            async move {
                loop {
                    auth_state_store.lock().await.vacuum();
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
            state: State::new(&db, &rate_limiter_registry, cluster.node_id),
            cluster,
            rate_limiter_registry,
            config_provider,
            auth_state_store,
            admin_token: Arc::new(admin_token.map(Secret::new)),
            cluster_token: Arc::new(resolve_cluster_token(&db).await?),
            login_protection,
            global_params: Arc::new(params),
            listener_status: Arc::default(),
        })
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
        self.auth_state_store
            .lock()
            .await
            .try_web_approval_bypass(state_arc, grace)
            .await
    }
}

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use tokio::sync::Mutex;
use tracing::warn;
use uuid::Uuid;
use warpgate_common::auth::{AuthState, CredentialKind};
use warpgate_common::{GlobalParams, Protocol, Secret, SessionId, WarpgateConfig, WarpgateError};
use warpgate_db_entities::{Parameters, Role, User, UserRoleAssignment};

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
        let recordings = SessionRecordings::new(db.clone(), &params);
        let recordings = Arc::new(Mutex::new(recordings));

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
        session_id: &SessionId,
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
        Ok(self.auth_state_store.lock().await.create(
            session_id,
            &user,
            protocol,
            target_name,
            policy,
            remote_ip,
        ))
    }

    /// Effective web-approval caching window for `user_id`, or `None` if
    /// caching is disabled. Resolved through the user > role > global
    /// override hierarchy: a user-level override wins outright; otherwise the
    /// shortest override among the user's currently active roles wins; else
    /// the global default applies. An explicit `0` at any level means
    /// "disabled at this level" and does not fall through further.
    pub async fn effective_web_approval_grace_period(
        &self,
        user_id: Uuid,
    ) -> Result<Option<Duration>, WarpgateError> {
        resolve_web_approval_grace_period(&self.db, user_id).await
    }

    /// If a matching web approval is still within the grace period, satisfies the
    /// pending `WebUserApproval` requirement and logs an audit event
    pub async fn try_web_approval_bypass(
        &self,
        state_arc: &Arc<Mutex<AuthState>>,
    ) -> Result<bool, WarpgateError> {
        let user_id = state_arc.lock().await.user_info().id;
        let Some(grace) = self.effective_web_approval_grace_period(user_id).await? else {
            return Ok(false);
        };
        self.auth_state_store
            .lock()
            .await
            .try_web_approval_bypass(state_arc, grace)
            .await
    }
}

/// Resolves the effective web-approval caching window for `user_id` through
/// the user > role > global override hierarchy: a user-level override wins
/// outright; otherwise the shortest override among the user's currently
/// active roles (see [`UserRoleAssignment::Entity::find_active`]) wins; else
/// the global default applies. An explicit `0` at any level means "disabled
/// at this level" and does not fall through further. Free-standing (rather
/// than a `Services` method) so it's testable against a bare `DatabaseConnection`.
async fn resolve_web_approval_grace_period(
    db: &DatabaseConnection,
    user_id: Uuid,
) -> Result<Option<Duration>, WarpgateError> {
    let seconds = resolve_web_approval_grace_period_seconds(db, user_id).await?;
    Ok(seconds
        .filter(|s| *s > 0)
        .and_then(|s| u64::try_from(s).ok())
        .map(Duration::from_secs))
}

async fn resolve_web_approval_grace_period_seconds(
    db: &DatabaseConnection,
    user_id: Uuid,
) -> Result<Option<i64>, WarpgateError> {
    if let Some(seconds) = User::Entity::find_by_id(user_id)
        .one(db)
        .await?
        .and_then(|u| u.web_approval_grace_period_seconds)
    {
        return Ok(Some(seconds));
    }

    let role_ids: Vec<Uuid> = UserRoleAssignment::Entity::find_active()
        .filter(UserRoleAssignment::Column::UserId.eq(user_id))
        .all(db)
        .await?
        .into_iter()
        .map(|a| a.role_id)
        .collect();

    if !role_ids.is_empty() {
        let role_override = Role::Entity::find()
            .filter(Role::Column::Id.is_in(role_ids))
            .all(db)
            .await?
            .into_iter()
            .filter_map(|r| r.web_approval_grace_period_seconds)
            .min();
        if role_override.is_some() {
            return Ok(role_override);
        }
    }

    Ok(Parameters::Entity::get(db)
        .await?
        .web_approval_grace_period_seconds)
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use sea_orm::{ActiveModelTrait, Database, Set};
    use time::OffsetDateTime;
    use warpgate_common::UserRequireCredentialsPolicy;
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
    use warpgate_db_migrations::migrate_database;

    use super::*;

    async fn migrated_db() -> DatabaseConnection {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        db
    }

    async fn make_user(db: &DatabaseConnection, grace_seconds: Option<i64>) -> Uuid {
        let id = Uuid::new_v4();
        User::ActiveModel {
            id: Set(id),
            username: Set(id.to_string()),
            credential_policy: Set(
                serde_json::to_value(UserRequireCredentialsPolicy::default()).unwrap(),
            ),
            description: Set(String::new()),
            rate_limit_bytes_per_second: Set(None),
            ldap_server_id: Set(None),
            ldap_object_uuid: Set(None),
            allowed_ip_ranges: Set(serde_json::Value::Null),
            web_approval_grace_period_seconds: Set(grace_seconds),
        }
        .insert(db)
        .await
        .unwrap();
        id
    }

    async fn make_role(db: &DatabaseConnection, grace_seconds: Option<i64>) -> Uuid {
        let id = Uuid::new_v4();
        Role::ActiveModel {
            id: Set(id),
            name: Set(id.to_string()),
            description: Set(String::new()),
            is_default: Set(false),
            web_approval_grace_period_seconds: Set(grace_seconds),
        }
        .insert(db)
        .await
        .unwrap();
        id
    }

    async fn assign_role(db: &DatabaseConnection, user_id: Uuid, role_id: Uuid) {
        UserRoleAssignment::Entity::idempotent_grant(db, user_id, role_id, None)
            .await
            .unwrap();
    }

    async fn set_global_grace(db: &DatabaseConnection, grace_seconds: Option<i64>) {
        let params = Parameters::Entity::get(db).await.unwrap();
        let mut model: Parameters::ActiveModel = params.into();
        model.web_approval_grace_period_seconds = Set(grace_seconds);
        model.update(db).await.unwrap();
    }

    #[tokio::test]
    async fn falls_back_to_global_when_no_user_or_role_override() {
        let db = migrated_db().await;
        set_global_grace(&db, Some(60)).await;
        let user_id = make_user(&db, None).await;

        assert_eq!(
            resolve_web_approval_grace_period(&db, user_id)
                .await
                .unwrap(),
            Some(Duration::from_secs(60))
        );
    }

    #[tokio::test]
    async fn role_override_wins_over_global() {
        let db = migrated_db().await;
        set_global_grace(&db, Some(3600)).await;
        let user_id = make_user(&db, None).await;
        let role_id = make_role(&db, Some(120)).await;
        assign_role(&db, user_id, role_id).await;

        assert_eq!(
            resolve_web_approval_grace_period(&db, user_id)
                .await
                .unwrap(),
            Some(Duration::from_secs(120))
        );
    }

    #[tokio::test]
    async fn user_override_wins_over_role_and_global() {
        let db = migrated_db().await;
        set_global_grace(&db, Some(3600)).await;
        let user_id = make_user(&db, Some(30)).await;
        let role_id = make_role(&db, Some(120)).await;
        assign_role(&db, user_id, role_id).await;

        assert_eq!(
            resolve_web_approval_grace_period(&db, user_id)
                .await
                .unwrap(),
            Some(Duration::from_secs(30))
        );
    }

    #[tokio::test]
    async fn multiple_active_roles_resolve_to_the_shortest() {
        let db = migrated_db().await;
        set_global_grace(&db, Some(3600)).await;
        let user_id = make_user(&db, None).await;
        let strict_role = make_role(&db, Some(60)).await;
        let loose_role = make_role(&db, Some(600)).await;
        assign_role(&db, user_id, strict_role).await;
        assign_role(&db, user_id, loose_role).await;

        assert_eq!(
            resolve_web_approval_grace_period(&db, user_id)
                .await
                .unwrap(),
            Some(Duration::from_secs(60))
        );
    }

    #[tokio::test]
    async fn expired_role_assignment_is_ignored() {
        let db = migrated_db().await;
        set_global_grace(&db, Some(3600)).await;
        let user_id = make_user(&db, None).await;
        let role_id = make_role(&db, Some(60)).await;
        UserRoleAssignment::Entity::idempotent_grant(
            &db,
            user_id,
            role_id,
            Some(OffsetDateTime::now_utc() - Duration::from_secs(60)),
        )
        .await
        .unwrap();

        assert_eq!(
            resolve_web_approval_grace_period(&db, user_id)
                .await
                .unwrap(),
            Some(Duration::from_secs(3600))
        );
    }

    #[tokio::test]
    async fn explicit_zero_at_user_level_disables_caching() {
        let db = migrated_db().await;
        set_global_grace(&db, Some(3600)).await;
        let user_id = make_user(&db, Some(0)).await;
        let role_id = make_role(&db, Some(120)).await;
        assign_role(&db, user_id, role_id).await;

        assert_eq!(
            resolve_web_approval_grace_period(&db, user_id)
                .await
                .unwrap(),
            None
        );
    }
}

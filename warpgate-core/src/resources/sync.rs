//! Syncs the GitOps provider from the source in the parameters: fetch,
//! validate, plan, apply, and record the outcome.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, IntoActiveModel, QueryFilter,
    QueryOrder, Set,
};
use serde_json::Value;
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::{info, warn};
use uuid::Uuid;
use warpgate_common::{ProviderId, SecretResolver, WarpgateError};
use warpgate_db_entities::Parameters::{self, GitopsSource};
use warpgate_db_entities::ProviderSync::{self, SyncStatus, SyncTrigger};
use warpgate_gitops::format_text;
use warpgate_gitops::plan::{Prune, format_errors, format_plan_json, plan};
use warpgate_gitops::source::checkout;
use warpgate_gitops::validate::check_files;

use super::AdmittedSessions;
use super::reconcile::{apply, load_current};
use crate::Services;
use crate::cluster::alive_nodes;
use crate::helpers::i64_seconds_to_duration;

const PROVIDER: ProviderId = ProviderId::GITOPS;

/// How often the schedule is checked; the configured interval is a multiple
const SCHEDULE_TICK: Duration = Duration::from_secs(15);

/// Keeps a failure's text within MySQL's 64 KB `TEXT`
const MAX_ERROR_CHARS: usize = 16_000;

/// The transport only bounds connecting; a remote that then stalls would
/// otherwise hold [`RUNNING`] for good
const CHECKOUT_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// One sync at a time per node; across nodes, `apply` refuses a plan that
/// another node's apply made stale
static RUNNING: Mutex<()> = Mutex::const_new(());

/// A webhook sync is waiting for [`RUNNING`]; further deliveries until it
/// starts add nothing, since it fetches whatever is newest by then
static WEBHOOK_QUEUED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("no GitOps source is configured")]
    NotConfigured,
    #[error(transparent)]
    Other(#[from] WarpgateError),
}

impl From<sea_orm::DbErr> for SyncError {
    fn from(err: sea_orm::DbErr) -> Self {
        Self::Other(err.into())
    }
}

/// What one sync reached, before it is recorded
#[derive(Default)]
struct Attempt {
    revision: Option<String>,
    plan: Option<Value>,
}

/// Syncs once and records the outcome. `force_prune` deletes what is gone
/// from the source however much that is. Returns the sessions that deleted targets had
/// admitted, for the caller to close.
pub async fn sync(
    db: &DatabaseConnection,
    secrets: &dyn SecretResolver,
    trigger: SyncTrigger,
    force_prune: bool,
) -> Result<(ProviderSync::Model, AdmittedSessions), SyncError> {
    let _running = RUNNING.lock().await;
    sync_locked(db, secrets, trigger, force_prune).await
}

/// [`sync`] for a caller that holds [`RUNNING`]
async fn sync_locked(
    db: &DatabaseConnection,
    secrets: &dyn SecretResolver,
    trigger: SyncTrigger,
    force_prune: bool,
) -> Result<(ProviderSync::Model, AdmittedSessions), SyncError> {
    let parameters = Parameters::Entity::get(db).await?;
    let source = parameters.gitops_source.ok_or(SyncError::NotConfigured)?;
    let prune = match (force_prune, parameters.gitops_prune) {
        (true, _) => Prune::Force,
        (false, true) => Prune::On,
        (false, false) => Prune::Off,
    };

    let mut attempt = Attempt::default();
    let result = attempt_sync(db, secrets, &source, prune, &mut attempt).await;
    let (status, error, admitted) = match result {
        Ok(Some(admitted)) => (SyncStatus::Applied, None, admitted),
        Ok(None) => (SyncStatus::Unchanged, None, AdmittedSessions(vec![])),
        Err(error) => (
            SyncStatus::Failed,
            Some(error.chars().take(MAX_ERROR_CHARS).collect()),
            AdmittedSessions(vec![]),
        ),
    };
    let row = ProviderSync::Model {
        id: Uuid::new_v4(),
        provider: PROVIDER,
        triggered_by: trigger,
        status,
        started_at: OffsetDateTime::now_utc(),
        checked_at: OffsetDateTime::now_utc(),
        source: source.describe(),
        revision: attempt.revision,
        plan: attempt.plan,
        error,
    };
    match &row.error {
        Some(error) => warn!(source = %row.source, "GitOps sync failed: {error}"),
        None => {
            info!(source = %row.source, revision = ?row.revision, status = ?row.status, "GitOps sync")
        }
    }
    Ok((record(db, row).await?, admitted))
}

/// `Some` when it applied changes, with the sessions deleted targets admitted
async fn attempt_sync(
    db: &DatabaseConnection,
    secrets: &dyn SecretResolver,
    source: &GitopsSource,
    prune: Prune,
    attempt: &mut Attempt,
) -> Result<Option<AdmittedSessions>, String> {
    let password = match source {
        GitopsSource::Git(git) if git.username.is_some() => Some(
            git.password
                .resolve(secrets)
                .await
                .map_err(|e| format!("git password: {e}"))?,
        ),
        _ => None,
    };
    let source = source.clone();
    let interrupt = Arc::new(AtomicBool::new(false));
    let task = {
        let interrupt = interrupt.clone();
        tokio::task::spawn_blocking(move || checkout(&source, password, &interrupt))
    };
    let checkout = match tokio::time::timeout(CHECKOUT_TIMEOUT, task).await {
        Ok(joined) => joined
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?,
        Err(_) => {
            interrupt.store(true, Ordering::Relaxed);
            return Err(format!(
                "fetching the source took longer than {}s",
                CHECKOUT_TIMEOUT.as_secs()
            ));
        }
    };
    attempt.revision = Some(checkout.revision);

    let resources =
        check_files(&checkout.files).map_err(|diagnostics| format_text(&diagnostics))?;
    let current = load_current(db).await.map_err(|e| e.to_string())?;
    let plan = plan(PROVIDER, &resources, &current, prune);
    attempt.plan = Some(format_plan_json(&plan));
    if plan.has_errors() {
        return Err(format_errors(&plan));
    }
    if !plan.has_pending() {
        return Ok(None);
    }
    apply(db, PROVIDER, &resources, &plan, secrets)
        .await
        .map(Some)
        .map_err(|e| e.to_string())
}

/// A sync that applied nothing and reached what the latest row already says
/// (same source, revision and error) extends that row instead of adding one
async fn record(
    db: &DatabaseConnection,
    row: ProviderSync::Model,
) -> Result<ProviderSync::Model, SyncError> {
    if row.status != SyncStatus::Applied {
        let latest = ProviderSync::Entity::find()
            .filter(ProviderSync::Column::Provider.eq(row.provider))
            .order_by_desc(ProviderSync::Column::StartedAt)
            .one(db)
            .await?;
        if let Some(latest) = latest
            && latest.source == row.source
            && latest.revision == row.revision
            && latest.error == row.error
        {
            let mut latest = latest.into_active_model();
            latest.checked_at = Set(row.checked_at);
            return Ok(latest.update(db).await?);
        }
    }
    Ok(
        ProviderSync::Entity::insert(row.clone().into_active_model())
            .exec_with_returning(db)
            .await?,
    )
}

impl Services {
    /// See [`sync`]; also closes the sessions of deleted targets
    pub async fn sync_gitops(
        &self,
        trigger: SyncTrigger,
        force_prune: bool,
    ) -> Result<ProviderSync::Model, SyncError> {
        let _running = RUNNING.lock().await;
        self.sync_gitops_locked(trigger, force_prune).await
    }

    async fn sync_gitops_locked(
        &self,
        trigger: SyncTrigger,
        force_prune: bool,
    ) -> Result<ProviderSync::Model, SyncError> {
        let (row, admitted) =
            sync_locked(&self.db, &*self.secret_backends, trigger, force_prune).await?;
        self.close_admitted_sessions(admitted).await?;
        Ok(row)
    }

    /// Syncs in the background for a push webhook. Deliveries that arrive
    /// while one is already waiting to start collapse into it.
    pub fn request_gitops_sync(&self) {
        if WEBHOOK_QUEUED.swap(true, Ordering::SeqCst) {
            return;
        }
        let services = self.clone();
        tokio::spawn(async move {
            let _running = RUNNING.lock().await;
            WEBHOOK_QUEUED.store(false, Ordering::SeqCst);
            if let Err(error) = services
                .sync_gitops_locked(SyncTrigger::Webhook, false)
                .await
            {
                warn!("GitOps sync: {error}");
            }
        });
    }

    /// Syncs at startup and then every `gitops_sync_interval_seconds`, on the
    /// live node with the lowest id, so a cluster fetches once per interval.
    /// A source configured later waits for the interval or a sync request.
    // ponytail: a node that dies mid-interval delays the next sync by up to
    // the node timeout; a DB lease would hand over sooner
    pub fn start_gitops_sync(&self) {
        let services = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(SCHEDULE_TICK);
            // `None` only on the first tick, which is the startup sync
            let mut last = None;
            loop {
                tick.tick().await;
                let scheduled = services.scheduled_sync(last).await;
                last.get_or_insert_with(Instant::now);
                let trigger = match scheduled {
                    Ok(Some(trigger)) => trigger,
                    Ok(None) => continue,
                    Err(error) => {
                        warn!("Could not check the GitOps sync schedule: {error}");
                        continue;
                    }
                };
                last = Some(Instant::now());
                if let Err(error) = services.sync_gitops(trigger, false).await {
                    warn!("GitOps sync: {error}");
                }
            }
        });
    }

    async fn scheduled_sync(
        &self,
        last: Option<Instant>,
    ) -> Result<Option<SyncTrigger>, WarpgateError> {
        let parameters = Parameters::Entity::get(&self.db).await?;
        if parameters.gitops_source.is_none() {
            return Ok(None);
        }
        let interval = parameters
            .gitops_sync_interval_seconds
            .and_then(i64_seconds_to_duration);
        let trigger = match (last, interval) {
            (None, _) => SyncTrigger::Startup,
            (Some(last), Some(interval)) if last.elapsed() >= interval => SyncTrigger::Interval,
            _ => return Ok(None),
        };
        let lowest = alive_nodes(&self.db)
            .await?
            .into_iter()
            .map(|node| node.id)
            .min();
        Ok(lowest
            .is_none_or(|id| id == self.cluster.node_id)
            .then_some(trigger))
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use std::fs;

    use sea_orm::PaginatorTrait;
    use warpgate_common::{Secret, SecretError, SecretRef};
    use warpgate_db_entities::Parameters::GitopsDirectorySource;
    use warpgate_db_entities::Role;

    use super::*;
    use crate::resources::tests::db;

    struct NoSecrets;

    #[async_trait::async_trait]
    impl SecretResolver for NoSecrets {
        async fn resolve(&self, _: &SecretRef) -> Result<Secret<String>, SecretError> {
            unreachable!()
        }
    }

    const ROLES: &str = "apiVersion: warpgate/v1\nkind: Role\nmetadata: {name: dba}\nspec: {}\n---\n\
                         apiVersion: warpgate/v1\nkind: Role\nmetadata: {name: ops}\nspec: {}\n";

    async fn configure(db: &DatabaseConnection, dir: &std::path::Path, prune: bool) {
        let mut parameters = Parameters::Entity::get(db)
            .await
            .unwrap()
            .into_active_model();
        parameters.gitops_source = Set(Some(GitopsSource::Directory(GitopsDirectorySource {
            path: dir.display().to_string(),
        })));
        parameters.gitops_prune = Set(prune);
        parameters.update(db).await.unwrap();
    }

    async fn run(db: &DatabaseConnection) -> ProviderSync::Model {
        sync(db, &NoSecrets, SyncTrigger::Api, false)
            .await
            .unwrap()
            .0
    }

    async fn rows(db: &DatabaseConnection) -> u64 {
        ProviderSync::Entity::find().count(db).await.unwrap()
    }

    #[tokio::test]
    async fn records_applied_runs_and_extends_unchanged_ones() {
        let db = db().await;
        assert!(matches!(
            sync(&db, &NoSecrets, SyncTrigger::Api, false).await,
            Err(SyncError::NotConfigured)
        ));

        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("roles.yaml"), ROLES).unwrap();
        configure(&db, dir.path(), false).await;

        let applied = run(&db).await;
        assert_eq!(applied.status, SyncStatus::Applied);
        assert_eq!(Role::Entity::find().count(&db).await.unwrap(), 2);

        let unchanged = run(&db).await;
        assert_eq!(unchanged.id, applied.id, "extends the applied row");
        assert!(unchanged.checked_at >= applied.checked_at);
        assert_eq!(rows(&db).await, 1);

        fs::write(dir.path().join("roles.yaml"), "kind: Nope\n").unwrap();
        let failed = run(&db).await;
        assert_eq!(failed.status, SyncStatus::Failed);
        assert!(failed.error.as_deref().unwrap().contains("roles.yaml"));
        let again = run(&db).await;
        assert_eq!(again.id, failed.id, "the same failure extends its row");
        assert_eq!(rows(&db).await, 2);
    }

    #[tokio::test]
    async fn prunes_only_when_turned_on() {
        let db = db().await;
        let dir = tempfile::tempdir().unwrap();
        let three = format!(
            "{ROLES}---\napiVersion: warpgate/v1\nkind: Role\nmetadata: {{name: dev}}\nspec: {{}}\n"
        );
        fs::write(dir.path().join("roles.yaml"), &three).unwrap();
        configure(&db, dir.path(), false).await;
        run(&db).await;

        let dba_only = ROLES.split("---").next().unwrap();
        fs::write(dir.path().join("roles.yaml"), dba_only).unwrap();
        assert_eq!(run(&db).await.status, SyncStatus::Unchanged);

        configure(&db, dir.path(), true).await;
        let blocked = run(&db).await;
        assert_eq!(
            blocked.status,
            SyncStatus::Failed,
            "2 of 3 is more than half"
        );
        assert!(
            blocked
                .error
                .as_deref()
                .is_some_and(|e| e.starts_with("blocked Role dev: removed from the source")),
            "{:?}",
            blocked.error
        );
        assert_eq!(Role::Entity::find().count(&db).await.unwrap(), 3);

        let (forced, _) = sync(&db, &NoSecrets, SyncTrigger::Api, true).await.unwrap();
        assert_eq!(forced.status, SyncStatus::Applied);
        assert_eq!(Role::Entity::find().count(&db).await.unwrap(), 1);
    }
}

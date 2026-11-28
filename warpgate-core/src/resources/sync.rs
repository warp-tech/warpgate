//! Syncs the GitOps provider from the source in the parameters: fetch,
//! validate, plan, apply, and record the outcome.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant};

use poem_openapi::Object;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait,
    IntoActiveModel, QueryFilter, QueryOrder, QuerySelect, Set,
};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::{info, warn};
use uuid::Uuid;
use warpgate_common::{ProviderId, SecretResolver, UserId, WarpgateError};
use warpgate_db_entities::Parameters::{self, GitopsSource};
use warpgate_db_entities::ProviderSync::{self, SyncPlan, SyncStatus, SyncTrigger};
use warpgate_gitops::format_text;
use warpgate_gitops::plan::{Plan, Prune, format_errors, plan};
use warpgate_gitops::source::{Checkout, checkout, checkout_text, content_hash};
use warpgate_gitops::types::Resource;
use warpgate_gitops::validate::check_files;

use super::AdmittedSessions;
use super::audit::ChangedBy;
use super::reconcile::{Applied, apply, load_current};
use crate::Services;
use crate::cluster::alive_nodes;
use crate::helpers::i64_seconds_to_duration;
use crate::logging::AuditEvent;

const PROVIDER: ProviderId = ProviderId::GITOPS;

/// How often the schedule is checked; the configured interval is a multiple
const SCHEDULE_TICK: Duration = Duration::from_secs(15);

/// Keeps a failure's text within MySQL's 64 KB `TEXT`
const MAX_ERROR_CHARS: usize = 16_000;

/// The transport only bounds connecting. A remote that stalls afterwards
/// would hold [`RUNNING`] forever.
const CHECKOUT_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// One sync at a time per node; across nodes, `apply` refuses a plan that
/// another node's apply made stale
static RUNNING: Mutex<()> = Mutex::const_new(());

/// Set while a webhook sync waits for [`RUNNING`]. Deliveries that arrive
/// before it starts are dropped: it fetches the newest revision anyway.
static WEBHOOK_QUEUED: AtomicBool = AtomicBool::new(false);

/// The last source this node fetched, with its files. While the source's
/// revision is unchanged, a sync reuses them and skips the fetch.
static HELD: std::sync::Mutex<Option<(GitopsSource, Arc<Checkout>)>> = std::sync::Mutex::new(None);

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("no GitOps source is configured")]
    NotConfigured,
    #[error("a GitOps source is configured; remove it to apply files directly")]
    SourceConfigured,
    #[error(transparent)]
    Other(#[from] WarpgateError),
}

impl From<sea_orm::DbErr> for SyncError {
    fn from(err: sea_orm::DbErr) -> Self {
        Self::Other(err.into())
    }
}

/// What asked for a sync
#[derive(Clone, Copy, Debug)]
pub enum SyncRequest {
    Startup,
    Interval,
    Webhook,
    /// `force_prune` deletes what the source dropped, past the mass-deletion guard
    Admin {
        user_id: UserId,
        force_prune: bool,
    },
}

impl SyncRequest {
    const fn trigger(self) -> SyncTrigger {
        match self {
            Self::Startup => SyncTrigger::Startup,
            Self::Interval => SyncTrigger::Interval,
            Self::Webhook => SyncTrigger::Webhook,
            Self::Admin { .. } => SyncTrigger::Api,
        }
    }

    const fn admin(self) -> Option<UserId> {
        match self {
            Self::Admin { user_id, .. } => Some(user_id),
            Self::Startup | Self::Interval | Self::Webhook => None,
        }
    }
}

/// The history's `source` for a sync of files sent with the request
pub const REQUEST_SOURCE: &str = "request";

/// The history's `source` for `warpgate config apply`
const CLI_SOURCE: &str = "command line";

/// Where a sync's files come from
enum Input {
    Source(GitopsSource),
    /// The full desired state, sent with the request
    Request(String),
}

impl Input {
    fn describe(&self) -> String {
        match self {
            Self::Source(source) => source.describe(),
            Self::Request(_) => REQUEST_SOURCE.into(),
        }
    }
}

/// The source's revision and plan, kept for the history when a later step fails
#[derive(Default)]
struct Reached {
    revision: Option<String>,
    plan: Option<SyncPlan>,
}

/// One sync before it is recorded
struct Attempt {
    /// The history row's ID
    id: Uuid,
    /// The admin who requested the sync
    admin: Option<UserId>,
    reached: Reached,
}

/// What a sync would do
#[derive(Object)]
pub struct DryRun {
    pub source: String,
    pub revision: Option<String>,
    pub plan: Option<SyncPlan>,
    pub unchanged: usize,
    /// if anything would be written
    pub pending: bool,
    pub error: Option<String>,
}

/// Fetches and plans as a sync for `request` would. Writes nothing.
pub async fn dry_run(
    db: &DatabaseConnection,
    secrets: &dyn SecretResolver,
    request: SyncRequest,
    files: Option<String>,
) -> Result<DryRun, SyncError> {
    let (input, prune) = current_config(db, request, files, false).await?;
    let mut reached = Reached::default();
    let planned = fetch_and_plan(db, secrets, &input, prune, &mut reached).await;
    Ok(DryRun {
        source: input.describe(),
        revision: reached.revision,
        unchanged: reached.plan.as_ref().map_or(0, SyncPlan::unchanged),
        plan: reached.plan.map(SyncPlan::changes_only),
        pending: planned.as_ref().is_ok_and(|(_, plan)| plan.has_pending()),
        error: planned.err(),
    })
}

/// Fail when trying to `warpgate config apply` while a real source is configured
pub fn assert_may_apply_manual_local_config(
    parameters: &Parameters::Model,
) -> Result<(), SyncError> {
    match parameters.gitops_source {
        Some(_) => Err(SyncError::SourceConfigured),
        None => Ok(()),
    }
}

/// The files to sync, `files` if given, else the configured source, and the
/// prune policy for `request`
async fn current_config(
    db: &DatabaseConnection,
    request: SyncRequest,
    files: Option<String>,
    writes: bool,
) -> Result<(Input, Prune), SyncError> {
    let parameters = Parameters::Entity::get(db).await?;
    if files.is_some() && writes {
        assert_may_apply_manual_local_config(&parameters)?;
    }
    let input = match (files, parameters.gitops_source) {
        (Some(files), _) => Input::Request(files),
        (None, Some(source)) => Input::Source(source),
        (None, None) => return Err(SyncError::NotConfigured),
    };
    // Forcing only disables the mass-deletion guard. It doesn't enable pruning.
    let prune = match (parameters.gitops_prune, request) {
        (false, _) => Prune::Off,
        (
            true,
            SyncRequest::Admin {
                force_prune: true, ..
            },
        ) => Prune::Force,
        (true, _) => Prune::On,
    };
    Ok((input, prune))
}

/// A finished sync that isn't in the history yet
struct Outcome {
    row: ProviderSync::Model,
    /// The admin who requested the sync
    admin: Option<UserId>,
}

impl Outcome {
    /// Puts the sync into the history and the audit log
    async fn record(self, db: &DatabaseConnection) -> Result<ProviderSync::Model, SyncError> {
        let id = self.row.id;
        let recorded = record(db, self.row).await?;
        // A different ID means `record` extended an earlier row; repeats aren't audited
        if recorded.id == id {
            audit_sync(&recorded, self.admin);
        }
        Ok(recorded)
    }
}

/// Syncs once. The caller holds [`RUNNING`]. `files`, when given, is the full
/// desired state. The caller records the returned outcome and closes the
/// returned sessions of deleted targets.
async fn sync_locked(
    db: &DatabaseConnection,
    secrets: &dyn SecretResolver,
    request: SyncRequest,
    files: Option<String>,
) -> Result<(Outcome, AdmittedSessions), SyncError> {
    // The history shows when a sync began, and the fetch can take minutes
    let started_at = OffsetDateTime::now_utc();
    let (input, prune) = current_config(db, request, files, true).await?;
    let mut attempt = Attempt {
        id: Uuid::new_v4(),
        admin: request.admin(),
        reached: Reached::default(),
    };
    let result = attempt_sync(db, secrets, &input, prune, &mut attempt).await;
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
        id: attempt.id,
        provider: PROVIDER,
        triggered_by: request.trigger(),
        status,
        started_at,
        checked_at: started_at,
        source: input.describe(),
        revision: attempt.reached.revision,
        plan: attempt.reached.plan.map(SyncPlan::changes_only),
        error,
    };
    match &row.error {
        Some(error) => warn!(source = %row.source, "GitOps sync failed: {error}"),
        None => {
            info!(source = %row.source, revision = ?row.revision, status = ?row.status, "GitOps sync")
        }
    }
    let outcome = Outcome {
        row,
        admin: attempt.admin,
    };
    Ok((outcome, admitted))
}

fn audit_sync(row: &ProviderSync::Model, admin: Option<UserId>) {
    AuditEvent::ProviderSynced {
        sync_id: row.id,
        provider: PROVIDER.label(),
        trigger: format!("{:?}", row.triggered_by),
        status: format!("{:?}", row.status),
        source: row.source.clone(),
        revision: row.revision.clone(),
        actor_user_id: admin,
    }
    .emit();
}

fn audit_changes(sync_id: Uuid, admin: Option<UserId>, applied: &Applied) {
    let by = ChangedBy::Sync {
        id: sync_id,
        provider: PROVIDER,
        admin,
    };
    for entry in &applied.entries {
        entry.log(by);
    }
    for change in &applied.role_assignments {
        change.audit(by);
    }
}

/// Writes the history row and the audit events for `warpgate config apply`
pub async fn record_cli_apply(
    db: &DatabaseConnection,
    files: &[(PathBuf, String)],
    plan: &Plan,
    applied: &Applied,
) -> Result<(), SyncError> {
    let now = OffsetDateTime::now_utc();
    let row = ProviderSync::Model {
        id: Uuid::new_v4(),
        provider: PROVIDER,
        triggered_by: SyncTrigger::Cli,
        status: SyncStatus::Applied,
        started_at: now,
        checked_at: now,
        source: CLI_SOURCE.into(),
        revision: Some(content_hash(files)),
        plan: Some(SyncPlan::from(plan).changes_only()),
        error: None,
    };
    audit_changes(row.id, None, applied);
    audit_sync(&record(db, row).await?, None);
    Ok(())
}

/// `Some` when it applied changes, with the sessions deleted targets admitted
async fn attempt_sync(
    db: &DatabaseConnection,
    secrets: &dyn SecretResolver,
    input: &Input,
    prune: Prune,
    attempt: &mut Attempt,
) -> Result<Option<AdmittedSessions>, String> {
    let (resources, plan) = fetch_and_plan(db, secrets, input, prune, &mut attempt.reached).await?;
    if !plan.has_pending() {
        return Ok(None);
    }
    let applied = apply(db, PROVIDER, &resources, &plan, secrets)
        .await
        .map_err(|e| e.to_string())?;
    if applied.entries.is_empty() {
        return Ok(None);
    }
    audit_changes(attempt.id, attempt.admin, &applied);
    Ok(Some(applied.admitted))
}

/// Fetches and validates the files, and plans them against the database. A
/// plan with collisions or blocked changes is an error.
async fn fetch_and_plan(
    db: &DatabaseConnection,
    secrets: &dyn SecretResolver,
    input: &Input,
    prune: Prune,
    reached: &mut Reached,
) -> Result<(Vec<Resource>, Plan), String> {
    let checkout = match input {
        Input::Source(source) => fetch(secrets, source).await?,
        Input::Request(yaml) => Arc::new(checkout_text(yaml.clone())),
    };
    reached.revision = Some(checkout.revision.clone());

    let resources = check_files(&checkout.files)
        .map_err(|diagnostics| format_text(&diagnostics))?
        .resources;
    let current = load_current(db).await.map_err(|e| e.to_string())?;
    let plan = plan(PROVIDER, &resources, &current, prune);
    reached.plan = Some(SyncPlan::from(&plan));
    if plan.has_errors() {
        return Err(format_errors(&plan));
    }
    Ok((resources, plan))
}

/// Checks out the source, off the async runtime and within [`CHECKOUT_TIMEOUT`]
async fn fetch(
    secrets: &dyn SecretResolver,
    source: &GitopsSource,
) -> Result<Arc<Checkout>, String> {
    let password = match source {
        GitopsSource::Git(git) => Some(
            git.password
                .resolve(secrets)
                .await
                .map_err(|e| format!("git password: {e}"))?,
        )
        .filter(|password| !password.expose_secret().is_empty()),
        GitopsSource::Directory(_) => None,
    };
    let held = HELD
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
        .filter(|(of, _)| of == source)
        .map(|(_, checkout)| checkout.clone());
    let interrupt = Arc::new(AtomicBool::new(false));
    let task = {
        let (source, interrupt) = (source.clone(), interrupt.clone());
        tokio::task::spawn_blocking(move || checkout(&source, password, held, &interrupt))
    };
    match tokio::time::timeout(CHECKOUT_TIMEOUT, task).await {
        Ok(joined) => {
            let checkout = joined
                .map_err(|e| e.to_string())?
                .map_err(|e| e.to_string())?;
            *HELD.lock().unwrap_or_else(PoisonError::into_inner) =
                Some((source.clone(), checkout.clone()));
            Ok(checkout)
        }
        Err(_) => {
            interrupt.store(true, Ordering::Relaxed);
            Err(format!(
                "fetching the source took longer than {}s",
                CHECKOUT_TIMEOUT.as_secs()
            ))
        }
    }
}

/// This provider's syncs, the most recent first
pub fn newest_first() -> sea_orm::Select<ProviderSync::Entity> {
    ProviderSync::Entity::find()
        .filter(ProviderSync::Column::Provider.eq(PROVIDER))
        .order_by_desc(ProviderSync::Column::StartedAt)
        .order_by_desc(ProviderSync::Column::Id)
}

/// The most recent sync, or the most recent one that didn't fail
pub async fn latest<C: ConnectionTrait>(
    db: &C,
    successful: bool,
) -> Result<Option<ProviderSync::Model>, sea_orm::DbErr> {
    let mut query = newest_first();
    if successful {
        query = query.filter(ProviderSync::Column::Status.ne(SyncStatus::Failed));
    }
    query.one(db).await
}

/// What the admin UI shows of the latest sync on every page
pub struct LatestOutcome {
    pub status: SyncStatus,
    pub started_at: OffsetDateTime,
    pub source: String,
    pub error: Option<String>,
}

/// The latest sync's outcome, read without its plan
pub async fn latest_outcome<C: ConnectionTrait>(
    db: &C,
) -> Result<Option<LatestOutcome>, sea_orm::DbErr> {
    use ProviderSync::Column;
    let row: Option<(SyncStatus, OffsetDateTime, String, Option<String>)> = newest_first()
        .select_only()
        .columns([
            Column::Status,
            Column::StartedAt,
            Column::Source,
            Column::Error,
        ])
        .into_tuple()
        .one(db)
        .await?;
    Ok(
        row.map(|(status, started_at, source, error)| LatestOutcome {
            status,
            started_at,
            source,
            error,
        }),
    )
}

/// A sync that applied nothing and reached what the latest row already says
/// (same trigger, source, revision and error) extends that row instead of
/// adding one
async fn record(
    db: &DatabaseConnection,
    row: ProviderSync::Model,
) -> Result<ProviderSync::Model, SyncError> {
    if row.status != SyncStatus::Applied
        && let Some(latest) = latest(db, false).await?
        && latest.triggered_by == row.triggered_by
        && latest.source == row.source
        && latest.revision == row.revision
        && latest.error == row.error
    {
        let mut latest = latest.into_active_model();
        latest.checked_at = Set(row.checked_at);
        return Ok(latest.update(db).await?);
    }
    Ok(
        ProviderSync::Entity::insert(row.clone().into_active_model())
            .exec_with_returning(db)
            .await?,
    )
}

impl Services {
    /// Syncs once, after any sync already running, and records the outcome.
    /// `files`, when given, is the full desired state. Closes the sessions of
    /// deleted targets.
    pub async fn sync_gitops(
        &self,
        request: SyncRequest,
        files: Option<String>,
    ) -> Result<ProviderSync::Model, SyncError> {
        let services = self.clone();
        // Spawned because the caller can be cancelled, e.g. an HTTP handler
        // whose client disconnects. A sync cancelled after its commit would
        // be missing from the history and the audit log.
        tokio::spawn(async move {
            let _running = RUNNING.lock().await;
            services.sync_gitops_locked(request, files).await
        })
        .await
        .map_err(|error| SyncError::Other(WarpgateError::Other(Box::new(error))))?
    }

    async fn sync_gitops_locked(
        &self,
        request: SyncRequest,
        files: Option<String>,
    ) -> Result<ProviderSync::Model, SyncError> {
        let (outcome, admitted) =
            sync_locked(&self.db, &*self.secret_backends, request, files).await?;
        // The deletes are committed, so the sessions are closed even if the
        // history write fails
        let closed = self.close_admitted_sessions(admitted).await;
        let row = outcome.record(&self.db).await?;
        closed?;
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
                .sync_gitops_locked(SyncRequest::Webhook, None)
                .await
            {
                warn!("GitOps sync: {error}");
            }
        });
    }

    /// Syncs when this node starts, if `gitops_sync_on_startup` is on. After
    /// that, the live node with the lowest id syncs every
    /// `gitops_sync_interval_seconds`, which keeps a cluster to one fetch per
    /// interval. A source configured later waits for the interval or a sync
    /// request.
    // ponytail: a node that dies mid-interval delays the next sync by up to
    // the node timeout; a DB lease would hand over sooner
    pub fn start_gitops_sync(&self) {
        let services = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(SCHEDULE_TICK);
            // `None` until the first successful schedule read. The startup
            // sync is due at that read.
            let mut last = None;
            loop {
                tick.tick().await;
                let request = match services.scheduled_sync(last).await {
                    Ok(request) => request,
                    Err(error) => {
                        warn!("Could not check the GitOps sync schedule: {error}");
                        continue;
                    }
                };
                // The interval starts at startup even if the startup sync is off
                if request.is_some() || last.is_none() {
                    last = Some(Instant::now());
                }
                let Some(request) = request else {
                    continue;
                };
                if let Err(error) = services.sync_gitops(request, None).await {
                    warn!("GitOps sync: {error}");
                }
            }
        });
    }

    async fn scheduled_sync(
        &self,
        last: Option<Instant>,
    ) -> Result<Option<SyncRequest>, WarpgateError> {
        let parameters = Parameters::Entity::get(&self.db).await?;
        if parameters.gitops_source.is_none() {
            return Ok(None);
        }
        let interval = parameters
            .gitops_sync_interval_seconds
            .and_then(i64_seconds_to_duration);
        let request = due(last, parameters.gitops_sync_on_startup, interval);
        // Only the interval sync is limited to the lowest node id. A startup
        // sync can't use that election: ids are random per start, and a
        // killed node stays listed until its heartbeat times out.
        if !matches!(request, Some(SyncRequest::Interval)) {
            return Ok(request);
        }
        let lowest = alive_nodes(&self.db)
            .await?
            .into_iter()
            .map(|node| node.id)
            .min();
        Ok(lowest
            .is_none_or(|id| id == self.cluster.node_id)
            .then_some(SyncRequest::Interval))
    }
}

/// The sync that is due on a node whose interval began at `last`. `last` is
/// `None` on a node that has just started.
fn due(last: Option<Instant>, on_startup: bool, interval: Option<Duration>) -> Option<SyncRequest> {
    match (last, interval) {
        (None, _) => on_startup.then_some(SyncRequest::Startup),
        (Some(last), Some(interval)) if last.elapsed() >= interval => Some(SyncRequest::Interval),
        _ => None,
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use std::fs;

    use sea_orm::PaginatorTrait;
    use warpgate_common::{Secret, SecretError, SecretRef};
    use warpgate_db_entities::Parameters::GitopsDirectorySource;
    use warpgate_db_entities::ProviderSync::PlanAction;
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

    /// Syncs and records, as [`Services::sync_gitops`] does
    async fn sync(
        db: &DatabaseConnection,
        request: SyncRequest,
        files: Option<String>,
    ) -> Result<ProviderSync::Model, SyncError> {
        let (outcome, _) = sync_locked(db, &NoSecrets, request, files).await?;
        outcome.record(db).await
    }

    async fn run(db: &DatabaseConnection) -> ProviderSync::Model {
        sync(db, SyncRequest::Interval, None).await.unwrap()
    }

    async fn rows(db: &DatabaseConnection) -> u64 {
        ProviderSync::Entity::find().count(db).await.unwrap()
    }

    #[tokio::test]
    async fn records_applied_runs_and_extends_unchanged_ones() {
        let db = db().await;
        assert!(matches!(
            sync(&db, SyncRequest::Interval, None).await,
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

        let admin = SyncRequest::Admin {
            user_id: UserId(Uuid::nil()),
            force_prune: false,
        };
        let manual = sync(&db, admin, None).await.unwrap();
        assert_ne!(manual.id, applied.id, "another trigger gets its own row");
        assert_eq!(manual.status, SyncStatus::Unchanged);
        assert_eq!(rows(&db).await, 2);
        let again = sync(&db, admin, None).await.unwrap();
        assert_eq!(again.id, manual.id);

        fs::write(dir.path().join("roles.yaml"), "kind: Nope\n").unwrap();
        let failed = run(&db).await;
        assert_eq!(failed.status, SyncStatus::Failed);
        assert!(failed.error.as_deref().unwrap().contains("roles.yaml"));
        let again = run(&db).await;
        assert_eq!(again.id, failed.id, "the same failure extends its row");
        assert_eq!(rows(&db).await, 3);
    }

    #[tokio::test]
    async fn a_dry_run_plans_and_writes_nothing() {
        let db = db().await;
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("roles.yaml"), ROLES).unwrap();
        configure(&db, dir.path(), false).await;

        let dry = dry_run(&db, &NoSecrets, SyncRequest::Interval, None)
            .await
            .unwrap();
        assert!(dry.error.is_none());
        assert!(dry.pending);
        let actions: Vec<_> = dry.plan.unwrap().0.iter().map(|c| c.action).collect();
        assert_eq!(actions, [PlanAction::Create, PlanAction::Create]);
        assert_eq!(Role::Entity::find().count(&db).await.unwrap(), 0);
        assert_eq!(rows(&db).await, 0);

        run(&db).await;
        let dry = dry_run(&db, &NoSecrets, SyncRequest::Interval, None)
            .await
            .unwrap();
        assert_eq!(
            (dry.plan.unwrap().0.len(), dry.unchanged, dry.pending),
            (0, 2, false)
        );
    }

    #[tokio::test]
    async fn syncs_files_from_the_request_without_a_source() {
        let db = db().await;
        let dry = dry_run(&db, &NoSecrets, SyncRequest::Interval, Some(ROLES.into()))
            .await
            .unwrap();
        assert_eq!(dry.source, "request");
        assert_eq!(dry.plan.unwrap().0.len(), 2);

        let row = sync(&db, SyncRequest::Interval, Some(ROLES.into()))
            .await
            .unwrap();
        assert_eq!(
            (row.status, row.source.as_str()),
            (SyncStatus::Applied, "request")
        );
        assert_eq!(Role::Entity::find().count(&db).await.unwrap(), 2);

        let dir = tempfile::tempdir().unwrap();
        configure(&db, dir.path(), true).await;
        assert!(matches!(
            sync(&db, SyncRequest::Interval, Some(ROLES.into())).await,
            Err(SyncError::SourceConfigured)
        ));
        let dry = dry_run(&db, &NoSecrets, SyncRequest::Interval, Some(ROLES.into()))
            .await
            .unwrap();
        assert_eq!(dry.source, "request", "a dry run writes nothing");
    }

    #[test]
    fn a_node_syncs_when_it_starts_and_then_by_the_interval() {
        let minute = Some(Duration::from_secs(60));
        assert!(matches!(due(None, true, None), Some(SyncRequest::Startup)));
        assert!(due(None, false, minute).is_none());

        let now = Instant::now();
        assert!(due(Some(now), true, minute).is_none());
        assert!(
            due(Some(now), true, Some(Duration::ZERO))
                .is_some_and(|request| matches!(request, SyncRequest::Interval))
        );
        assert!(due(Some(now), true, None).is_none());
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
        let force = SyncRequest::Admin {
            user_id: UserId(Uuid::nil()),
            force_prune: true,
        };
        let forced = sync(&db, force, None).await.unwrap();
        assert_eq!(
            forced.status,
            SyncStatus::Unchanged,
            "forcing doesn't turn pruning on"
        );
        assert_eq!(Role::Entity::find().count(&db).await.unwrap(), 3);

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

        let refused = blocked.plan.unwrap();
        assert_eq!(refused.stats().guarded, 2);
        assert!(refused.needs_force());

        let forced = sync(&db, force, None).await.unwrap();
        assert_eq!(forced.status, SyncStatus::Applied);
        assert_eq!(Role::Entity::find().count(&db).await.unwrap(), 1);
    }
}

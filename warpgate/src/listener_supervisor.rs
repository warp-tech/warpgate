use std::collections::HashSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use futures::future::BoxFuture;
use futures::{Stream, StreamExt};
use notify::{RecommendedWatcher, RecursiveMode, Watcher, recommended_watcher};
use tokio::sync::mpsc;
use tokio::task::{JoinError, JoinHandle};
use tracing::{error, info, warn};
use warpgate_common::{ListenEndpoint, WarpgateError};
use warpgate_core::{ListenerState, ListenerStatus, ListenerStatusRegistry, TlsCertificateInfo};
use warpgate_tls::{TlsCertificateAndPrivateKey, TlsCertificateBundle, TlsPrivateKey};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TlsPathPair {
    pub certificate: PathBuf,
    pub key: PathBuf,
}

impl TlsPathPair {
    pub fn new(base: &Path, certificate: &str, key: &str) -> Option<Self> {
        if certificate.is_empty() || key.is_empty() {
            return None;
        }
        Some(Self {
            certificate: base.join(certificate),
            key: base.join(key),
        })
    }
}

/// The desired state of a single protocol listener, derived from the current
/// config. When any field changes, the listener is restarted.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ListenerParams {
    pub enabled: bool,
    pub endpoint: ListenEndpoint,
    pub proxy_protocol: bool,
    /// TLS pairs the listener serves (main + SNI). Empty for non-TLS protocols.
    pub tls: Vec<TlsPathPair>,
}

/// Builds the protocol server on the given endpoint, handed the pre-loaded and
/// validated TLS material (empty for non-TLS protocols). Called afresh on every
/// (re)start. Two phases: the outer future *binds* the socket — an error here is
/// non-fatal (the supervisor pauses until the next config/cert change) — and the
/// inner future *drives the accept loop* — an error there restarts the listener.
pub type ServerFactory = Arc<
    dyn Fn(
            ListenEndpoint,
            bool,
            Vec<TlsCertificateAndPrivateKey>,
        ) -> BoxFuture<'static, Result<BoxFuture<'static, Result<()>>>>
        + Send
        + Sync,
>;

/// Extracts a listener's desired state from the current config value.
pub type ConfigSelector<C> = Arc<dyn Fn(&C) -> ListenerParams + Send + Sync>;

/// Supervises one protocol listener, keeping it in sync with the live config:
///
/// * restarts it when its endpoint / enabled flag / TLS paths change;
/// * restarts it when a watched TLS cert/key file changes on disk — but only
///   after the new material loads and the key matches the certificate;
/// * if the listener fails (e.g. the port is taken), pauses it and keeps the
///   rest of the process running, retrying on the next config or cert change.
pub struct ListenerSupervisor<C> {
    name: &'static str,
    factory: ServerFactory,
    selector: ConfigSelector<C>,
    status_registry: ListenerStatusRegistry,
}

impl<C: Send + 'static> ListenerSupervisor<C> {
    pub fn new(
        name: &'static str,
        factory: ServerFactory,
        selector: ConfigSelector<C>,
        status_registry: ListenerStatusRegistry,
    ) -> Self {
        Self {
            name,
            factory,
            selector,
            status_registry,
        }
    }

    async fn report_status(
        &self,
        state: ListenerState,
        endpoint: &ListenEndpoint,
        error: Option<String>,
        certificates: Vec<TlsCertificateInfo>,
    ) {
        self.status_registry.lock().await.insert(
            self.name.to_string(),
            ListenerStatus {
                name: self.name.to_string(),
                state,
                address: endpoint.address().to_string(),
                error,
                certificates,
            },
        );
    }

    /// Drive the listener off a stream of config values. Runs until the stream
    /// ends (i.e. for the process lifetime in production).
    pub async fn run(self, mut config_stream: impl Stream<Item = C> + Unpin) {
        let (watcher_tx, mut watcher_rx) = mpsc::channel::<notify::Result<notify::Event>>(16);
        let mut watcher = match recommended_watcher(move |res| {
            let _ = watcher_tx.blocking_send(res);
        }) {
            Ok(watcher) => Some(watcher),
            Err(error) => {
                error!(name = self.name, %error, "Failed to create a certificate file watcher; certificate changes will not be picked up automatically");
                None
            }
        };

        let mut task: Option<JoinHandle<Result<()>>> = None;
        let mut applied: Option<ListenerParams> = None;
        let mut desired: Option<ListenerParams> = None;
        let mut watched_dirs: HashSet<PathBuf> = HashSet::new();

        loop {
            tokio::select! {
                maybe_config = config_stream.next() => {
                    let Some(config) = maybe_config else {
                        break;
                    };
                    let new_desired = (self.selector)(&config);
                    self.update_watches(&new_desired, watcher.as_mut(), &mut watched_dirs);
                    self.maybe_restart_with_new_params(&new_desired, &mut task, &mut applied).await;
                    desired = Some(new_desired);
                }
                Some(event) = watcher_rx.recv() => {
                    let Some(new_desired) = desired.clone() else {
                        continue;
                    };
                    if Self::event_touches(&event, &new_desired) {
                        info!(name = self.name, "Certificate or key file changed on disk");
                        self.restart_with_new_params(&new_desired, &mut task, &mut applied).await;
                    }
                }
                result = wait_task(&mut task), if task.is_some() => {
                    task = None;
                    match result {
                        Ok(Ok(())) => warn!(name = self.name, "Accept loop stopped; restarting listener"),
                        Ok(Err(error)) => error!(name = self.name, %error, "Accept loop failed; restarting listener"),
                        Err(join_error) if join_error.is_panic() => error!(name = self.name, %join_error, "Accept loop panicked; restarting listener"),
                        Err(_) => {}
                    }
                    // The socket had bound successfully, so this is a transient
                    // accept-loop failure: restart. Back off briefly to avoid a
                    // tight crash loop; a *bind* failure during the restart then
                    // pauses until the next config change (handled in restart).
                    // ponytail: fixed 1s backoff, not exponential — rare event.
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    if let Some(params) = applied.clone() {
                        self.restart_with_new_params(&params, &mut task, &mut applied).await;
                    }
                }
            }
        }
    }

    /// Start, stop, or restart the listener to match `desired`. `force` bypasses
    /// the "params unchanged" check — used for cert file changes, where the paths
    /// are the same but the file contents are not.
    async fn maybe_restart_with_new_params(
        &self,
        desired: &ListenerParams,
        task: &mut Option<JoinHandle<Result<()>>>,
        applied: &mut Option<ListenerParams>,
    ) {
        let unchanged = applied.as_ref() == Some(desired);
        // A stopped/paused listener (task is None) always needs a (re)start attempt.
        if unchanged && task.is_some() {
            return;
        }
        self.restart_with_new_params(desired, task, applied).await;
    }

    async fn restart_with_new_params(
        &self,
        desired: &ListenerParams,
        task: &mut Option<JoinHandle<Result<()>>>,
        applied: &mut Option<ListenerParams>,
    ) {
        if !desired.enabled {
            if let Some(handle) = task.take() {
                abort_and_wait(handle).await;
                info!(name = self.name, "Listener disabled by config");
            }
            *applied = Some(desired.clone());
            self.report_status(ListenerState::Disabled, &desired.endpoint, None, Vec::new())
                .await;
            return;
        }

        // Only swap in the new TLS material once it loads and the key matches the
        // certificate — an operator may replace cert and key one file at a time.
        // The loaded material is handed to the server so it serves exactly what
        // was validated (no re-read, no room for a mismatch to slip in).
        let tls = if desired.tls.is_empty() {
            Vec::new()
        } else {
            match validate_tls(&desired.tls).await {
                Ok(loaded) => loaded,
                Err(error) => {
                    error!(name = self.name, %error, "New TLS certificate/key is invalid; keeping the current listener");
                    // The current listener keeps serving its previously-reported status.
                    return;
                }
            }
        };

        if let Some(handle) = task.take() {
            abort_and_wait(handle).await;
        }
        *applied = Some(desired.clone());

        let certificates: Vec<TlsCertificateInfo> = tls
            .iter()
            .map(|pair| TlsCertificateInfo {
                domains: pair.certificate.sni_names().unwrap_or_default(),
                expiry: pair.certificate.not_after(),
            })
            .collect();

        info!(name = self.name, endpoint = ?desired.endpoint, "Binding listener");
        // Phase 1: bind. A bind failure is non-fatal — leave the listener stopped
        // (`task` = None) so it retries on the next config or certificate change.
        match (self.factory)(desired.endpoint.clone(), desired.proxy_protocol, tls).await {
            // Phase 2: drive the accept loop in its own task. If it ends, the task
            // branch of `run` restarts the listener.
            Ok(accept_loop) => {
                *task = Some(tokio::spawn(accept_loop));
                self.report_status(
                    ListenerState::Listening,
                    &desired.endpoint,
                    None,
                    certificates,
                )
                .await;
            }
            Err(error) => {
                error!(name = self.name, %error, "Listener failed to bind; paused until the next config or certificate change");
                self.report_status(
                    ListenerState::BindFailed,
                    &desired.endpoint,
                    Some(error.to_string()),
                    certificates,
                )
                .await;
            }
        }
    }

    /// Watch the parent directories of the desired cert/key files (robust to
    /// atomic write-rename rotation), adding/removing watches as paths change.
    fn update_watches(
        &self,
        desired: &ListenerParams,
        watcher: Option<&mut RecommendedWatcher>,
        watched_dirs: &mut HashSet<PathBuf>,
    ) {
        let Some(watcher) = watcher else {
            return;
        };

        let mut wanted = HashSet::new();
        for pair in &desired.tls {
            if let Some(dir) = pair.certificate.parent() {
                wanted.insert(dir.to_path_buf());
            }
            if let Some(dir) = pair.key.parent() {
                wanted.insert(dir.to_path_buf());
            }
        }

        for dir in watched_dirs.iter() {
            if !wanted.contains(dir) {
                let _ = watcher.unwatch(dir);
            }
        }
        for dir in &wanted {
            if !watched_dirs.contains(dir)
                && let Err(error) = watcher.watch(dir, RecursiveMode::NonRecursive)
            {
                warn!(name = self.name, ?dir, %error, "Failed to watch certificate directory");
            }
        }

        *watched_dirs = wanted;
    }

    /// Whether a filesystem event affects one of the listener's cert/key files.
    /// Matched by file name to be robust across absolute/relative/symlinked paths
    /// (we only watch the specific parent directories of those files).
    fn event_touches(event: &notify::Result<notify::Event>, desired: &ListenerParams) -> bool {
        let Ok(event) = event else {
            return false;
        };
        if !(event.kind.is_modify() || event.kind.is_create() || event.kind.is_remove()) {
            return false;
        }
        let names: HashSet<&OsStr> = desired
            .tls
            .iter()
            .flat_map(|pair| [pair.certificate.file_name(), pair.key.file_name()])
            .flatten()
            .collect();
        event
            .paths
            .iter()
            .any(|path| path.file_name().is_some_and(|name| names.contains(name)))
    }
}

/// Abort the accept-loop task and wait for it to actually stop before returning,
/// so its listen socket is closed before we rebind the same port — otherwise the
/// new bind races the old socket's close and can hit `EADDRINUSE`, pausing the
/// listener until the next change. Closing a listening socket frees the port
/// immediately (no `TIME_WAIT`), so `SO_REUSEADDR` isn't needed here.
///
/// This only stops *accepting*: in-flight sessions/connections are spawned as
/// independent tasks (SSH/MySQL/Postgres session tasks; poem detaches each
/// connection and doesn't cancel them on server drop), so they finish in the
/// background rather than being killed on an endpoint or certificate change.
async fn abort_and_wait(handle: JoinHandle<Result<()>>) {
    handle.abort();
    let _ = handle.await;
}

/// Await the running listener task, or never resolve if there is none. The
/// select branch is guarded by `task.is_some()`, so the pending arm is only a
/// type-level placeholder and is never actually awaited.
async fn wait_task(task: &mut Option<JoinHandle<Result<()>>>) -> Result<Result<()>, JoinError> {
    match task.as_mut() {
        Some(handle) => handle.await,
        None => std::future::pending().await,
    }
}

/// Load every cert/key pair and verify each key matches its certificate,
/// returning the loaded material in the same order as `pairs`. On failure the
/// returned [`TlsState`] classifies whether the material could not be loaded or
/// loaded but did not match.
pub async fn validate_tls(
    pairs: &[TlsPathPair],
) -> Result<Vec<TlsCertificateAndPrivateKey>, WarpgateError> {
    let mut loaded = Vec::with_capacity(pairs.len());
    for pair in pairs {
        // Keep the typed `WarpgateError::TlsSetup(RustlsSetupError::…)` (via `?`'s
        // `#[from]`) so callers can distinguish a load failure from a cert/key
        // mismatch — don't route through anyhow context, which would erase it.
        let certificate = TlsCertificateBundle::from_file(&pair.certificate).await?;
        let private_key = TlsPrivateKey::from_file(&pair.key).await?;
        let pair_material = TlsCertificateAndPrivateKey {
            certificate,
            private_key,
        };
        pair_material.verify_key_matches_certificate()?;
        loaded.push(pair_material);
    }
    Ok(loaded)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use futures::FutureExt;
    use tempfile::tempdir;
    use tokio::sync::mpsc::unbounded_channel;
    use tokio::sync::watch;
    use tokio::time::timeout;
    use tokio_stream::wrappers::WatchStream;

    use super::*;

    fn endpoint(port: u16) -> ListenEndpoint {
        ListenEndpoint::from(SocketAddr::from(([127, 0, 0, 1], port)))
    }

    fn params(port: u16, enabled: bool) -> ListenerParams {
        ListenerParams {
            enabled,
            endpoint: endpoint(port),
            proxy_protocol: false,
            tls: vec![],
        }
    }

    fn registry() -> ListenerStatusRegistry {
        Default::default()
    }

    /// Factory that reports each start (endpoint) on a channel and either fails
    /// immediately or runs forever, controlled by a shared flag.
    fn counting_factory(
        starts: tokio::sync::mpsc::UnboundedSender<ListenEndpoint>,
        fail: Arc<AtomicBool>,
    ) -> ServerFactory {
        Arc::new(move |endpoint: ListenEndpoint, _proxy_protocol, _tls| {
            let _ = starts.send(endpoint);
            let fail = fail.clone();
            async move {
                if fail.load(Ordering::SeqCst) {
                    anyhow::bail!("simulated bind failure");
                }
                // Bind ok; the accept loop pends forever (listener stays up).
                Ok(async move {
                    std::future::pending::<()>().await;
                    Ok(())
                }
                .boxed())
            }
            .boxed()
        })
    }

    async fn next_start(
        starts: &mut tokio::sync::mpsc::UnboundedReceiver<ListenEndpoint>,
    ) -> ListenEndpoint {
        timeout(Duration::from_secs(5), starts.recv())
            .await
            .expect("timed out waiting for a listener start")
            .expect("start channel closed")
    }

    async fn expect_no_start(starts: &mut tokio::sync::mpsc::UnboundedReceiver<ListenEndpoint>) {
        assert!(
            timeout(Duration::from_millis(300), starts.recv())
                .await
                .is_err(),
            "unexpected listener (re)start"
        );
    }

    #[tokio::test]
    async fn starts_restarts_and_stops_on_config_changes() {
        let (starts_tx, mut starts_rx) = unbounded_channel();
        let fail = Arc::new(AtomicBool::new(false));
        let factory = counting_factory(starts_tx, fail);
        let selector: ConfigSelector<ListenerParams> = Arc::new(|p: &ListenerParams| p.clone());

        let (cfg_tx, cfg_rx) = watch::channel(params(2201, true));
        let supervisor = ListenerSupervisor::new("test", factory, selector, registry());
        let handle = tokio::spawn(supervisor.run(WatchStream::new(cfg_rx)));

        // Initial config → starts on port 2201.
        assert_eq!(next_start(&mut starts_rx).await.port(), 2201);

        // Unrelated no-op resend (same value) → no restart.
        cfg_tx.send(params(2201, true)).unwrap();
        expect_no_start(&mut starts_rx).await;

        // Endpoint change → restart on the new port.
        cfg_tx.send(params(2202, true)).unwrap();
        assert_eq!(next_start(&mut starts_rx).await.port(), 2202);

        // Disable → stop, no new start.
        cfg_tx.send(params(2202, false)).unwrap();
        expect_no_start(&mut starts_rx).await;

        // Re-enable → start again.
        cfg_tx.send(params(2202, true)).unwrap();
        assert_eq!(next_start(&mut starts_rx).await.port(), 2202);

        handle.abort();
    }

    #[tokio::test]
    async fn pauses_on_failure_and_retries_on_next_change() {
        let (starts_tx, mut starts_rx) = unbounded_channel();
        let fail = Arc::new(AtomicBool::new(true));
        let factory = counting_factory(starts_tx, fail.clone());
        let selector: ConfigSelector<ListenerParams> = Arc::new(|p: &ListenerParams| p.clone());

        let (cfg_tx, cfg_rx) = watch::channel(params(2301, true));
        let supervisor = ListenerSupervisor::new("test", factory, selector, registry());
        let handle = tokio::spawn(supervisor.run(WatchStream::new(cfg_rx)));

        // First attempt starts but the factory fails → listener pauses.
        assert_eq!(next_start(&mut starts_rx).await.port(), 2301);

        // A later change (even to a different port) retries.
        fail.store(false, Ordering::SeqCst);
        cfg_tx.send(params(2302, true)).unwrap();
        assert_eq!(next_start(&mut starts_rx).await.port(), 2302);

        handle.abort();
    }

    // Uses the real 1s restart backoff; well within `next_start`'s 5s timeout.
    #[tokio::test]
    async fn restarts_on_accept_loop_failure() {
        use std::sync::atomic::AtomicUsize;

        let (starts_tx, mut starts_rx) = unbounded_channel();
        // Bind always succeeds; the first accept loop dies immediately, the rest pend.
        let accept_calls = Arc::new(AtomicUsize::new(0));
        let factory: ServerFactory = {
            let starts = starts_tx.clone();
            let accept_calls = accept_calls.clone();
            Arc::new(move |endpoint: ListenEndpoint, _proxy_protocol, _tls| {
                let _ = starts.send(endpoint);
                let accept_calls = accept_calls.clone();
                async move {
                    Ok(async move {
                        if accept_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                            anyhow::bail!("accept loop died");
                        }
                        std::future::pending::<()>().await;
                        Ok(())
                    }
                    .boxed())
                }
                .boxed()
            })
        };
        let selector: ConfigSelector<ListenerParams> = Arc::new(|p: &ListenerParams| p.clone());

        let (_cfg_tx, cfg_rx) = watch::channel(params(2401, true));
        let supervisor = ListenerSupervisor::new("test", factory, selector, registry());
        let handle = tokio::spawn(supervisor.run(WatchStream::new(cfg_rx)));

        // Initial bind, then the accept loop dies and the listener auto-restarts
        // (no config change) after the backoff — a second bind on the same port.
        assert_eq!(next_start(&mut starts_rx).await.port(), 2401);
        assert_eq!(next_start(&mut starts_rx).await.port(), 2401);

        handle.abort();
    }

    #[tokio::test]
    async fn reloads_only_matching_cert_key_pairs() {
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("tls.crt");
        let key_path = dir.path().join("tls.key");

        // Write a matching self-signed pair.
        let a = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        std::fs::write(&cert_path, a.cert.pem()).unwrap();
        std::fs::write(&key_path, a.signing_key.serialize_pem()).unwrap();

        let tls = vec![TlsPathPair {
            certificate: cert_path.clone(),
            key: key_path.clone(),
        }];

        // A matching pair validates.
        validate_tls(&tls).await.unwrap();

        // Replacing only the certificate (with a different key's cert) must not
        // validate — this is the one-file-at-a-time replacement window.
        let b = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        std::fs::write(&cert_path, b.cert.pem()).unwrap();
        let err = validate_tls(&tls).await.unwrap_err();
        assert!(
            matches!(
                err,
                WarpgateError::TlsSetup(
                    warpgate_tls::RustlsSetupError::MismatchedCertificateAndKey
                ),
            ),
            "wrong error"
        );

        // Once the matching key lands, it validates again.
        std::fs::write(&key_path, b.signing_key.serialize_pem()).unwrap();
        validate_tls(&tls).await.unwrap();
    }

    #[test]
    fn event_touches_matches_cert_and_key_by_name() {
        let desired = ListenerParams {
            enabled: true,
            endpoint: endpoint(8443),
            proxy_protocol: false,
            tls: vec![TlsPathPair {
                certificate: "/etc/warpgate/tls.crt".into(),
                key: "/etc/warpgate/tls.key".into(),
            }],
        };

        let hit = notify::Event::new(notify::EventKind::Modify(notify::event::ModifyKind::Any))
            .add_path("/some/other/dir/tls.key".into());
        assert!(ListenerSupervisor::<ListenerParams>::event_touches(
            &Ok(hit),
            &desired
        ));

        let miss = notify::Event::new(notify::EventKind::Modify(notify::event::ModifyKind::Any))
            .add_path("/etc/warpgate/unrelated.pem".into());
        assert!(!ListenerSupervisor::<ListenerParams>::event_touches(
            &Ok(miss),
            &desired
        ));
    }
}

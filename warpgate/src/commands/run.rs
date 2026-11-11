use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use futures::FutureExt;
use futures::stream::{FuturesUnordered, StreamExt};
#[cfg(target_os = "linux")]
use sd_notify::NotifyState;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::WatchStream;
use tracing::{debug, error, info, warn};
use warpgate_common::encryption::validate_encryption_config;
use warpgate_common::version::warpgate_version;
use warpgate_common::{GlobalParams, WarpgateConfig};
use warpgate_core::db::cleanup_db;
use warpgate_core::logging::install_database_logger;
use warpgate_core::{ListenerStatusRegistry, ProtocolServer, Services};
use warpgate_protocol_http::HTTPProtocolServer;
use warpgate_protocol_kubernetes::KubernetesProtocolServer;
use warpgate_protocol_mysql::MySQLProtocolServer;
use warpgate_protocol_postgres::PostgresProtocolServer;
use warpgate_protocol_rdp::RdpProtocolServer;
use warpgate_protocol_ssh::SSHProtocolServer;
use warpgate_protocol_vnc::VncProtocolServer;

use crate::config::{load_config, watch_config};
use crate::listener_supervisor::{
    ConfigSelector, ListenerParams, ListenerSupervisor, ServerFactory, TlsPathPair, validate_tls,
};

/// Endpoint failures at startup are fatal (only runtime changes are non-fatal),
/// so probe the initial config's TLS material and port before spawning the
/// supervisor, which then owns rebinding for the process lifetime.
async fn spawn_supervisor(
    name: &'static str,
    requires_tls: bool,
    factory: ServerFactory,
    selector: ConfigSelector<WarpgateConfig>,
    config_rx: &watch::Receiver<WarpgateConfig>,
    status_registry: ListenerStatusRegistry,
) -> Result<JoinHandle<()>> {
    let params = selector(&config_rx.borrow());
    if params.enabled {
        if requires_tls && params.tls.is_empty() {
            anyhow::bail!("{name} listener: no TLS certificate/key configured");
        }
        validate_tls(&params.tls)
            .await
            .with_context(|| format!("{name} listener: TLS setup failed"))?;
        params.endpoint.probe().with_context(|| {
            format!("{name} listener: cannot bind {}", params.endpoint.address())
        })?;
    }
    let stream = WatchStream::new(config_rx.clone());
    Ok(tokio::spawn(
        ListenerSupervisor::new(name, factory, selector, status_registry).run(stream),
    ))
}

pub async fn command(params: &GlobalParams, enable_admin_token: bool) -> Result<()> {
    let version = warpgate_version();
    info!(%version, "Warpgate");

    let admin_token = enable_admin_token.then(|| {
        std::env::var("WARPGATE_ADMIN_TOKEN").unwrap_or_else(|_| {
            error!("`WARPGATE_ADMIN_TOKEN` env variable must set when using --enable-admin-token");
            std::process::exit(1);
        })
    });

    let config = match load_config(params, true) {
        Ok(config) => config,
        Err(error) => {
            error!(?error, "Failed to load config file");
            std::process::exit(1);
        }
    };

    let services = Services::new(config.clone(), admin_token, params.clone()).await?;

    validate_encryption_config(&config);

    // Join the cluster before the credential backfill below
    services.start_cluster().await?;

    install_database_logger(services.db.clone());

    // Runs even when the SSH listener is disabled so that the admin UI can
    // manage the keys and other protocols' features relying on them work.
    let keys_path = config.store.ssh.keys_path(params);
    warpgate_protocol_ssh::ensure_host_keys(&services.db, &keys_path).await?;
    warpgate_protocol_ssh::ensure_client_keys(&services.db, &keys_path).await?;

    // Encrypt before listeners start
    if warpgate_core::backfill_credential_encryption(&services.db).await?
        == warpgate_core::BackfillOutcome::AwaitingCluster
    {
        let db = services.db.clone();
        tokio::spawn(async move {
            loop {
                match warpgate_core::backfill_credential_encryption(&db).await {
                    Ok(warpgate_core::BackfillOutcome::Settled) => break,
                    Ok(warpgate_core::BackfillOutcome::AwaitingCluster) => {}
                    Err(error) => warn!(%error, "Deferred credential encryption failed"),
                }
                tokio::time::sleep(Duration::from_secs(rand::random_range(3..7))).await;
            }
        });
    }

    if console::user_attended() {
        info!("--------------------------------------------");
        info!("Warpgate is now running.");
    }

    drop(config);

    // The config file is watched and pushed onto this channel; each protocol
    // supervisor and the session-reauth loop react to changes off a clone of it.
    let config_rx = watch_config(params, services.config.clone()).await?;

    let base = params.paths_relative_to().clone();

    // One supervisor per protocol keeps its listener in sync with the live config,
    // rebinding on endpoint/enable/certificate changes and pausing (rather than
    // killing the process) if a bind fails.
    let mut supervisors: FuturesUnordered<JoinHandle<()>> = FuturesUnordered::new();

    // HTTP has no `enable` flag — it is always on.
    {
        let status_registry = services.listener_status.clone();
        let services = services.clone();
        let factory: ServerFactory = Arc::new(move |address, proxy_protocol, tls| {
            let services = services.clone();
            async move {
                HTTPProtocolServer::new(&services)
                    .bind(address, proxy_protocol, tls)
                    .await
            }
            .boxed()
        });
        let base = base.clone();
        let selector: ConfigSelector<WarpgateConfig> = Arc::new(move |c: &WarpgateConfig| {
            let mut tls = Vec::new();
            if let Some(pair) =
                TlsPathPair::new(&base, &c.store.http.certificate, &c.store.http.key)
            {
                tls.push(pair);
            }
            for sni in &c.store.http.sni_certificates {
                if let Some(pair) = TlsPathPair::new(&base, &sni.certificate, &sni.key) {
                    tls.push(pair);
                }
            }
            ListenerParams {
                enabled: true,
                endpoint: c.store.http.listen.clone(),
                proxy_protocol: c.store.http.proxy_protocol,
                tls,
            }
        });
        supervisors.push(
            spawn_supervisor("HTTP", true, factory, selector, &config_rx, status_registry).await?,
        );
    }

    {
        let status_registry = services.listener_status.clone();
        let services = services.clone();
        let factory: ServerFactory = Arc::new(move |address, proxy_protocol, tls| {
            let services = services.clone();
            async move {
                let server = SSHProtocolServer::new(&services).await?;
                server.bind(address, proxy_protocol, tls).await
            }
            .boxed()
        });
        let selector: ConfigSelector<WarpgateConfig> =
            Arc::new(|c: &WarpgateConfig| ListenerParams {
                enabled: c.store.ssh.enable,
                endpoint: c.store.ssh.listen.clone(),
                proxy_protocol: c.store.ssh.proxy_protocol,
                tls: Vec::new(),
            });
        supervisors.push(
            spawn_supervisor("SSH", false, factory, selector, &config_rx, status_registry).await?,
        );
    }

    // These protocols are uniform: sync `new`, one enable flag, one cert/key pair.
    // `$cfg` is the `store` field holding their config (all share the shape).
    macro_rules! tls_listener {
        ($name:literal, $server:ident, $cfg:ident) => {{
            let status_registry = services.listener_status.clone();
            let services = services.clone();
            let base = base.clone();
            let factory: ServerFactory = Arc::new(move |address, proxy_protocol, tls| {
                let services = services.clone();
                async move {
                    $server::new(&services)
                        .bind(address, proxy_protocol, tls)
                        .await
                }
                .boxed()
            });
            let selector: ConfigSelector<WarpgateConfig> =
                Arc::new(move |c: &WarpgateConfig| ListenerParams {
                    enabled: c.store.$cfg.enable,
                    endpoint: c.store.$cfg.listen.clone(),
                    proxy_protocol: c.store.$cfg.proxy_protocol,
                    tls: TlsPathPair::new(&base, &c.store.$cfg.certificate, &c.store.$cfg.key)
                        .into_iter()
                        .collect(),
                });
            spawn_supervisor($name, true, factory, selector, &config_rx, status_registry).await?
        }};
    }

    supervisors.push(tls_listener!("MySQL", MySQLProtocolServer, mysql));
    supervisors.push(tls_listener!(
        "PostgreSQL",
        PostgresProtocolServer,
        postgres
    ));
    supervisors.push(tls_listener!(
        "Kubernetes",
        KubernetesProtocolServer,
        kubernetes
    ));
    supervisors.push(tls_listener!("VNC", VncProtocolServer, vnc));
    supervisors.push(tls_listener!("RDP", RdpProtocolServer, rdp));

    tokio::spawn({
        let services = services.clone();
        async move {
            loop {
                let retention = { services.config.lock().await.store.log.retention };
                let audit_retention = { services.config.lock().await.store.log.audit_retention };
                let interval = std::cmp::min(retention, audit_retention) / 10;
                match cleanup_db(
                    &services.db,
                    &services.recordings,
                    &retention,
                    &audit_retention,
                )
                .await
                {
                    Err(error) => {
                        error!(?error, "Failed to cleanup the database");
                    }
                    _ => {
                        debug!("Database cleaned up, next in {:?}", interval);
                    }
                }
                tokio::time::sleep(interval).await;
            }
        }
    });

    #[cfg(target_os = "linux")]
    if let Ok(true) = sd_notify::booted() {
        use std::time::Duration;
        tokio::spawn(async {
            if let Err(error) = async {
                sd_notify::notify(&[NotifyState::Ready])?;
                loop {
                    sd_notify::notify(&[NotifyState::Watchdog])?;
                    tokio::time::sleep(Duration::from_secs(15)).await;
                }
                #[allow(unreachable_code)]
                Ok::<(), anyhow::Error>(())
            }
            .await
            {
                error!(?error, "Failed to communicate with systemd");
            }
        });
    }

    let mut shutdown = ShutdownSignals::new()?;

    loop {
        tokio::select! {
            () = shutdown.recv() => {
                break
            }
            result = supervisors.next() => {
                match result {
                    Some(Err(error)) => {
                        error!(?error, "Listener supervisor task failed");
                    }
                    None => break,
                    _ => (),
                }
            }
        }
    }

    let cleanup = async {
        services.recordings.shutdown().await;
        if let Err(error) = services.cluster.shutdown().await {
            warn!(%error, "Failed to deregister cluster node");
        }
    };

    tokio::select! {
        () = cleanup => {}
        () = shutdown.recv() => std::process::exit(1),
    }

    info!("Exiting");
    Ok(())
}

/// The OS requests that stop the server: SIGINT/SIGTERM on Unix,
/// Ctrl+C/Ctrl+Break/console close/system shutdown on Windows. Not logoff:
/// a service receives that whenever any user logs off and must keep running.
struct ShutdownSignals {
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
    #[cfg(windows)]
    interrupt: tokio::signal::windows::CtrlC,
    #[cfg(windows)]
    break_key: tokio::signal::windows::CtrlBreak,
    #[cfg(windows)]
    console_close: tokio::signal::windows::CtrlClose,
    #[cfg(windows)]
    system_shutdown: tokio::signal::windows::CtrlShutdown,
}

impl ShutdownSignals {
    fn new() -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            Ok(Self {
                interrupt: signal(SignalKind::interrupt())?,
                terminate: signal(SignalKind::terminate())?,
            })
        }
        #[cfg(windows)]
        {
            use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close, ctrl_shutdown};
            Ok(Self {
                interrupt: ctrl_c()?,
                break_key: ctrl_break()?,
                console_close: ctrl_close()?,
                system_shutdown: ctrl_shutdown()?,
            })
        }
    }

    async fn recv(&mut self) {
        #[cfg(unix)]
        tokio::select! {
            _ = self.interrupt.recv() => {}
            _ = self.terminate.recv() => {}
        }
        #[cfg(windows)]
        tokio::select! {
            _ = self.interrupt.recv() => {}
            _ = self.break_key.recv() => {}
            _ = self.console_close.recv() => {}
            _ = self.system_shutdown.recv() => {}
        }
    }
}

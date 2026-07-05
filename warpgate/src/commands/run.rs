use std::sync::Arc;

use anyhow::{Context, Result};
use futures::FutureExt;
use futures::stream::{FuturesUnordered, StreamExt};
#[cfg(target_os = "linux")]
use sd_notify::NotifyState;
use tokio::signal::unix::SignalKind;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::WatchStream;
use tracing::{debug, error, info, warn};
use warpgate_common::version::warpgate_version;
use warpgate_common::{GlobalParams, WarpgateConfig};
use warpgate_core::db::cleanup_db;
use warpgate_core::logging::install_database_logger;
use warpgate_core::{ConfigProvider, ProtocolServer, Services};
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
) -> Result<JoinHandle<()>> {
    let params = selector(&config_rx.borrow());
    if params.enabled {
        if requires_tls && params.tls.is_empty() {
            anyhow::bail!("{name} listener: no TLS certificate/key configured");
        }
        validate_tls(&params.tls)
            .await
            .with_context(|| format!("{name} listener: TLS setup failed"))?;
        // Fail fast if the port can't be bound; the probe listeners drop here and
        // the supervisor rebinds. ponytail: tiny drop→rebind window, fine at startup.
        params.endpoint.tcp_listeners().await.with_context(|| {
            format!("{name} listener: cannot bind {}", params.endpoint.address())
        })?;
    }
    let stream = WatchStream::new(config_rx.clone());
    Ok(tokio::spawn(
        ListenerSupervisor::new(name, factory, selector).run(stream),
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

    install_database_logger(services.db.clone());

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
        let services = services.clone();
        let factory: ServerFactory = Arc::new(move |address, tls| {
            let services = services.clone();
            async move { HTTPProtocolServer::new(&services).bind(address, tls).await }.boxed()
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
                tls,
            }
        });
        supervisors.push(spawn_supervisor("HTTP", true, factory, selector, &config_rx).await?);
    }

    {
        let services = services.clone();
        let factory: ServerFactory = Arc::new(move |address, tls| {
            let services = services.clone();
            async move {
                let server = SSHProtocolServer::new(&services).await?;
                server.bind(address, tls).await
            }
            .boxed()
        });
        let selector: ConfigSelector<WarpgateConfig> =
            Arc::new(|c: &WarpgateConfig| ListenerParams {
                enabled: c.store.ssh.enable,
                endpoint: c.store.ssh.listen.clone(),
                tls: Vec::new(),
            });
        supervisors.push(spawn_supervisor("SSH", false, factory, selector, &config_rx).await?);
    }

    // These protocols are uniform: sync `new`, one enable flag, one cert/key pair.
    // `$cfg` is the `store` field holding their config (all share the shape).
    macro_rules! tls_listener {
        ($name:literal, $server:ident, $cfg:ident) => {{
            let services = services.clone();
            let base = base.clone();
            let factory: ServerFactory = Arc::new(move |address, tls| {
                let services = services.clone();
                async move { $server::new(&services).bind(address, tls).await }.boxed()
            });
            let selector: ConfigSelector<WarpgateConfig> =
                Arc::new(move |c: &WarpgateConfig| ListenerParams {
                    enabled: c.store.$cfg.enable,
                    endpoint: c.store.$cfg.listen.clone(),
                    tls: TlsPathPair::new(&base, &c.store.$cfg.certificate, &c.store.$cfg.key)
                        .into_iter()
                        .collect(),
                });
            spawn_supervisor($name, true, factory, selector, &config_rx).await?
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
                #[allow(clippy::explicit_auto_deref)]
                match cleanup_db(
                    &*services.db.lock().await,
                    &*services.recordings.lock().await,
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

    tokio::spawn(watch_config_and_reload(services.clone(), config_rx.clone()));

    let mut sigint = tokio::signal::unix::signal(SignalKind::interrupt())?;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                std::process::exit(1);
            }
            _ = sigint.recv() => {
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

    info!("Exiting");
    Ok(())
}

pub async fn watch_config_and_reload(
    services: Services,
    mut config_rx: watch::Receiver<WarpgateConfig>,
) -> Result<()> {
    while config_rx.changed().await.is_ok() {
        let state = services.state.lock().await;
        let mut cp = services.config_provider.lock().await;
        // TODO no longer happens since everything is in the DB
        for (id, session) in &state.sessions {
            let mut session = session.lock().await;
            if let (Some(user_info), Some(target)) =
                (session.user_info.as_ref(), session.target.as_ref())
                && !cp
                    .authorize_target(&user_info.username, &target.name)
                    .await?
            {
                warn!(sesson_id=%id, %user_info.username, target=&target.name, "Session no longer authorized after config reload");
                session.handle.close();
            }
        }
    }

    Ok(())
}

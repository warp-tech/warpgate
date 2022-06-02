use crate::config::{load_config, watch_config};
use anyhow::Result;
use futures::StreamExt;
use std::net::ToSocketAddrs;
use tracing::*;
use warpgate_common::db::cleanup_db;
use warpgate_common::logging::install_database_logger;
use warpgate_common::{ProtocolServer, Services};
use warpgate_protocol_http::HTTPProtocolServer;
use warpgate_protocol_ssh::SSHProtocolServer;

#[cfg(target_os = "linux")]
use sd_notify::NotifyState;

pub(crate) async fn command(cli: &crate::Cli) -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    info!(%version, "Warpgate");

    let config = load_config(&cli.config, true)?;
    let services = Services::new(config.clone()).await?;

    install_database_logger(services.db.clone());

    let mut other_futures = futures::stream::FuturesUnordered::new();
    let mut protocol_futures = futures::stream::FuturesUnordered::new();

    protocol_futures.push(
        SSHProtocolServer::new(&services).await?.run(
            config
                .store
                .ssh
                .listen
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| anyhow::anyhow!("Failed to resolve the listen address"))?,
        ),
    );

    if config.store.http.enable {
        protocol_futures.push(
            HTTPProtocolServer::new(&services).await?.run(
                config
                    .store
                    .http
                    .listen
                    .to_socket_addrs()?
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("Failed to resolve the listen address"))?,
            ),
        );
    }

    if config.store.web_admin.enable {
        let admin = warpgate_admin::AdminServer::new(&services);
        let admin_future = admin.run(
            config
                .store
                .web_admin
                .listen
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| {
                    anyhow::anyhow!("Failed to resolve the listen address for the admin server")
                })?,
        );
        other_futures.push(admin_future);
    }

    tokio::spawn({
        let services = services.clone();
        async move {
            loop {
                let retention = { services.config.lock().await.store.log.retention };
                let interval = retention / 10;
                match cleanup_db(&mut *services.db.lock().await, &retention).await {
                    Err(error) => error!(?error, "Failed to cleanup the database"),
                    Ok(_) => debug!("Database cleaned up, next in {:?}", interval),
                }
                tokio::time::sleep(interval).await;
            }
        }
    });

    if console::user_attended() {
        info!("--------------------------------------------");
        info!("Warpgate is now running.");
        info!("Accepting SSH connections on  {}", config.store.ssh.listen);
        if config.store.http.enable {
            info!("Accepting HTTP connections on {}", config.store.http.listen);
        }
        if config.store.web_admin.enable {
            info!(
                "Access admin UI on https://{}",
                config.store.web_admin.listen
            );
        }
        info!("--------------------------------------------");
    }

    #[cfg(target_os = "linux")]
    if let Ok(true) = sd_notify::booted() {
        use std::time::Duration;
        tokio::spawn(async {
            if let Err(error) = async {
                sd_notify::notify(false, &[NotifyState::Ready])?;
                loop {
                    sd_notify::notify(false, &[NotifyState::Watchdog])?;
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

    drop(config);

    tokio::spawn(watch_config(cli.config.clone(), services.config.clone()));

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                std::process::exit(1);
            }
            result = protocol_futures.next() => {
                match result {
                    Some(Err(error)) => {
                        error!(?error, "SSH server error");
                        std::process::exit(1);
                    },
                    None => break,
                    _ => (),
                }
            }
            result = other_futures.next(), if !other_futures.is_empty() => {
                match result {
                    Some(Err(error)) => {
                        error!(?error, "Error");
                        std::process::exit(1);
                    },
                    None => break,
                    _ => (),
                }
            }
        }
    }

    info!("Exiting");
    Ok(())
}

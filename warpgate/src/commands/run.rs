use crate::config::load_config;
use anyhow::Result;
use futures::StreamExt;
use std::net::ToSocketAddrs;
use tracing::*;
use tracing_subscriber::Layer;
use warpgate_common::{ProtocolServer, Services};
use warpgate_protocol_ssh::SSHProtocolServer;

pub(crate) async fn command(cli: &crate::Cli) -> Result<()> {
    let config = load_config(&cli.config)?;

    let version = env!("CARGO_PKG_VERSION");
    info!(%version, "Warpgate");

    let services = Services::new(config.clone()).await?;

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

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                break
            }
            result = protocol_futures.next() => {
                match result {
                    Some(Err(error)) => {
                        error!(?error, "SSH server error");
                    },
                    None => break,
                    _ => (),
                }
            }
            result = other_futures.next(), if !other_futures.is_empty() => {
                match result {
                    Some(Err(error)) => {
                        error!(?error, "Error");
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

use anyhow::Result;
use tracing::*;
use warpgate_common::{ProtocolServer, Services, Target, TargetTestError};

use crate::config::load_config;

pub(crate) async fn command(cli: &crate::Cli, target_name: &String) -> Result<()> {
    let config = load_config(&cli.config, true)?;

    let Some(target) = config
        .store
        .targets
        .iter()
        .find(|x| &x.name == target_name)
        .map(Target::clone) else {
        error!("Target not found: {}", target_name);
        return Ok(());
    };

    let services = Services::new(config.clone()).await?;

    let s = warpgate_protocol_ssh::SSHProtocolServer::new(&services).await?;
    match s.test_target(target).await {
        Err(TargetTestError::AuthenticationError) => {
            error!("Authentication failed");
        }
        Err(TargetTestError::ConnectionError(error)) => {
            error!(?error, "Connection error");
        }
        Err(TargetTestError::Io(error)) => {
            error!(?error, "I/O error");
        }
        Err(TargetTestError::Misconfigured(error)) => {
            error!(?error, "Misconfigured");
        }
        Err(TargetTestError::Unreachable) => {
            error!("Target is unreachable");
        }
        Ok(()) => {
            info!("Connection successful!");
        }
    }

    Ok(())
}

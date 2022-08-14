use anyhow::Result;
use tracing::*;
use warpgate_common::{ProtocolServer, Services, Target, TargetOptions, TargetTestError};

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

    let s: Box<dyn ProtocolServer> = match target.options {
        TargetOptions::Ssh(_) => {
            Box::new(warpgate_protocol_ssh::SSHProtocolServer::new(&services).await?)
        }
        TargetOptions::Http(_) => {
            Box::new(warpgate_protocol_http::HTTPProtocolServer::new(&services).await?)
        }
        TargetOptions::MySql(_) => {
            Box::new(warpgate_protocol_mysql::MySQLProtocolServer::new(&services).await?)
        }
        TargetOptions::WebAdmin(_) => {
            error!("Unsupported target type");
            return Ok(());
        }
    };

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
            return Ok(());
        }
    }

    anyhow::bail!("Connection test failed")
}

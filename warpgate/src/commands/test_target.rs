use anyhow::Result;
use tracing::*;
use warpgate_common::{GlobalParams, TargetOptions};
use warpgate_core::{ConfigProvider, ProtocolServer, Services, TargetTestError};

use crate::config::load_config;
use crate::protocols::ProtocolServerEnum;

pub(crate) async fn command(params: &GlobalParams, target_name: &String) -> Result<()> {
    let config = load_config(params, true)?;
    let services = Services::new(config.clone(), None, params.clone()).await?;

    let Some(target) = services
        .config_provider
        .lock()
        .await
        .list_targets()
        .await?
        .iter()
        .find(|x| &x.name == target_name)
        .cloned()
    else {
        error!("Target not found: {}", target_name);
        return Ok(());
    };

    let s: ProtocolServerEnum = match target.options {
        TargetOptions::Ssh(_) => ProtocolServerEnum::SSHProtocolServer(
            warpgate_protocol_ssh::SSHProtocolServer::new(&services).await?,
        ),
        TargetOptions::Http(_) => ProtocolServerEnum::HTTPProtocolServer(
            warpgate_protocol_http::HTTPProtocolServer::new(&services).await?,
        ),
        TargetOptions::MySql(_) => ProtocolServerEnum::MySQLProtocolServer(
            warpgate_protocol_mysql::MySQLProtocolServer::new(&services).await?,
        ),
        TargetOptions::Postgres(_) => ProtocolServerEnum::PostgresProtocolServer(
            warpgate_protocol_postgres::PostgresProtocolServer::new(&services).await?,
        ),
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
        Err(TargetTestError::Misconfigured(error)) => {
            error!(?error, "Misconfigured");
        }
        Err(TargetTestError::Unreachable) => {
            error!("Target is unreachable");
        }
        Err(other) => {
            error!("Misc error: {other}");
        }
        Ok(()) => {
            info!("Connection successful!");
            return Ok(());
        }
    }

    anyhow::bail!("Connection test failed")
}

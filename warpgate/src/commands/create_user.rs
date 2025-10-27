use warpgate_common::Secret;
use warpgate_core::Services;
use crate::config::load_config;
use crate::users::create_user;

pub(crate) async fn command(cli: &crate::Cli, username: &str, password: &Secret<String>, role: &Option<String>) -> anyhow::Result<()> {
    let config = load_config(&cli.config, true)?;
    let services = Services::new(config.clone(), None).await?;

    create_user(
        username,
        password,
        role,
        &services,
    ).await?;

    Ok(())
}
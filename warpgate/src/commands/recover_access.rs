use anyhow::Result;
use dialoguer::theme::ColorfulTheme;
use sea_orm::{ActiveModelTrait, EntityTrait, QueryOrder, Set};
use tracing::*;
use warpgate_common::auth::CredentialKind;
use warpgate_common::helpers::hash::hash_password;
use warpgate_common::{Secret, User as UserConfig, UserAuthCredential, UserPasswordCredential};
use warpgate_core::Services;
use warpgate_db_entities::User;

use crate::commands::common::assert_interactive_terminal;
use crate::config::load_config;

pub(crate) async fn command(cli: &crate::Cli, username: &Option<String>) -> Result<()> {
    assert_interactive_terminal();

    let config = load_config(&cli.config, true)?;
    let services = Services::new(config.clone()).await?;
    warpgate_protocol_ssh::generate_host_keys(&config)?;
    warpgate_protocol_ssh::generate_client_keys(&config)?;

    let theme = ColorfulTheme::default();
    let db = services.db.lock().await;

    let users = User::Entity::find()
        .order_by_asc(User::Column::Username)
        .all(&*db)
        .await?;

    let users: Result<Vec<UserConfig>, _> = users.into_iter().map(|t| t.try_into()).collect();
    let mut users = users?;
    let usernames = users.iter().map(|x| x.username.clone()).collect::<Vec<_>>();

    let user = match username {
        Some(username) => users
            .iter_mut()
            .find(|x| &x.username == username)
            .ok_or_else(|| anyhow::anyhow!("User not found"))?,
        None =>
        {
            #[allow(clippy::indexing_slicing)]
            &mut users[dialoguer::Select::with_theme(&theme)
                .with_prompt("Select a user to recover access for")
                .items(&usernames)
                .default(0)
                .interact()?]
        }
    };

    let password = dialoguer::Password::with_theme(&theme)
        .with_prompt(format!("New password for {}", user.username))
        .interact()?;

    if !dialoguer::Confirm::with_theme(&theme)
            .default(true)
            .with_prompt("This tool will add a new password for the user and set their HTTP auth policy to only require a password. Continue?")
            .interact()? {
                std::process::exit(0);
            }

    user.credentials
        .push(UserAuthCredential::Password(UserPasswordCredential {
            hash: Secret::new(hash_password(&password)),
        }));
    user.credential_policy
        .get_or_insert_with(Default::default)
        .http = Some(vec![CredentialKind::Password]);

    let model = User::ActiveModel {
        id: Set(user.id),
        credentials: Set(serde_json::to_value(&user.credentials)?),
        credential_policy: Set(serde_json::to_value(Some(&user.credential_policy))?),
        ..Default::default()
    };

    model.update(&*db).await?;

    info!("All done. You can now log in");

    Ok(())
}

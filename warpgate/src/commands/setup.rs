use crate::config::load_config;
use anyhow::Result;
use dialoguer::theme::ColorfulTheme;
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::Path;
use tracing::*;
use warpgate_common::hash::hash_password;
use warpgate_common::{
    RecordingsConfig, Role, SSHConfig, Secret, Services, Target, TargetWebAdminOptions, User,
    UserAuthCredential, WarpgateConfigStore, WebAdminConfig,
};

pub(crate) async fn command(cli: &crate::Cli) -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    info!("Welcome to Warpgate {version}");

    if cli.config.exists() {
        error!("Config file already exists at {}.", cli.config.display());
        error!("To generate a new config file, rename or delete the existing one first.");
        std::process::exit(1);
    }

    let mut config_dir = cli.config.parent().unwrap_or_else(|| Path::new(&"."));
    if config_dir.as_os_str().is_empty() {
        config_dir = Path::new(&".");
    }
    create_dir_all(config_dir)?;

    info!("Let's do some basic setup first.");
    info!(
        "The new config will be written in {}.",
        cli.config.display()
    );

    let theme = ColorfulTheme::default();
    let mut store = WarpgateConfigStore {
        roles: vec![Role {
            name: "warpgate:admin".to_owned(),
        }],
        ..Default::default()
    };

    // ---

    store.ssh.listen = dialoguer::Input::with_theme(&theme)
        .default(SSHConfig::default().listen)
        .with_prompt("Endpoint to listen for SSH connections on")
        .interact_text()?;

    // ---

    store.web_admin.listen = dialoguer::Input::with_theme(&theme)
        .default(WebAdminConfig::default().listen)
        .with_prompt("Endpoint to expose admin web interface on")
        .interact_text()?;

    if store.web_admin.enable {
        store.targets.push(Target {
            name: "web-admin".to_owned(),
            allow_roles: vec!["warpgate:admin".to_owned()],
            ssh: None,
            web_admin: Some(TargetWebAdminOptions {
                ..Default::default()
            }),
        });
    }

    // ---

    info!(
        "* Paths can be either absolute or relative to {}.",
        config_dir.canonicalize()?.display()
    );

    // ---

    let mut db_path: String = dialoguer::Input::with_theme(&theme)
        .default("data/db".into())
        .with_prompt("Directory to store the database in")
        .interact_text()?;

    if let Some(x) = db_path.strip_suffix("./") {
        db_path = x.to_string();
    }

    let mut database_url = "sqlite:".to_owned();
    database_url.push_str(&db_path);
    store.database_url = Secret::new(database_url);

    // ---

    store.ssh.keys = dialoguer::Input::with_theme(&theme)
        .default(SSHConfig::default().keys)
        .with_prompt("Directory to store SSH keys in")
        .interact_text()?;

    // ---

    store.recordings.enable = dialoguer::Confirm::with_theme(&theme)
        .default(true)
        .with_prompt("Do you want to record user sessions?")
        .interact()?;

    if store.recordings.enable {
        store.recordings.path = dialoguer::Input::with_theme(&theme)
            .default(RecordingsConfig::default().path)
            .with_prompt("Directory to store recordings in")
            .interact_text()?;
    }

    // ---

    let password = dialoguer::Password::with_theme(&theme)
        .with_prompt("Set a password for the Warpgate admin user")
        .interact()?;

    store.users.push(User {
        username: "admin".into(),
        credentials: vec![UserAuthCredential::Password {
            hash: Secret::new(hash_password(&password)),
        }],
        require: None,
        roles: vec!["warpgate:admin".into()],
    });

    // ---

    info!("Generated configuration:");
    let yaml = serde_yaml::to_string(&store)?;
    println!("{}", yaml);

    File::create(&cli.config)?.write_all(yaml.as_bytes())?;
    info!("Saved into {}", cli.config.display());

    let config = load_config(&cli.config)?;
    Services::new(config.clone()).await?;
    warpgate_protocol_ssh::generate_host_keys(&config)?;
    warpgate_protocol_ssh::generate_client_keys(&config)?;

    info!("");
    info!("Admin user credentials:");
    info!("  * Username: admin");
    info!("  * Password: <your password>");
    info!("");
    info!("You can now start Warpgate with:");
    info!(
        "  {} --config {} run",
        std::env::args().next().unwrap(),
        cli.config.display()
    );

    Ok(())
}

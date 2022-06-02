use crate::config::load_config;
use anyhow::Result;
use dialoguer::theme::ColorfulTheme;
use rcgen::generate_simple_self_signed;
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::*;
use warpgate_common::helpers::fs::{secure_directory, secure_file};
use warpgate_common::helpers::hash::hash_password;
use warpgate_common::{
    Role, SSHConfig, Secret, Services, Target, TargetWebAdminOptions, User, UserAuthCredential,
    WarpgateConfigStore, WebAdminConfig,
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

    info!(
        "* Paths can be either absolute or relative to {}.",
        config_dir.canonicalize()?.display()
    );

    // ---

    let data_path: String = dialoguer::Input::with_theme(&theme)
        .default("/var/lib/warpgate".into())
        .with_prompt("Directory to store app data (up to a few MB) in")
        .interact_text()?;

    let db_path = PathBuf::from(&data_path).join("db");
    create_dir_all(&db_path)?;
    secure_directory(&db_path)?;

    let mut db_path = db_path.to_string_lossy().to_string();

    if let Some(x) = db_path.strip_suffix("./") {
        db_path = x.to_string();
    }

    let mut database_url = "sqlite:".to_owned();
    database_url.push_str(&db_path);
    store.database_url = Secret::new(database_url);

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
            http: None,
            web_admin: Some(TargetWebAdminOptions {}),
        });
    }

    store.web_admin.certificate = PathBuf::from(&data_path)
        .join("web-admin.certificate.pem")
        .to_string_lossy()
        .to_string();

    store.web_admin.key = PathBuf::from(&data_path)
        .join("web-admin.key.pem")
        .to_string_lossy()
        .to_string();

    // ---

    store.ssh.keys = PathBuf::from(&data_path)
        .join("ssh-keys")
        .to_string_lossy()
        .to_string();

    // ---

    store.recordings.enable = dialoguer::Confirm::with_theme(&theme)
        .default(true)
        .with_prompt("Do you want to record user sessions?")
        .interact()?;
    store.recordings.path = PathBuf::from(&data_path)
        .join("recordings")
        .to_string_lossy()
        .to_string();

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

    let config = load_config(&cli.config, true)?;
    Services::new(config.clone()).await?;
    warpgate_protocol_ssh::generate_host_keys(&config)?;
    warpgate_protocol_ssh::generate_client_keys(&config)?;

    {
        info!("Generating HTTPS certificate");
        let cert = generate_simple_self_signed(vec![
            "warpgate.local".to_string(),
            "localhost".to_string(),
        ])?;

        let certificate_path = config
            .paths_relative_to
            .join(&config.store.web_admin.certificate);
        let key_path = config.paths_relative_to.join(&config.store.web_admin.key);
        std::fs::write(&certificate_path, cert.serialize_pem()?)?;
        std::fs::write(&key_path, cert.serialize_private_key_pem())?;
        secure_file(&certificate_path)?;
        secure_file(&key_path)?;
    }

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

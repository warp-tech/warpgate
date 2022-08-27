use std::fs::{create_dir_all, File};
use std::io::Write;
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use dialoguer::theme::ColorfulTheme;
use rcgen::generate_simple_self_signed;
use tracing::*;
use uuid::Uuid;
use warpgate_common::helpers::fs::{secure_directory, secure_file};
use warpgate_common::helpers::hash::hash_password;
use warpgate_common::{
    HTTPConfig, ListenEndpoint, MySQLConfig, Role, SSHConfig, Secret, Target, TargetOptions,
    TargetWebAdminOptions, User, UserAuthCredential, WarpgateConfigStore,
};
use warpgate_core::consts::BUILTIN_ADMIN_ROLE_NAME;
use warpgate_core::Services;

use crate::config::load_config;

fn prompt_endpoint(prompt: &str, default: ListenEndpoint) -> ListenEndpoint {
    loop {
        let v = dialoguer::Input::with_theme(&ColorfulTheme::default())
            .default(format!("{:?}", default))
            .with_prompt(prompt)
            .interact_text()
            .and_then(|v| v.to_socket_addrs());
        match v {
            Ok(mut addr) => match addr.next() {
                Some(addr) => return ListenEndpoint(addr),
                None => {
                    error!("No endpoints resolved");
                }
            },
            Err(err) => {
                error!("Failed to resolve this endpoint: {err}")
            }
        }
    }
}

pub(crate) async fn command(cli: &crate::Cli) -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    info!("Welcome to Warpgate {version}");

    if cli.config.exists() {
        error!("Config file already exists at {}.", cli.config.display());
        error!("To generate a new config file, rename or delete the existing one first.");
        std::process::exit(1);
    }

    let is_docker = std::env::var("DOCKER").is_ok();

    if !atty::is(atty::Stream::Stdin) {
        error!("Please run this command from an interactive terminal.");
        if is_docker {
            info!("(have you forgotten `-it`?)");
        }
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
            id: Uuid::new_v4(),
            name: BUILTIN_ADMIN_ROLE_NAME.to_owned(),
        }],
        http: HTTPConfig {
            enable: true,
            ..Default::default()
        },
        ..Default::default()
    };

    // ---

    if !is_docker {
        info!(
            "* Paths can be either absolute or relative to {}.",
            config_dir.canonicalize()?.display()
        );
    }

    // ---

    let data_path: String = if is_docker {
        "/data".to_owned()
    } else {
        dialoguer::Input::with_theme(&theme)
            .default("/var/lib/warpgate".into())
            .with_prompt("Directory to store app data (up to a few MB) in")
            .interact_text()?
    };

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
    if !is_docker {
        store.http.listen = prompt_endpoint(
            "Endpoint to listen for HTTP connections on",
            HTTPConfig::default().listen,
        );

        info!("You will now choose specific protocol listeners to be enabled.");
        info!("");
        info!("NB: Nothing will be exposed by default -");
        info!("    you'll set target hosts in the config file later.");

        store.ssh.enable = dialoguer::Confirm::with_theme(&theme)
            .default(true)
            .with_prompt("Accept SSH connections?")
            .interact()?;

        if store.ssh.enable {
            store.ssh.listen = prompt_endpoint(
                "Endpoint to listen for SSH connections on",
                SSHConfig::default().listen,
            );
        }

        // ---

        store.mysql.enable = dialoguer::Confirm::with_theme(&theme)
            .default(true)
            .with_prompt("Accept MySQL connections?")
            .interact()?;

        if store.mysql.enable {
            store.mysql.listen = prompt_endpoint(
                "Endpoint to listen for MySQL connections on",
                MySQLConfig::default().listen,
            );
        }
    }

    if store.http.enable {
        store.targets.push(Target {
            id: Uuid::new_v4(),
            name: "Web admin".to_owned(),
            allow_roles: vec![BUILTIN_ADMIN_ROLE_NAME.to_owned()],
            options: TargetOptions::WebAdmin(TargetWebAdminOptions {}),
        });
    }

    store.http.certificate = PathBuf::from(&data_path)
        .join("tls.certificate.pem")
        .to_string_lossy()
        .to_string();

    store.http.key = PathBuf::from(&data_path)
        .join("tls.key.pem")
        .to_string_lossy()
        .to_string();

    store.mysql.certificate = store.http.certificate.clone();
    store.mysql.key = store.http.key.clone();

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
        roles: vec![BUILTIN_ADMIN_ROLE_NAME.into()],
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
        info!("Generating a TLS certificate");
        let cert = generate_simple_self_signed(vec![
            "warpgate.local".to_string(),
            "localhost".to_string(),
        ])?;

        let certificate_path = config
            .paths_relative_to
            .join(&config.store.http.certificate);
        let key_path = config.paths_relative_to.join(&config.store.http.key);
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
    if is_docker {
        info!("docker run -p 8888:8888 -p 2222:2222 -it -v <your data dir>:/data ghcr.io/warp-tech/warpgate");
    } else {
        info!(
            "  {} --config {} run",
            std::env::args()
                .next()
                .unwrap_or_else(|| "warpgate".to_string()),
            cli.config.display()
        );
    }

    Ok(())
}

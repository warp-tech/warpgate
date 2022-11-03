#![allow(clippy::collapsible_else_if)]

use std::fs::{create_dir_all, File};
use std::io::Write;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};

use anyhow::Result;
use dialoguer::theme::ColorfulTheme;
use rcgen::generate_simple_self_signed;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use tracing::*;
use uuid::Uuid;
use warpgate_common::helpers::fs::{secure_directory, secure_file};
use warpgate_common::helpers::hash::hash_password;
use warpgate_common::{
    HTTPConfig, ListenEndpoint, MySQLConfig, SSHConfig, Secret, UserAuthCredential,
    UserPasswordCredential, UserRequireCredentialsPolicy, WarpgateConfigStore, WarpgateError,
};
use warpgate_core::consts::{BUILTIN_ADMIN_ROLE_NAME, BUILTIN_ADMIN_USERNAME};
use warpgate_core::Services;
use warpgate_db_entities::{Role, User, UserRoleAssignment};

use crate::commands::common::{assert_interactive_terminal, is_docker};
use crate::config::load_config;
use crate::Commands;

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

    if let Commands::Setup = cli.command {
        assert_interactive_terminal();
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
        http: HTTPConfig {
            enable: true,
            ..Default::default()
        },
        ..Default::default()
    };

    // ---

    if !is_docker() {
        info!(
            "* Paths can be either absolute or relative to {}.",
            config_dir.canonicalize()?.display()
        );
    }

    // ---

    let data_path: String = if let Commands::UnattendedSetup { data_path, .. } = &cli.command {
        data_path.to_owned()
    } else {
        #[cfg(target_os = "linux")]
        let default_data_path = "/var/lib/warpgate".to_string();
        #[cfg(target_os = "macos")]
        let default_data_path = "/usr/local/var/lib/warpgate".to_string();

        if is_docker() {
            "/data".to_owned()
        } else {
            dialoguer::Input::with_theme(&theme)
                .default(default_data_path)
                .with_prompt("Directory to store app data (up to a few MB) in")
                .interact_text()?
        }
    };

    let db_path = PathBuf::from(&data_path).join("db");
    create_dir_all(&db_path)?;
    secure_directory(&db_path)?;

    store.database_url = Secret::new(
        if let Commands::UnattendedSetup {
            database_url: Some(url),
            ..
        } = &cli.command
        {
            url.to_owned()
        } else {
            let mut db_path = db_path.to_string_lossy().to_string();

            if let Some(x) = db_path.strip_suffix("./") {
                db_path = x.to_string();
            }

            format!("sqlite:{db_path}")
        },
    );

    if let Commands::UnattendedSetup { http_port, .. } = &cli.command {
        store.http.enable = true;
        store.http.listen = ListenEndpoint(SocketAddr::from(([0, 0, 0, 0], *http_port)));
    } else {
        if !is_docker() {
            store.http.listen = prompt_endpoint(
                "Endpoint to listen for HTTP connections on",
                HTTPConfig::default().listen,
            );
        }
    }

    if let Commands::UnattendedSetup { ssh_port, .. } = &cli.command {
        if let Some(ssh_port) = ssh_port {
            store.ssh.enable = true;
            store.ssh.listen = ListenEndpoint(SocketAddr::from(([0, 0, 0, 0], *ssh_port)));
        }
    } else {
        if !is_docker() {
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
        }
    }

    if let Commands::UnattendedSetup { ssh_port, .. } = &cli.command {
        if let Some(ssh_port) = ssh_port {
            store.ssh.enable = true;
            store.ssh.listen = ListenEndpoint(SocketAddr::from(([0, 0, 0, 0], *ssh_port)));
        }
    } else {
        if !is_docker() {
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

    if let Commands::UnattendedSetup {
        record_sessions, ..
    } = &cli.command
    {
        store.recordings.enable = *record_sessions;
    } else {
        store.recordings.enable = dialoguer::Confirm::with_theme(&theme)
            .default(true)
            .with_prompt("Do you want to record user sessions?")
            .interact()?;
    }
    store.recordings.path = PathBuf::from(&data_path)
        .join("recordings")
        .to_string_lossy()
        .to_string();

    // ---

    let admin_password = if let Commands::UnattendedSetup { admin_password, .. } = &cli.command {
        if let Some(admin_password) = admin_password {
            admin_password.to_owned()
        } else {
            if let Ok(admin_password) = std::env::var("WARPGATE_ADMIN_PASSWORD") {
                admin_password
            } else {
                error!(
                    "You must supply the admin password either through the --admin-password option"
                );
                error!("or the WARPGATE_ADMIN_PASSWORD environment variable.");
                std::process::exit(1);
            }
        }
    } else {
        dialoguer::Password::with_theme(&theme)
            .with_prompt("Set a password for the Warpgate admin user")
            .interact()?
    };

    // ---

    info!("Generated configuration:");
    let yaml = serde_yaml::to_string(&store)?;
    println!("{}", yaml);

    File::create(&cli.config)?.write_all(yaml.as_bytes())?;
    info!("Saved into {}", cli.config.display());

    let config = load_config(&cli.config, true)?;
    let services = Services::new(config.clone()).await?;
    warpgate_protocol_ssh::generate_host_keys(&config)?;
    warpgate_protocol_ssh::generate_client_keys(&config)?;

    {
        let db = services.db.lock().await;

        let admin_role = Role::Entity::find()
            .filter(Role::Column::Name.eq(BUILTIN_ADMIN_ROLE_NAME))
            .all(&*db)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("Database inconsistent: no admin role"))?;

        let admin_user = match User::Entity::find()
            .filter(User::Column::Username.eq(BUILTIN_ADMIN_USERNAME))
            .all(&*db)
            .await?
            .first()
        {
            Some(x) => x.to_owned(),
            None => {
                let values = User::ActiveModel {
                    id: Set(Uuid::new_v4()),
                    username: Set(BUILTIN_ADMIN_USERNAME.to_owned()),
                    credentials: Set(serde_json::to_value(vec![UserAuthCredential::Password(
                        UserPasswordCredential {
                            hash: Secret::new(hash_password(&admin_password)),
                        },
                    )])?),
                    credential_policy: Set(serde_json::to_value(
                        None::<UserRequireCredentialsPolicy>,
                    )?),
                };
                values.insert(&*db).await.map_err(WarpgateError::from)?
            }
        };

        if UserRoleAssignment::Entity::find()
            .filter(UserRoleAssignment::Column::UserId.eq(admin_user.id))
            .filter(UserRoleAssignment::Column::RoleId.eq(admin_role.id))
            .all(&*db)
            .await?
            .is_empty()
        {
            let values = UserRoleAssignment::ActiveModel {
                user_id: Set(admin_user.id),
                role_id: Set(admin_role.id),
                ..Default::default()
            };
            values.insert(&*db).await.map_err(WarpgateError::from)?;
        }
    }

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
    if is_docker() {
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

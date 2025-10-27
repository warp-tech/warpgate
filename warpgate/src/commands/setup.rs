#![allow(clippy::collapsible_else_if)]

use std::fs::{create_dir_all, File};
use std::io::Write;
use std::net::{Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use dialoguer::theme::ColorfulTheme;
use rcgen::generate_simple_self_signed;
use tracing::*;
use warpgate_common::helpers::fs::{secure_directory, secure_file};
use warpgate_common::version::warpgate_version;
use warpgate_common::{
    HttpConfig, ListenEndpoint, MySqlConfig, PostgresConfig, Secret, SshConfig,
    WarpgateConfigStore,
};
use warpgate_core::consts::{BUILTIN_ADMIN_ROLE_NAME, BUILTIN_ADMIN_USERNAME};
use warpgate_core::Services;

use crate::commands::common::{assert_interactive_terminal, is_docker};
use crate::config::load_config;
use crate::Commands;
use crate::users::{create_user};

fn prompt_endpoint(prompt: &str, default: ListenEndpoint) -> ListenEndpoint {
    loop {
        let v = dialoguer::Input::with_theme(&ColorfulTheme::default())
            .default(format!("{default:?}"))
            .with_prompt(prompt)
            .interact_text()
            .context("dialoguer")
            .and_then(|v| v.to_socket_addrs().context("address resolution"));
        match v {
            Ok(mut addr) => match addr.next() {
                Some(addr) => return ListenEndpoint::from(addr),
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
    let version = warpgate_version();
    info!("Welcome to Warpgate {version}");

    if cli.config.exists() {
        error!("Config file already exists at {}.", cli.config.display());
        error!("To generate a new config file, rename or delete the existing one first.");
        std::process::exit(1);
    }

    if let Commands::Setup { .. } = cli.command {
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
    let mut store = WarpgateConfigStore::default();

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

    let data_path = config_dir.join(PathBuf::from(&data_path)).canonicalize()?;
    create_dir_all(&data_path)?;

    let db_path = data_path.join("db");
    create_dir_all(&db_path)?;
    secure_directory(&db_path)?;

    store.database_url = Secret::new(match &cli.command {
        Commands::UnattendedSetup {
            database_url: Some(url),
            ..
        }
        | Commands::Setup {
            database_url: Some(url),
            ..
        } => url.to_owned(),
        _ => {
            let mut db_path = db_path.to_string_lossy().to_string();

            if let Some(x) = db_path.strip_suffix("./") {
                db_path = x.to_string();
            }

            format!("sqlite:{db_path}")
        }
    });

    if let Commands::UnattendedSetup { http_port, .. } = &cli.command {
        store.http.listen =
            ListenEndpoint::from(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), *http_port));
    } else {
        if !is_docker() {
            store.http.listen = prompt_endpoint(
                "Endpoint to listen for HTTP connections on",
                HttpConfig::default().listen,
            );
        }
    }

    if let Commands::UnattendedSetup { ssh_port, .. } = &cli.command {
        if let Some(ssh_port) = ssh_port {
            store.ssh.enable = true;
            store.ssh.listen =
                ListenEndpoint::from(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), *ssh_port));
        }
    } else {
        if is_docker() {
            store.ssh.enable = true;
        } else {
            info!("You will now choose specific protocol listeners to be enabled.");
            info!("");
            info!("NB: Nothing will be exposed by default -");
            info!("    you'll choose target hosts in the UI later.");

            store.ssh.enable = dialoguer::Confirm::with_theme(&theme)
                .default(true)
                .with_prompt("Accept SSH connections?")
                .interact()?;

            if store.ssh.enable {
                store.ssh.listen = prompt_endpoint(
                    "Endpoint to listen for SSH connections on",
                    SshConfig::default().listen,
                );
            }
        }
    }

    if let Commands::UnattendedSetup { mysql_port, .. } = &cli.command {
        if let Some(mysql_port) = mysql_port {
            store.mysql.enable = true;
            store.mysql.listen =
                ListenEndpoint::from(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), *mysql_port));
        }
    } else {
        if is_docker() {
            store.mysql.enable = true;
        } else {
            store.mysql.enable = dialoguer::Confirm::with_theme(&theme)
                .default(true)
                .with_prompt("Accept MySQL connections?")
                .interact()?;

            if store.mysql.enable {
                store.mysql.listen = prompt_endpoint(
                    "Endpoint to listen for MySQL connections on",
                    MySqlConfig::default().listen,
                );
            }
        }
    }
    if let Commands::UnattendedSetup { postgres_port, .. } = &cli.command {
        if let Some(postgres_port) = postgres_port {
            store.postgres.enable = true;
            store.postgres.listen = ListenEndpoint::from(SocketAddr::new(
                Ipv6Addr::UNSPECIFIED.into(),
                *postgres_port,
            ));
        }
    } else {
        if is_docker() {
            store.postgres.enable = true;
        } else {
            store.postgres.enable = dialoguer::Confirm::with_theme(&theme)
                .default(true)
                .with_prompt("Accept PostgreSQL connections?")
                .interact()?;

            if store.postgres.enable {
                store.postgres.listen = prompt_endpoint(
                    "Endpoint to listen for PostgreSQL connections on",
                    PostgresConfig::default().listen,
                );
            }
        }
    }

    store.http.certificate = data_path
        .join("tls.certificate.pem")
        .to_string_lossy()
        .to_string();

    store.http.key = data_path.join("tls.key.pem").to_string_lossy().to_string();

    store.mysql.certificate = store.http.certificate.clone();
    store.mysql.key = store.http.key.clone();

    store.postgres.certificate = store.http.certificate.clone();
    store.postgres.key = store.http.key.clone();

    // ---

    store.ssh.keys = data_path.join("ssh-keys").to_string_lossy().to_string();

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
    store.recordings.path = data_path.join("recordings").to_string_lossy().to_string();

    // ---

    let admin_password = Secret::new(
        if let Commands::UnattendedSetup { admin_password, .. } = &cli.command {
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
        },
    );

    if let Commands::UnattendedSetup { external_host, .. } = &cli.command {
        store.external_host = external_host.clone();
    }

    // ---

    info!("Generated configuration:");
    let yaml = serde_yaml::to_string(&store)?;
    println!("{yaml}");

    let yaml = format!(
        "# Config generated in version {version}\n# yaml-language-server: $schema=https://raw.githubusercontent.com/warp-tech/warpgate/refs/heads/main/config-schema.json\n\n{yaml}",
        version = warpgate_version()
    );

    File::create(&cli.config)?.write_all(yaml.as_bytes())?;
    info!("Saved into {}", cli.config.display());

    let config = load_config(&cli.config, true)?;
    let services = Services::new(config.clone(), None).await?;
    warpgate_protocol_ssh::generate_host_keys(&config)?;
    warpgate_protocol_ssh::generate_client_keys(&config)?;

    // Create the admin user
    create_user(
        BUILTIN_ADMIN_USERNAME,
        &admin_password,
        BUILTIN_ADMIN_ROLE_NAME,
        &services,
    ).await?;

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
        std::fs::write(&certificate_path, cert.cert.pem())?;
        std::fs::write(&key_path, cert.key_pair.serialize_pem())?;
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

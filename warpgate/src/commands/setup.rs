use std::fs::{File, create_dir_all};
use std::io::Write;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use dialoguer::theme::ColorfulTheme;
use rcgen::generate_simple_self_signed;
use sea_orm::ActiveValue::Set;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, IntoActiveModel, QueryFilter,
};
use tracing::{error, info};
use uuid::Uuid;
use warpgate_common::helpers::fs::{secure_directory, secure_file};
use warpgate_common::version::warpgate_version;
use warpgate_common::{
    GlobalParams, HttpConfig, KubernetesConfig, ListenEndpoint, MySqlConfig, PostgresConfig,
    RdpConfig, Secret, SshConfig, SshHostKeyVerificationMode, VncConfig, WarpgateConfig,
    WarpgateConfigStore,
};
use warpgate_core::consts::{BUILTIN_ADMIN_ROLE_NAME, BUILTIN_ADMIN_USERNAME};
use warpgate_core::db::connect_to_db_and_migrate;
use warpgate_db_entities::Parameters::{RecordingsDiskConfig, RecordingsStorageConfig};
use warpgate_db_entities::{Parameters, Role, User, UserRoleAssignment};

use crate::commands::common::{assert_interactive_terminal, is_docker};
use crate::config::load_config;
use crate::{SetupArgs, UnattendedSetupArgs};

#[derive(Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum IfConfigExists {
    #[default]
    Fail,
    Skip,
    /// Initialise the database as a fresh setup would (admin user, defaults,
    /// SSH keys) if it has no users yet, e.g. for a provided config
    Bootstrap,
}

impl SetupArgs {
    fn validate(&self) -> Result<()> {
        for (flag, dir) in [
            ("--import-ssh-host-keys", &self.import_ssh_host_keys),
            ("--import-ssh-client-keys", &self.import_ssh_client_keys),
        ] {
            if let Some(dir) = dir
                && !dir.is_dir()
            {
                anyhow::bail!("{flag}: {} is not a directory", dir.display());
            }
        }
        Ok(())
    }
}

impl UnattendedSetupArgs {
    fn admin_password(&self) -> Secret<String> {
        if let Some(password) = self
            .admin_password
            .clone()
            .or_else(|| std::env::var("WARPGATE_ADMIN_PASSWORD").ok())
        {
            Secret::new(password)
        } else {
            error!("You must supply the admin password either through the --admin-password option");
            error!("or the WARPGATE_ADMIN_PASSWORD environment variable.");
            std::process::exit(1);
        }
    }

    /// Read before anything is written, so a bad path leaves no half-done setup.
    fn provided_tls(&self) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        match (&self.tls_certificate, &self.tls_key) {
            (Some(certificate), Some(key)) => Ok(Some((
                std::fs::read(certificate)
                    .with_context(|| format!("--tls-certificate: {}", certificate.display()))?,
                std::fs::read(key).with_context(|| format!("--tls-key: {}", key.display()))?,
            ))),
            _ => Ok(None),
        }
    }
}

struct Listener {
    enable: bool,
    listen: ListenEndpoint,
}

struct Answers {
    data_path: PathBuf,
    database_url: Option<String>,
    http: ListenEndpoint,
    ssh: Listener,
    mysql: Listener,
    postgres: Listener,
    kubernetes: Listener,
    vnc: Listener,
    rdp: Listener,
    host_key_verification: SshHostKeyVerificationMode,
    record_sessions: bool,
    admin_password: Secret<String>,
    external_host: Option<String>,
}

impl Answers {
    fn from_args(args: &UnattendedSetupArgs, config_dir: &Path) -> Result<Self> {
        let listen_on =
            |port: u16| ListenEndpoint::from(SocketAddr::new(args.listen_address, port));
        let listener = |port: Option<u16>, default: ListenEndpoint| Listener {
            enable: port.is_some(),
            listen: listen_on(port.unwrap_or_else(|| default.address().port())),
        };

        Ok(Self {
            data_path: resolve_data_path(config_dir, &args.data_path)?,
            database_url: args.common.database_url.clone(),
            http: listen_on(args.http_port),
            ssh: listener(args.ssh_port, SshConfig::default().listen),
            mysql: listener(args.mysql_port, MySqlConfig::default().listen),
            postgres: listener(args.postgres_port, PostgresConfig::default().listen),
            kubernetes: listener(args.kubernetes_port, KubernetesConfig::default().listen),
            vnc: listener(args.vnc_port, VncConfig::default().listen),
            rdp: listener(args.rdp_port, RdpConfig::default().listen),
            host_key_verification: args.host_key_verification,
            record_sessions: args.record_sessions,
            admin_password: args.admin_password(),
            external_host: args.external_host.clone(),
        })
    }

    fn interactive(common: &SetupArgs, config_dir: &Path) -> Result<Self> {
        let theme = ColorfulTheme::default();

        let data_path = if is_docker() {
            "/data".to_owned()
        } else {
            info!(
                "* Paths can be either absolute or relative to {}.",
                config_dir.canonicalize()?.display()
            );
            #[cfg(target_os = "linux")]
            let default_data_path = "/var/lib/warpgate";
            #[cfg(target_os = "macos")]
            let default_data_path = "/usr/local/var/lib/warpgate";
            dialoguer::Input::with_theme(&theme)
                .default(default_data_path.to_string())
                .with_prompt("Directory to store app data (up to a few MB) in")
                .interact_text()?
        };
        let data_path = resolve_data_path(config_dir, &data_path)?;

        let http = if is_docker() {
            HttpConfig::default().listen
        } else {
            prompt_endpoint(
                "Endpoint to listen for HTTP connections on",
                &HttpConfig::default().listen,
            )
        };

        if !is_docker() {
            info!("You will now choose specific protocol listeners to be enabled.");
            info!("");
            info!("NB: Nothing will be exposed by default -");
            info!("    you'll choose target hosts in the UI later.");
        }
        let ssh = prompt_listener(&theme, "SSH", SshConfig::default().listen, true)?;
        let mysql = prompt_listener(&theme, "MySQL", MySqlConfig::default().listen, true)?;
        let postgres =
            prompt_listener(&theme, "PostgreSQL", PostgresConfig::default().listen, true)?;
        let kubernetes = prompt_listener(
            &theme,
            "Kubernetes",
            KubernetesConfig::default().listen,
            true,
        )?;

        let vnc = prompt_listener(&theme, "VNC", VncConfig::default().listen, false)?;
        let rdp = prompt_listener(&theme, "RDP", RdpConfig::default().listen, false)?;

        let record_sessions = dialoguer::Confirm::with_theme(&theme)
            .default(true)
            .with_prompt("Do you want to record user sessions?")
            .interact()?;

        let admin_password = Secret::new(
            dialoguer::Password::with_theme(&theme)
                .with_prompt("Set a password for the Warpgate admin user")
                .interact()?,
        );

        Ok(Self {
            data_path,
            database_url: common.database_url.clone(),
            http,
            ssh,
            mysql,
            postgres,
            kubernetes,
            vnc,
            rdp,
            host_key_verification: SshHostKeyVerificationMode::default(),
            record_sessions,
            admin_password,
            external_host: None,
        })
    }

    fn config(&self, db_path: &Path) -> WarpgateConfigStore {
        let database_url = self.database_url.clone().unwrap_or_else(|| {
            let db_path = db_path.to_string_lossy();
            format!("sqlite:{}", db_path.strip_suffix("./").unwrap_or(&db_path))
        });
        let mut store = WarpgateConfigStore {
            database_url: Secret::new(database_url),
            ..Default::default()
        };

        store.http.listen = self.http.clone();
        for (listener, enable, listen) in [
            (&self.ssh, &mut store.ssh.enable, &mut store.ssh.listen),
            (
                &self.mysql,
                &mut store.mysql.enable,
                &mut store.mysql.listen,
            ),
            (
                &self.postgres,
                &mut store.postgres.enable,
                &mut store.postgres.listen,
            ),
            (
                &self.kubernetes,
                &mut store.kubernetes.enable,
                &mut store.kubernetes.listen,
            ),
            (&self.vnc, &mut store.vnc.enable, &mut store.vnc.listen),
            (&self.rdp, &mut store.rdp.enable, &mut store.rdp.listen),
        ] {
            *enable = listener.enable;
            *listen = listener.listen.clone();
        }

        let certificate = self
            .data_path
            .join("tls.certificate.pem")
            .to_string_lossy()
            .to_string();
        let key = self
            .data_path
            .join("tls.key.pem")
            .to_string_lossy()
            .to_string();
        for (store_certificate, store_key) in [
            (&mut store.http.certificate, &mut store.http.key),
            (&mut store.mysql.certificate, &mut store.mysql.key),
            (&mut store.postgres.certificate, &mut store.postgres.key),
            (&mut store.kubernetes.certificate, &mut store.kubernetes.key),
            (&mut store.vnc.certificate, &mut store.vnc.key),
            (&mut store.rdp.certificate, &mut store.rdp.key),
        ] {
            *store_certificate = certificate.clone();
            *store_key = key.clone();
        }

        store.ssh.host_key_verification = self.host_key_verification;
        store.external_host = self.external_host.clone();
        store
    }

    fn recordings_path(&self) -> String {
        self.data_path
            .join("recordings")
            .to_string_lossy()
            .to_string()
    }
}

fn prompt_listener(
    theme: &ColorfulTheme,
    name: &str,
    default: ListenEndpoint,
    default_enabled: bool,
) -> Result<Listener> {
    if is_docker() {
        return Ok(Listener {
            enable: default_enabled,
            listen: default,
        });
    }
    let enable = dialoguer::Confirm::with_theme(theme)
        .default(default_enabled)
        .with_prompt(format!("Accept {name} connections?"))
        .interact()?;
    let listen = if enable {
        prompt_endpoint(
            &format!("Endpoint to listen for {name} connections on"),
            &default,
        )
    } else {
        default
    };
    Ok(Listener { enable, listen })
}

fn prompt_endpoint(prompt: &str, default: &ListenEndpoint) -> ListenEndpoint {
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
                error!("Failed to resolve this endpoint: {err}");
            }
        }
    }
}

fn config_dir(params: &GlobalParams) -> &Path {
    let dir = params.paths_relative_to();
    if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    }
}

fn resolve_data_path(config_dir: &Path, data_path: &str) -> Result<PathBuf> {
    Ok(config_dir.join(data_path).canonicalize()?)
}

async fn bootstrap_database(
    params: &GlobalParams,
    config: &WarpgateConfig,
    db: &DatabaseConnection,
    answers: &Answers,
    imports: &SetupArgs,
    only_if_empty: bool,
) -> Result<()> {
    let created = crate::commands::create_user::command(
        params,
        BUILTIN_ADMIN_USERNAME,
        &answers.admin_password,
        Some(&BUILTIN_ADMIN_ROLE_NAME.to_string()),
    )
    .await?;
    if !created && only_if_empty {
        info!("Another node is initialising the database already");
        return Ok(());
    }

    let mut parameters = Parameters::Entity::get(db).await?.into_active_model();
    parameters.recordings_enable = Set(answers.record_sessions);
    parameters.recordings_storage = Set(serde_json::to_string(&RecordingsStorageConfig::Disk(
        RecordingsDiskConfig {
            path: answers.recordings_path(),
        },
    ))?);
    Parameters::Entity::update(parameters).exec(db).await?;

    let keys_path = config.store.ssh.keys_path(params);
    warpgate_protocol_ssh::ensure_host_keys(
        db,
        imports
            .import_ssh_host_keys
            .as_deref()
            .unwrap_or(&keys_path),
    )
    .await?;
    warpgate_protocol_ssh::ensure_client_keys(
        db,
        imports
            .import_ssh_client_keys
            .as_deref()
            .unwrap_or(&keys_path),
    )
    .await?;

    #[allow(clippy::expect_used)]
    let user = User::Entity::find()
        .filter(User::Entity::username_eq_ci(BUILTIN_ADMIN_USERNAME))
        .one(db)
        .await?
        .expect("Admin user should exist");

    let access_role = match Role::Entity::find()
        .filter(Role::Column::Name.eq(BUILTIN_ADMIN_USERNAME))
        .one(db)
        .await?
    {
        Some(role) => role,
        None => {
            Role::ActiveModel {
                id: Set(Uuid::new_v4()),
                name: Set(BUILTIN_ADMIN_USERNAME.to_string()),
                description: Set("".to_string()),
                is_default: Set(false),
            }
            .insert(db)
            .await?
        }
    };

    UserRoleAssignment::Entity::idempotent_grant(db, user.id, access_role.id, None).await?;
    Ok(())
}

async fn bootstrap_existing(params: &GlobalParams, args: &UnattendedSetupArgs) -> Result<()> {
    let config_path = params.config_path();
    let config = load_config(params, true)?;
    let db = connect_to_db_and_migrate(&config, params).await?;
    if User::Entity::find().one(&db).await?.is_some() {
        info!(
            "Config file already exists at {} and the database is initialised, nothing to do.",
            config_path.display()
        );
        return Ok(());
    }
    info!(
        "Config file already exists at {}, initialising the database.",
        config_path.display()
    );
    let answers = Answers::from_args(args, config_dir(params))?;
    bootstrap_database(params, &config, &db, &answers, &args.common, true).await
}

fn install_tls(
    params: &GlobalParams,
    config: &WarpgateConfig,
    provided: Option<(Vec<u8>, Vec<u8>)>,
) -> Result<()> {
    let (certificate, key) = if let Some(tls) = provided {
        info!("Installing the provided TLS certificate");
        tls
    } else {
        info!("Generating a TLS certificate");
        let cert = generate_simple_self_signed(vec![
            "warpgate.local".to_string(),
            "localhost".to_string(),
        ])?;
        (
            cert.cert.pem().into_bytes(),
            cert.signing_key.serialize_pem().into_bytes(),
        )
    };

    let certificate_path = params
        .paths_relative_to()
        .join(&config.store.http.certificate);
    let key_path = params.paths_relative_to().join(&config.store.http.key);
    std::fs::write(&certificate_path, certificate)?;
    std::fs::write(&key_path, key)?;
    if params.should_secure_files() {
        secure_file(&certificate_path)?;
        secure_file(&key_path)?;
    }
    Ok(())
}

pub async fn command(
    params: &GlobalParams,
    common: &SetupArgs,
    unattended: Option<&UnattendedSetupArgs>,
) -> Result<()> {
    let version = warpgate_version();
    info!("Welcome to Warpgate {version}");
    let config_path = params.config_path();

    if config_path.exists() {
        match unattended {
            Some(args) if args.if_config_exists == IfConfigExists::Skip => {
                info!(
                    "Config file already exists at {}, skipping setup.",
                    config_path.display()
                );
                return Ok(());
            }
            Some(args) if args.if_config_exists == IfConfigExists::Bootstrap => {
                return bootstrap_existing(params, args).await;
            }
            _ => {
                error!("Config file already exists at {}.", config_path.display());
                error!("To generate a new config file, rename or delete the existing one first.");
                std::process::exit(1);
            }
        }
    }

    if unattended.is_none() {
        assert_interactive_terminal();
    }
    common.validate()?;

    let provided_tls = unattended
        .map(UnattendedSetupArgs::provided_tls)
        .transpose()?
        .flatten();

    let config_dir = config_dir(params);
    create_dir_all(config_dir)?;

    info!("Let's do some basic setup first.");
    info!(
        "The new config will be written in {}.",
        config_path.display()
    );

    let answers = match unattended {
        Some(args) => Answers::from_args(args, config_dir)?,
        None => Answers::interactive(common, config_dir)?,
    };

    let db_path = answers.data_path.join("db");
    create_dir_all(&db_path)?;
    if params.should_secure_files() {
        secure_directory(&db_path)?;
    }
    let store = answers.config(&db_path);

    info!("Generated configuration:");
    let yaml = yaml_serde::to_string(&store)?;
    println!("{yaml}");

    let yaml = format!(
        "# Config generated in version {version}\n# yaml-language-server: $schema=https://raw.githubusercontent.com/warp-tech/warpgate/refs/heads/main/config-schema.json\n\n{yaml}",
        version = warpgate_version()
    );

    File::create(config_path)?.write_all(yaml.as_bytes())?;
    info!("Saved into {}", config_path.display());

    let config = load_config(params, true)?;
    let db = connect_to_db_and_migrate(&config, params).await?;
    bootstrap_database(params, &config, &db, &answers, common, false).await?;
    install_tls(params, &config, provided_tls)?;

    info!("");
    info!("Admin user credentials:");
    info!("  * Username: admin");
    info!("  * Password: <your password>");
    info!("");
    info!("You can now start Warpgate with:");
    if is_docker() {
        info!(
            "docker run -p 8888:8888 -p 2222:2222 -it -v <your data dir>:/data ghcr.io/warp-tech/warpgate"
        );
    } else {
        info!(
            "  {} --config {} run",
            std::env::args()
                .next()
                .unwrap_or_else(|| "warpgate".to_string()),
            config_path.display()
        );
    }

    Ok(())
}

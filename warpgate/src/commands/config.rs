use std::path::{Path, PathBuf};
use std::process::exit;

use anyhow::Result;
use warpgate_common::encryption::{EncryptionError, validate_encryption_config};
use warpgate_common::{GlobalParams, ProviderId, WarpgateError, warnings};
use warpgate_core::db::{connect_to_db, has_pending_migrations};
use warpgate_core::resources::reconcile::load_current;
use warpgate_gitops::diagnostic::Diagnostic;
use warpgate_gitops::plan::{format_plan, format_plan_json, plan};
use warpgate_gitops::validate::check_files;
use warpgate_gitops::{format_json, format_text, json_schema, read_files};

use crate::config::load_config;

#[derive(clap::Subcommand)]
pub enum ConfigCommand {
    /// Check resource files offline: syntax, fields, names and references.
    /// Exits with 1 if any are invalid, 2 if they cannot be read.
    Validate {
        /// Files, and directories to search for *.yaml and *.yml
        #[clap(required = true)]
        paths: Vec<PathBuf>,
        #[clap(long, value_enum, default_value_t)]
        format: OutputFormat,
    },
    /// Show what applying resource files would change in the database, without
    /// changing it. Exits with 0 if nothing would change, 3 if something
    /// would, 1 if a resource is invalid or collides with a row it may not change.
    Plan {
        /// Files, and directories to search for *.yaml and *.yml
        #[clap(required = true)]
        paths: Vec<PathBuf>,
        #[clap(long, value_enum, default_value_t)]
        format: OutputFormat,
    },
    /// Print the JSON schema of resource files
    Schema,
}

#[derive(Clone, Copy, Default, clap::ValueEnum)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

pub async fn command(command: &ConfigCommand, params: &GlobalParams) -> Result<()> {
    match command {
        ConfigCommand::Schema => {
            println!("{}", serde_json::to_string_pretty(&json_schema())?);
            Ok(())
        }
        ConfigCommand::Validate { paths, format } => validate(paths, *format),
        ConfigCommand::Plan { paths, format } => plan_command(params, paths, *format).await,
    }
}

fn read_or_exit(paths: &[PathBuf]) -> Vec<(PathBuf, String)> {
    match read_files(paths) {
        Ok(files) if files.is_empty() => {
            eprintln!("No .yaml or .yml files found");
            exit(2);
        }
        Ok(files) => files,
        Err(error) => {
            eprintln!("{error}");
            exit(2);
        }
    }
}

fn print_diagnostics(diagnostics: &[(&Path, Diagnostic)], format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Text => print!("{}", format_text(diagnostics)),
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&format_json(diagnostics))?
        ),
    }
    Ok(())
}

fn validate(paths: &[PathBuf], format: OutputFormat) -> Result<()> {
    let files = read_or_exit(paths);
    let diagnostics = check_files(&files).err().unwrap_or_default();
    print_diagnostics(&diagnostics, format)?;
    if !diagnostics.is_empty() {
        exit(1);
    }
    Ok(())
}

async fn plan_command(
    params: &GlobalParams,
    paths: &[PathBuf],
    format: OutputFormat,
) -> Result<()> {
    let files = read_or_exit(paths);
    let resources = match check_files(&files) {
        Ok(resources) => resources,
        Err(diagnostics) => {
            print_diagnostics(&diagnostics, format)?;
            exit(1);
        }
    };

    let config = load_config(params, false)?;
    validate_encryption_config(&config);
    for warning in warnings() {
        eprintln!("warning: {warning}");
    }

    let db = connect_to_db(&config, params).await?;
    if has_pending_migrations(&db).await? {
        eprintln!(
            "The database schema is older than this binary; start Warpgate once to migrate it, then plan again"
        );
        exit(1);
    }
    let current = match load_current(&db).await {
        Ok(current) => current,
        Err(WarpgateError::Encryption(error @ EncryptionError::NoKey { .. })) => {
            eprintln!(
                "{error}: stored credentials are encrypted, and comparing them needs the key"
            );
            exit(1);
        }
        Err(error) => return Err(error.into()),
    };

    let plan = plan(ProviderId::GITOPS, &resources, &current);
    match format {
        OutputFormat::Text => print!("{}", format_plan(&plan)),
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&format_plan_json(&plan))?
        ),
    }
    if plan.has_errors() {
        exit(1);
    }
    if plan.has_pending() {
        exit(3);
    }
    Ok(())
}

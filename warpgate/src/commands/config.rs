use std::path::PathBuf;
use std::process::exit;

use anyhow::Result;
use warpgate_gitops::validate::check_files;
use warpgate_gitops::{format_json, format_text, json_schema, read_files};

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
    /// Print the JSON schema of resource files
    Schema,
}

#[derive(Clone, Copy, Default, clap::ValueEnum)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

pub fn command(command: &ConfigCommand) -> Result<()> {
    match command {
        ConfigCommand::Schema => {
            println!("{}", serde_json::to_string_pretty(&json_schema())?);
            Ok(())
        }
        ConfigCommand::Validate { paths, format } => validate(paths, *format),
    }
}

fn validate(paths: &[PathBuf], format: OutputFormat) -> Result<()> {
    let files = match read_files(paths) {
        Ok(files) if files.is_empty() => {
            eprintln!("No .yaml or .yml files found");
            exit(2);
        }
        Ok(files) => files,
        Err(error) => {
            eprintln!("{error}");
            exit(2);
        }
    };

    let diagnostics = check_files(&files);
    match format {
        OutputFormat::Text => print!("{}", format_text(&diagnostics)),
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&format_json(&diagnostics))?
        ),
    }

    if !diagnostics.is_empty() {
        exit(1);
    }
    Ok(())
}

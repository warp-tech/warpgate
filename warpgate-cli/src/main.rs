use anyhow::Result;
use clap::{Parser, Subcommand};
use warpgate_common::hash::hash_password;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Hash,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Hash => {
            let input: String = dialoguer::Password::new()
                .with_prompt("Password to be hashed")
                .interact()?;

            let hash = hash_password(&input);
            println!("{}", hash);
        }
    }

    Ok(())
}

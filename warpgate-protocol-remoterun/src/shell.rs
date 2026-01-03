//! Shell execution mode for RemoteRun targets.
//!
//! Executes a shell command on the host machine or via a jump host.

use anyhow::Result;
use tokio::process::Command;
use tracing::{info, warn};
use warpgate_common::RemoteRunShellOptions;
use warpgate_core::Services;

/// Execute a shell command for a RemoteRun session.
pub async fn execute(_services: &Services, opts: &RemoteRunShellOptions) -> Result<()> {
    info!(command = %opts.command, jump_host = ?opts.jump_host, "Executing shell command");

    let mut cmd = if cfg!(target_os = "windows") {
        let mut c = Command::new("cmd");
        c.args(["/C", &opts.command]);
        c
    } else {
        let mut c = Command::new("sh");
        c.args(["-c", &opts.command]);
        c
    };

    // If there's a jump host, we might need to modify the command
    // For now, we expect the command itself to include any jump host config
    if let Some(ref jump_host) = opts.jump_host {
        info!(jump_host = %jump_host, "Using jump host (expected in command)");
    }

    let status = cmd.status().await?;

    if status.success() {
        info!("Shell command completed successfully");
        Ok(())
    } else {
        let code = status.code().unwrap_or(-1);
        warn!(exit_code = code, "Shell command failed");
        anyhow::bail!("Shell command exited with code {}", code)
    }
}

/// Test that the shell command configuration is valid.
pub async fn test_connection(opts: &RemoteRunShellOptions) -> Result<()> {
    // Basic validation - ensure command is not empty
    if opts.command.trim().is_empty() {
        anyhow::bail!("Shell command cannot be empty");
    }

    // Test that the shell is available
    let test_cmd = if cfg!(target_os = "windows") {
        Command::new("cmd").args(["/C", "echo ok"]).output().await?
    } else {
        Command::new("sh").args(["-c", "echo ok"]).output().await?
    };

    if !test_cmd.status.success() {
        anyhow::bail!("Shell is not available or not working");
    }

    info!(command = %opts.command, "Shell command configuration validated");
    Ok(())
}

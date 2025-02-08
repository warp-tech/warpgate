use std::io::IsTerminal;

use tracing::*;

pub(crate) fn assert_interactive_terminal() {
    if !std::io::stdin().is_terminal() {
        error!("Please run this command from an interactive terminal.");
        if is_docker() {
            info!("(have you forgotten `-it`?)");
        }
        std::process::exit(1);
    }
}

pub(crate) fn is_docker() -> bool {
    std::env::var("DOCKER").is_ok()
}

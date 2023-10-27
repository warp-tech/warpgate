use tracing::*;
use std::path::Path;

pub(crate) fn assert_interactive_terminal() {
    if !atty::is(atty::Stream::Stdin) {
        error!("Please run this command from an interactive terminal.");
        if is_docker() {
            info!("(have you forgotten `-it`?)");
        }
        std::process::exit(1);
    }
}

pub(crate) fn is_docker() -> bool {
    Path::new("/.dockerenv").exists()
}
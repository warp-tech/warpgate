/// Config warnings that show up in the admin UI
///
use std::sync::{LazyLock, Mutex};

use tracing::warn;

static CONFIG_WARNINGS: LazyLock<Mutex<Vec<String>>> = LazyLock::new(|| Mutex::new(vec![]));
static RUNTIME_WARNINGS: LazyLock<Mutex<Vec<String>>> = LazyLock::new(|| Mutex::new(vec![]));

fn push(store: &Mutex<Vec<String>>, message: String) {
    warn!("{message}");
    if let Ok(mut warnings) = store.lock()
        && !warnings.contains(&message)
    {
        warnings.push(message);
    }
}

/// Warning that are caused by config file contents
pub fn emit_config_warning(message: String) {
    push(&CONFIG_WARNINGS, message);
}

/// Warning that are caused by something else unrelated to config loading
pub fn emit_runtime_warning(message: String) {
    push(&RUNTIME_WARNINGS, message);
}

pub fn warnings() -> Vec<String> {
    let mut warnings = CONFIG_WARNINGS
        .lock()
        .map(|w| w.clone())
        .unwrap_or_default();
    warnings.extend(
        RUNTIME_WARNINGS
            .lock()
            .map(|w| w.clone())
            .unwrap_or_default(),
    );
    warnings
}

pub fn clear_config_warnings() {
    if let Ok(mut warnings) = CONFIG_WARNINGS.lock() {
        warnings.clear();
    }
}

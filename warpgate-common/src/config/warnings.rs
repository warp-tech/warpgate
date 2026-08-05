use std::sync::{LazyLock, Mutex};

use tracing::warn;

static WARNINGS: LazyLock<Mutex<Vec<String>>> = LazyLock::new(|| Mutex::new(vec![]));

/// Config warnings show up in the admin UI
pub fn emit_config_warning(message: String) {
    warn!("{message}");
    if let Ok(mut warnings) = WARNINGS.lock()
        && !warnings.contains(&message)
    {
        warnings.push(message);
    }
}

pub fn config_warnings() -> Vec<String> {
    WARNINGS.lock().map(|w| w.clone()).unwrap_or_default()
}

pub fn clear_config_warnings() {
    if let Ok(mut warnings) = WARNINGS.lock() {
        warnings.clear();
    }
}

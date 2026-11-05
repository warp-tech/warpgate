mod database;
mod json_console;
pub(crate) mod layer;
#[cfg(unix)]
mod socket;
#[cfg(windows)]
mod socket_windows;
mod values;

pub use database::{format_related_ids, install_database_logger, make_database_logger_layer};
pub use json_console::make_json_console_logger_layer;
#[cfg(unix)]
pub use socket::make_socket_logger_layer;
#[cfg(windows)]
pub use socket_windows::make_socket_logger_layer;
pub use warpgate_common::audit::{AuditEvent, CredentialChangedVia, KubernetesAuditSubject};

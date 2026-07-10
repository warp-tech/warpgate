use std::collections::HashMap;
use std::sync::Arc;

use poem_openapi::{Enum, Object};
use time::OffsetDateTime;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Enum)]
pub enum ListenerState {
    Disabled,
    Listening,
    BindFailed,
}

#[derive(Debug, Clone, Object)]
pub struct TlsCertificateInfo {
    /// SAN DNS/IP names and the CN of the leaf certificate.
    pub domains: Vec<String>,
    pub expiry: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Object)]
pub struct ListenerStatus {
    pub name: String,
    pub state: ListenerState,
    pub address: String,
    pub error: Option<String>,
    /// The first certificate is the primary one; the rest are SNI certificates.
    pub certificates: Vec<TlsCertificateInfo>,
}

pub type ListenerStatusRegistry = Arc<Mutex<HashMap<String, ListenerStatus>>>;

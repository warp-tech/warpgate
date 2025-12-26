use poem_openapi::Enum;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, Copy, Enum, PartialEq, Eq, Default)]
pub enum TlsMode {
    #[serde(rename = "disabled")]
    #[oai(rename = "disabled")]
    Disabled,
    #[serde(rename = "preferred")]
    #[oai(rename = "preferred")]
    #[default]
    Preferred,
    #[serde(rename = "required")]
    #[oai(rename = "required")]
    Required,
}

impl From<&str> for TlsMode {
    fn from(s: &str) -> Self {
        match s {
            "disabled" => TlsMode::Disabled,
            "preferred" => TlsMode::Preferred,
            "required" => TlsMode::Required,
            _ => TlsMode::Preferred,
        }
    }
}

impl From<TlsMode> for String {
    fn from(mode: TlsMode) -> Self {
        match mode {
            TlsMode::Disabled => "disabled".to_string(),
            TlsMode::Preferred => "preferred".to_string(),
            TlsMode::Required => "required".to_string(),
        }
    }
}

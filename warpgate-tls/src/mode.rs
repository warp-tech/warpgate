use poem_openapi::Enum;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, Copy, Enum, PartialEq, Eq, Default)]
pub enum TlsMode {
    #[serde(rename = "disabled")]
    Disabled,
    #[serde(rename = "preferred")]
    #[default]
    Preferred,
    #[serde(rename = "required")]
    Required,
}

impl From<&str> for TlsMode {
    fn from(s: &str) -> Self {
        match s {
            "Disabled" => TlsMode::Disabled,
            "Preferred" => TlsMode::Preferred,
            "Required" => TlsMode::Required,
            _ => TlsMode::Preferred,
        }
    }
}

impl From<TlsMode> for String {
    fn from(mode: TlsMode) -> Self {
        match mode {
            TlsMode::Disabled => "Disabled".to_string(),
            TlsMode::Preferred => "Preferred".to_string(),
            TlsMode::Required => "Required".to_string(),
        }
    }
}

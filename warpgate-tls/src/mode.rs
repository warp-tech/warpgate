use poem_openapi::Enum;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, Copy, Enum, PartialEq, Eq, Default)]
pub enum TlsMode {
    Disabled,
    #[default]
    Preferred,
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

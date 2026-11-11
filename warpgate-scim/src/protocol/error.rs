//! The SCIM error envelope (RFC 7644 §3.12).

use serde_json::{Value, json};
use warpgate_common::WarpgateError;

use super::resource::SCHEMA_ERROR;

/// The `scimType` of a 400/409 response, naming what was wrong with the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScimType {
    InvalidFilter,
    TooMany,
    Uniqueness,
    Mutability,
    InvalidSyntax,
    InvalidPath,
    NoTarget,
    InvalidValue,
    InvalidVers,
    Sensitive,
}

impl ScimType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidFilter => "invalidFilter",
            Self::TooMany => "tooMany",
            Self::Uniqueness => "uniqueness",
            Self::Mutability => "mutability",
            Self::InvalidSyntax => "invalidSyntax",
            Self::InvalidPath => "invalidPath",
            Self::NoTarget => "noTarget",
            Self::InvalidValue => "invalidValue",
            Self::InvalidVers => "invalidVers",
            Self::Sensitive => "sensitive",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ScimError {
    /// A client error, rendered as the SCIM error envelope.
    #[error("{detail}")]
    Protocol {
        status: u16,
        scim_type: Option<ScimType>,
        detail: String,
    },
    /// A server-side failure; the HTTP layer hands it to the gateway's error
    /// renderer so it is logged with a correlation id and never leaks detail.
    #[error(transparent)]
    Internal(#[from] WarpgateError),
}

impl From<sea_orm::DbErr> for ScimError {
    fn from(err: sea_orm::DbErr) -> Self {
        Self::Internal(err.into())
    }
}

impl ScimError {
    pub fn bad_request(scim_type: ScimType, detail: impl Into<String>) -> Self {
        Self::Protocol {
            status: 400,
            scim_type: Some(scim_type),
            detail: detail.into(),
        }
    }

    pub fn invalid_syntax(detail: impl Into<String>) -> Self {
        Self::bad_request(ScimType::InvalidSyntax, detail)
    }

    pub fn invalid_value(detail: impl Into<String>) -> Self {
        Self::bad_request(ScimType::InvalidValue, detail)
    }

    pub fn invalid_filter(detail: impl Into<String>) -> Self {
        Self::bad_request(ScimType::InvalidFilter, detail)
    }

    pub fn invalid_path(detail: impl Into<String>) -> Self {
        Self::bad_request(ScimType::InvalidPath, detail)
    }

    pub fn mutability(detail: impl Into<String>) -> Self {
        Self::bad_request(ScimType::Mutability, detail)
    }

    pub fn no_target(detail: impl Into<String>) -> Self {
        Self::bad_request(ScimType::NoTarget, detail)
    }

    pub fn unauthorized() -> Self {
        Self::Protocol {
            status: 401,
            scim_type: None,
            detail: "a valid bearer token is required".into(),
        }
    }

    pub fn not_found(detail: impl Into<String>) -> Self {
        Self::Protocol {
            status: 404,
            scim_type: None,
            detail: detail.into(),
        }
    }

    pub fn conflict(detail: impl Into<String>) -> Self {
        Self::Protocol {
            status: 409,
            scim_type: Some(ScimType::Uniqueness),
            detail: detail.into(),
        }
    }

    pub fn not_implemented(detail: impl Into<String>) -> Self {
        Self::Protocol {
            status: 501,
            scim_type: None,
            detail: detail.into(),
        }
    }

    /// The envelope body, for the `Protocol` case.
    pub fn to_json(&self) -> Value {
        match self {
            Self::Protocol {
                status,
                scim_type,
                detail,
            } => {
                let mut body = json!({
                    "schemas": [SCHEMA_ERROR],
                    "status": status.to_string(),
                    "detail": detail,
                });
                if let (Some(scim_type), Some(object)) = (scim_type, body.as_object_mut()) {
                    object.insert("scimType".into(), json!(scim_type.as_str()));
                }
                body
            }
            Self::Internal(_) => json!({
                "schemas": [SCHEMA_ERROR],
                "status": "500",
                "detail": "internal error",
            }),
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn envelope_carries_status_as_a_string_and_the_scim_type() {
        let body = ScimError::conflict("userName taken").to_json();
        assert_eq!(body["schemas"][0], SCHEMA_ERROR);
        assert_eq!(body["status"], "409");
        assert_eq!(body["scimType"], "uniqueness");
        assert_eq!(body["detail"], "userName taken");

        let body = ScimError::not_found("no such user").to_json();
        assert_eq!(body["status"], "404");
        assert!(body.get("scimType").is_none());
    }

    #[test]
    fn internal_errors_do_not_leak_their_cause() {
        let body = ScimError::Internal(WarpgateError::InconsistentState("secret".into())).to_json();
        assert_eq!(body["status"], "500");
        assert_eq!(body["detail"], "internal error");
    }
}

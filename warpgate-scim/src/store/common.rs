use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use warpgate_db_entities::UserRoleAssignment;

use crate::protocol::ScimError;
use crate::protocol::resource::{attr_get, attr_key};

/// The largest `scim_attributes` document a user may carry; a bound on what an
/// identity provider can make Warpgate store per user.
pub const MAX_ATTRIBUTES_BYTES: usize = 64 * 1024;

/// `created` / `lastModified` for a resource's `meta`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScimTimestamps {
    pub created: Option<OffsetDateTime>,
    pub last_modified: Option<OffsetDateTime>,
}

impl ScimTimestamps {
    /// `lastModified` is the later of the row's own update and any change to
    /// its role assignments, so a membership change moves it without a write
    /// to the row.
    pub fn new<'a>(
        created_at: Option<OffsetDateTime>,
        updated_at: Option<OffsetDateTime>,
        assignments: impl IntoIterator<Item = &'a UserRoleAssignment::Model>,
    ) -> Self {
        let mut last_modified = updated_at;
        for assignment in assignments {
            for stamp in [assignment.granted_at, assignment.revoked_at] {
                if stamp > last_modified {
                    last_modified = stamp;
                }
            }
        }
        Self {
            created: created_at,
            last_modified,
        }
    }

    pub fn meta(self, resource_type: &str, location: &str) -> Value {
        let mut meta = json!({
            "resourceType": resource_type,
            "location": location,
        });
        if let Some(object) = meta.as_object_mut() {
            if let Some(created) = self.created {
                object.insert("created".into(), json!(rfc3339(created)));
            }
            if let Some(last_modified) = self.last_modified {
                object.insert("lastModified".into(), json!(rfc3339(last_modified)));
            }
        }
        meta
    }
}

/// RFC 3339 in UTC with exactly three fractional digits, so two timestamps
/// compare correctly as strings: filters and `sortBy` compare them that way,
/// and the well-known formatter would otherwise print a variable-length
/// fraction (`.5Z` sorts after `.123Z`).
pub fn rfc3339(time: OffsetDateTime) -> String {
    const FORMAT: &[time::format_description::BorrowedFormatItem<'static>] = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
    );
    time.to_offset(time::UtcOffset::UTC)
        .format(FORMAT)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::rfc3339;

    #[test]
    fn timestamps_have_a_fixed_width_fraction_in_utc() {
        assert_eq!(
            rfc3339(datetime!(2026-11-02 04:16:07.5 +00:00)),
            "2026-11-02T04:16:07.500Z"
        );
        assert_eq!(
            rfc3339(datetime!(2026-11-02 06:16:07.123456 +02:00)),
            "2026-11-02T04:16:07.123Z"
        );
        assert_eq!(
            rfc3339(datetime!(2026-11-02 04:16:07 +00:00)),
            "2026-11-02T04:16:07.000Z"
        );
    }
}

/// The request body as an object, or `invalidSyntax`.
pub fn body_object(body: &Value) -> Result<&Map<String, Value>, ScimError> {
    body.as_object()
        .ok_or_else(|| ScimError::invalid_syntax("the resource must be a JSON object"))
}

/// An optional string attribute; `null` and `""` both mean unset.
pub fn optional_string(body: &Value, name: &str) -> Result<Option<String>, ScimError> {
    match attr_get(body, name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(ScimError::invalid_value(format!("{name} must be a string"))),
    }
}

/// A boolean attribute, also accepting the strings `"true"`/`"false"` that
/// Entra ID sends for `active`.
pub fn optional_bool(body: &Value, name: &str) -> Result<Option<bool>, ScimError> {
    match attr_get(body, name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(Value::String(s)) if s.eq_ignore_ascii_case("true") => Ok(Some(true)),
        Some(Value::String(s)) if s.eq_ignore_ascii_case("false") => Ok(Some(false)),
        Some(_) => Err(ScimError::invalid_value(format!(
            "{name} must be a boolean"
        ))),
    }
}

/// `body` without the attributes `reserved` names (case-insensitively).
pub fn without(body: &Map<String, Value>, reserved: &[&str]) -> Map<String, Value> {
    let mut rest = body.clone();
    for name in reserved {
        if let Some(key) = attr_key(&rest, name).map(str::to_owned) {
            rest.remove(&key);
        }
    }
    rest
}

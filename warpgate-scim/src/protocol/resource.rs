//! Schema URNs and the attribute helpers every other module relies on.
//!
//! SCIM attribute names are case-insensitive (RFC 7643 §2.1), so every lookup
//! into a resource goes through [`attr_get`] and friends rather than indexing
//! the JSON map directly.

use serde_json::{Map, Value, json};

pub const SCHEMA_USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const SCHEMA_GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
pub const SCHEMA_ENTERPRISE_USER: &str =
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
pub const SCHEMA_LIST_RESPONSE: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
pub const SCHEMA_PATCH_OP: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
pub const SCHEMA_SEARCH_REQUEST: &str = "urn:ietf:params:scim:api:messages:2.0:SearchRequest";
pub const SCHEMA_ERROR: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
pub const SCHEMA_SERVICE_PROVIDER_CONFIG: &str =
    "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
pub const SCHEMA_RESOURCE_TYPE: &str = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";
pub const SCHEMA_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Schema";

/// The core schemas, whose attributes live at the top level of a resource.
/// Attributes of any other schema live under a key named after it.
pub const fn is_core_schema(urn: &str) -> bool {
    urn.eq_ignore_ascii_case(SCHEMA_USER) || urn.eq_ignore_ascii_case(SCHEMA_GROUP)
}

/// The key under which `name` is stored, if any, compared case-insensitively.
pub fn attr_key<'a>(object: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    object
        .keys()
        .find(|key| key.eq_ignore_ascii_case(name))
        .map(String::as_str)
}

pub fn attr_get<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    let object = value.as_object()?;
    attr_key(object, name).and_then(|key| object.get(key))
}

pub fn attr_get_mut<'a>(value: &'a mut Value, name: &str) -> Option<&'a mut Value> {
    let object = value.as_object_mut()?;
    let key = attr_key(object, name)?.to_owned();
    object.get_mut(&key)
}

/// Sets `name`, keeping the spelling of an existing key.
pub fn attr_set(value: &mut Value, name: &str, new: Value) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    let key = attr_key(object, name).map_or_else(|| name.to_owned(), str::to_owned);
    object.insert(key, new);
}

pub fn attr_remove(value: &mut Value, name: &str) -> Option<Value> {
    let object = value.as_object_mut()?;
    let key = attr_key(object, name)?.to_owned();
    object.remove(&key)
}

/// `attr_get` as an owned string, for the attributes the store maps to columns.
pub fn attr_str<'a>(value: &'a Value, name: &str) -> Option<&'a str> {
    attr_get(value, name).and_then(Value::as_str)
}

/// Whether a value counts as present for the `pr` operator (RFC 7644
/// §3.4.2.2): non-null, and non-empty for strings, arrays and objects.
pub fn is_present(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
        Value::Bool(_) | Value::Number(_) => true,
    }
}

/// A `ListResponse` (RFC 7644 §3.4.2).
pub fn list_response(resources: &[Value], total_results: usize, start_index: usize) -> Value {
    json!({
        "schemas": [SCHEMA_LIST_RESPONSE],
        "totalResults": total_results,
        "startIndex": start_index,
        "itemsPerPage": resources.len(),
        "Resources": resources,
    })
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn attribute_lookups_ignore_case_and_keep_the_stored_spelling() {
        let mut user = json!({"userName": "alice", "Name": {"givenName": "Alice"}});
        assert_eq!(attr_get(&user, "USERNAME"), Some(&json!("alice")));
        assert_eq!(attr_str(&user, "username"), Some("alice"));
        assert!(attr_get(&user, "missing").is_none());
        assert!(attr_get(&json!("not an object"), "x").is_none());

        attr_set(&mut user, "username", json!("bob"));
        assert_eq!(
            user,
            json!({"userName": "bob", "Name": {"givenName": "Alice"}})
        );
        attr_set(&mut user, "active", json!(true));
        assert_eq!(user["active"], true);

        *attr_get_mut(&mut user, "NAME").unwrap() = json!({});
        assert_eq!(user["Name"], json!({}));
        assert_eq!(attr_remove(&mut user, "name"), Some(json!({})));
        assert!(attr_get(&user, "name").is_none());
    }

    #[test]
    fn presence_follows_the_spec() {
        assert!(!is_present(&Value::Null));
        assert!(!is_present(&json!("")));
        assert!(!is_present(&json!([])));
        assert!(!is_present(&json!({})));
        assert!(is_present(&json!(false)));
        assert!(is_present(&json!(0)));
        assert!(is_present(&json!("x")));
        assert!(is_present(&json!([1])));
    }

    #[test]
    fn list_response_counts_the_page_not_the_total() {
        let body = list_response(&[json!({"id": "1"})], 10, 4);
        assert_eq!(body["schemas"][0], SCHEMA_LIST_RESPONSE);
        assert_eq!(body["totalResults"], 10);
        assert_eq!(body["startIndex"], 4);
        assert_eq!(body["itemsPerPage"], 1);
        assert_eq!(body["Resources"].as_array().unwrap().len(), 1);
    }
}

//! PATCH (RFC 7644 §3.5.2) applied to a resource's JSON form.
//!
//! The engine edits the JSON only; the store validates and persists the result.
//! Beyond the RFC it accepts what real identity providers send: capitalised
//! operation names, a path-less `value` object (Okta), `remove` of a
//! multi-valued attribute with the elements to drop in `value` (Okta), and
//! value filters on `members` (Entra ID).

use serde_json::{Map, Value};

use super::error::ScimError;
use super::filter::AttrPath;
use super::resource::{attr_get, attr_get_mut, attr_remove, attr_set};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchOp {
    Add,
    Remove,
    Replace,
}

#[derive(Debug, Clone)]
pub struct PatchOperation {
    pub op: PatchOp,
    pub path: Option<AttrPath>,
    pub value: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct PatchRequest {
    pub operations: Vec<PatchOperation>,
}

impl PatchRequest {
    pub fn parse(body: &Value) -> Result<Self, ScimError> {
        let Some(operations) = attr_get(body, "Operations").and_then(Value::as_array) else {
            return Err(ScimError::invalid_syntax(
                "a PatchOp must carry an Operations array",
            ));
        };
        if operations.is_empty() {
            return Err(ScimError::invalid_value("Operations is empty"));
        }
        let operations = operations
            .iter()
            .map(PatchOperation::parse)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { operations })
    }
}

impl PatchOperation {
    fn parse(value: &Value) -> Result<Self, ScimError> {
        let op = match attr_get(value, "op").and_then(Value::as_str) {
            Some(op) if op.eq_ignore_ascii_case("add") => PatchOp::Add,
            Some(op) if op.eq_ignore_ascii_case("remove") => PatchOp::Remove,
            Some(op) if op.eq_ignore_ascii_case("replace") => PatchOp::Replace,
            Some(op) => {
                return Err(ScimError::invalid_value(format!(
                    "unknown PATCH operation {op:?}"
                )));
            }
            None => return Err(ScimError::invalid_syntax("a PATCH operation needs an op")),
        };
        let path = match attr_get(value, "path") {
            None | Some(Value::Null) => None,
            Some(Value::String(path)) => Some(AttrPath::parse(path)?),
            Some(_) => return Err(ScimError::invalid_path("path must be a string")),
        };
        let value = attr_get(value, "value").cloned();
        if op != PatchOp::Remove && value.is_none() {
            return Err(ScimError::invalid_value(
                "add and replace operations need a value",
            ));
        }
        Ok(Self { op, path, value })
    }
}

/// Applies every operation in order; the first failure aborts and leaves
/// `resource` partially modified, so callers must work on a copy.
/// `read_only` names the top-level attributes the client may not change.
pub fn apply_patch(
    resource: &mut Value,
    request: &PatchRequest,
    read_only: &[&str],
) -> Result<(), ScimError> {
    for operation in &request.operations {
        apply_one(resource, operation, read_only)?;
    }
    Ok(())
}

fn is_read_only(read_only: &[&str], name: &str) -> bool {
    read_only.iter().any(|attr| attr.eq_ignore_ascii_case(name))
}

fn apply_one(
    resource: &mut Value,
    operation: &PatchOperation,
    read_only: &[&str],
) -> Result<(), ScimError> {
    match (&operation.path, operation.op) {
        (None, PatchOp::Remove) => Err(ScimError::no_target("remove needs a path")),
        (None, op) => {
            let Some(Value::Object(values)) = &operation.value else {
                return Err(ScimError::invalid_value(
                    "a path-less operation needs an object value",
                ));
            };
            for (name, value) in values {
                // The envelope's own key, never an attribute.
                if name.eq_ignore_ascii_case("schemas") {
                    continue;
                }
                if is_read_only(read_only, name) {
                    // Echoing an unchanged read-only value back is harmless.
                    if attr_get(resource, name) == Some(value) {
                        continue;
                    }
                    return Err(ScimError::mutability(format!("{name} is read-only")));
                }
                match op {
                    PatchOp::Add => {
                        add_attr(resource, name, value.clone());
                    }
                    _ => replace_attr(resource, name, value.clone()),
                }
            }
            Ok(())
        }
        (Some(path), op) => {
            if path.schema.is_none() && is_read_only(read_only, &path.attr) {
                return Err(ScimError::mutability(format!("{} is read-only", path.attr)));
            }
            if path.schema.is_none() && path.attr.eq_ignore_ascii_case("schemas") {
                return Err(ScimError::mutability("schemas is read-only"));
            }
            let container = container_for(resource, path, op != PatchOp::Remove)?;
            let Some(container) = container else {
                // Removing from an absent extension is a no-op.
                return Ok(());
            };
            match &path.value_filter {
                None => apply_plain(container, path, op, operation.value.as_ref()),
                Some(filter) => {
                    apply_filtered(container, path, filter, op, operation.value.as_ref())
                }
            }
        }
    }
}

/// The object holding the path's attribute: the resource itself, or the
/// extension object (created on demand when writing).
fn container_for<'a>(
    resource: &'a mut Value,
    path: &AttrPath,
    create: bool,
) -> Result<Option<&'a mut Value>, ScimError> {
    let Some(schema) = &path.schema else {
        return Ok(Some(resource));
    };
    if attr_get(resource, schema).is_none() {
        if !create {
            return Ok(None);
        }
        attr_set(resource, schema, Value::Object(Map::default()));
    }
    let extension = attr_get_mut(resource, schema)
        .ok_or_else(|| ScimError::invalid_path(format!("{schema} is not an object")))?;
    if !extension.is_object() {
        return Err(ScimError::invalid_path(format!(
            "{schema} is not an object"
        )));
    }
    Ok(Some(extension))
}

fn apply_plain(
    container: &mut Value,
    path: &AttrPath,
    op: PatchOp,
    value: Option<&Value>,
) -> Result<(), ScimError> {
    match (&path.sub, op) {
        (None, PatchOp::Remove) => {
            match value {
                // Okta: `remove` of `members` with the elements to drop in `value`.
                Some(Value::Array(to_remove)) => {
                    if let Some(Value::Array(items)) = attr_get_mut(container, &path.attr) {
                        items.retain(|item| !to_remove.iter().any(|gone| same_element(item, gone)));
                    }
                }
                Some(gone @ Value::Object(_)) => {
                    if let Some(Value::Array(items)) = attr_get_mut(container, &path.attr) {
                        items.retain(|item| !same_element(item, gone));
                    }
                }
                _ => {
                    attr_remove(container, &path.attr);
                }
            }
            Ok(())
        }
        (None, PatchOp::Add) => {
            add_attr(container, &path.attr, value.cloned().unwrap_or(Value::Null));
            Ok(())
        }
        (None, PatchOp::Replace) => {
            replace_attr(container, &path.attr, value.cloned().unwrap_or(Value::Null));
            Ok(())
        }
        (Some(sub), op) => {
            if attr_get(container, &path.attr).is_none() {
                if op == PatchOp::Remove {
                    return Ok(());
                }
                attr_set(container, &path.attr, Value::Object(Map::default()));
            }
            let parent = attr_get_mut(container, &path.attr)
                .ok_or_else(|| ScimError::invalid_path(format!("{} is missing", path.attr)))?;
            match parent {
                Value::Object(_) => {
                    match op {
                        PatchOp::Remove => {
                            attr_remove(parent, sub);
                        }
                        PatchOp::Add => {
                            add_attr(parent, sub, value.cloned().unwrap_or(Value::Null));
                        }
                        PatchOp::Replace => {
                            replace_attr(parent, sub, value.cloned().unwrap_or(Value::Null));
                        }
                    }
                    Ok(())
                }
                // `emails.value` without a filter addresses every element.
                Value::Array(items) => {
                    for item in items.iter_mut().filter(|item| item.is_object()) {
                        match op {
                            PatchOp::Remove => {
                                attr_remove(item, sub);
                            }
                            PatchOp::Add => {
                                add_attr(item, sub, value.cloned().unwrap_or(Value::Null));
                            }
                            PatchOp::Replace => {
                                replace_attr(item, sub, value.cloned().unwrap_or(Value::Null));
                            }
                        }
                    }
                    Ok(())
                }
                _ => Err(ScimError::invalid_path(format!(
                    "{} has no sub-attributes",
                    path.attr
                ))),
            }
        }
    }
}

fn apply_filtered(
    container: &mut Value,
    path: &AttrPath,
    filter: &super::filter::Filter,
    op: PatchOp,
    value: Option<&Value>,
) -> Result<(), ScimError> {
    let Some(Value::Array(items)) = attr_get_mut(container, &path.attr) else {
        return match op {
            PatchOp::Remove => Ok(()),
            _ => Err(ScimError::no_target(format!(
                "{} has no element matching the filter",
                path.attr
            ))),
        };
    };
    let matched: Vec<usize> = items
        .iter()
        .enumerate()
        .filter(|(_, item)| item.is_object() && filter.matches(item))
        .map(|(i, _)| i)
        .collect();
    if matched.is_empty() {
        return match op {
            PatchOp::Remove => Ok(()),
            _ => Err(ScimError::no_target(format!(
                "{} has no element matching the filter",
                path.attr
            ))),
        };
    }
    match (&path.sub, op) {
        (None, PatchOp::Remove) => {
            let mut index = 0;
            items.retain(|_| {
                let keep = !matched.contains(&index);
                index += 1;
                keep
            });
        }
        (None, PatchOp::Replace) => {
            let Some(value) = value else {
                return Err(ScimError::invalid_value("replace needs a value"));
            };
            for item in items
                .iter_mut()
                .enumerate()
                .filter(|(i, _)| matched.contains(i))
            {
                *item.1 = value.clone();
            }
        }
        (None, PatchOp::Add) => {
            let Some(Value::Object(fields)) = value else {
                return Err(ScimError::invalid_value(
                    "adding to a filtered element needs an object value",
                ));
            };
            for (_, item) in items
                .iter_mut()
                .enumerate()
                .filter(|(i, _)| matched.contains(i))
            {
                for (name, field) in fields {
                    add_attr(item, name, field.clone());
                }
            }
        }
        (Some(sub), op) => {
            for (_, item) in items
                .iter_mut()
                .enumerate()
                .filter(|(i, _)| matched.contains(i))
            {
                match op {
                    PatchOp::Remove => {
                        attr_remove(item, sub);
                    }
                    PatchOp::Add => {
                        add_attr(item, sub, value.cloned().unwrap_or(Value::Null));
                    }
                    PatchOp::Replace => {
                        replace_attr(item, sub, value.cloned().unwrap_or(Value::Null));
                    }
                }
            }
        }
    }
    Ok(())
}

/// `add`: append to a multi-valued attribute (skipping elements already
/// there), merge into a complex one, otherwise set.
fn add_attr(container: &mut Value, name: &str, value: Value) {
    match (attr_get_mut(container, name), value) {
        (Some(Value::Array(items)), Value::Array(new)) => {
            for element in new {
                if !items.iter().any(|item| same_element(item, &element)) {
                    items.push(element);
                }
            }
        }
        (Some(Value::Array(items)), element) => {
            if !items.iter().any(|item| same_element(item, &element)) {
                items.push(element);
            }
        }
        (Some(Value::Object(_)), Value::Object(fields)) => {
            if let Some(existing) = attr_get_mut(container, name) {
                for (field, value) in fields {
                    add_attr(existing, &field, value);
                }
            }
        }
        (_, value) => attr_set(container, name, value),
    }
}

/// `replace`: a complex attribute has the given sub-attributes replaced, a
/// multi-valued one is replaced wholesale, anything else is set.
fn replace_attr(container: &mut Value, name: &str, value: Value) {
    match (attr_get_mut(container, name), value) {
        (Some(Value::Object(_)), Value::Object(fields)) => {
            if let Some(existing) = attr_get_mut(container, name) {
                for (field, value) in fields {
                    attr_set(existing, &field, value);
                }
            }
        }
        (_, value) => attr_set(container, name, value),
    }
}

/// Two multi-valued elements are the same when their `value` sub-attributes
/// match (case-insensitively), or when they are equal outright.
fn same_element(a: &Value, b: &Value) -> bool {
    match (attr_get(a, "value"), attr_get(b, "value")) {
        (Some(Value::String(a)), Some(Value::String(b))) => a.eq_ignore_ascii_case(b),
        (Some(a), Some(b)) => a == b,
        _ => a == b,
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic)]
mod tests {
    use serde_json::json;

    use super::*;

    const READ_ONLY: &[&str] = &["id", "meta", "groups"];

    fn user() -> Value {
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "u1",
            "userName": "alice",
            "active": true,
            "name": {"givenName": "Alice", "familyName": "Smith"},
            "emails": [
                {"value": "alice@work.example", "type": "work", "primary": true},
                {"value": "alice@home.example", "type": "home"}
            ],
            "groups": [{"value": "g1", "display": "ops"}]
        })
    }

    fn patched(resource: Value, operations: Value) -> Result<Value, ScimError> {
        let mut resource = resource;
        let request = PatchRequest::parse(&json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": operations,
        }))?;
        apply_patch(&mut resource, &request, READ_ONLY)?;
        Ok(resource)
    }

    fn scim_type(result: Result<Value, ScimError>) -> Option<super::super::ScimType> {
        match result {
            Err(ScimError::Protocol { scim_type, .. }) => scim_type,
            other => panic!("expected a protocol error, got {other:?}"),
        }
    }

    #[test]
    fn entra_replace_active_with_a_string_and_capitalised_op() {
        let user = patched(
            user(),
            json!([{"op": "Replace", "path": "active", "value": "False"}]),
        )
        .unwrap();
        assert_eq!(user["active"], "False");
    }

    #[test]
    fn okta_pathless_replace_object() {
        let user = patched(
            user(),
            json!([{"op": "replace", "value": {"active": false, "userName": "alice2", "id": "u1"}}]),
        )
        .unwrap();
        assert_eq!(user["active"], false);
        assert_eq!(user["userName"], "alice2");
    }

    #[test]
    fn read_only_attributes_cannot_change() {
        use super::super::ScimType;
        let result = patched(user(), json!([{"op": "replace", "value": {"id": "other"}}]));
        assert_eq!(scim_type(result), Some(ScimType::Mutability));
        let result = patched(
            user(),
            json!([{"op": "add", "path": "groups", "value": [{"value": "g2"}]}]),
        );
        assert_eq!(scim_type(result), Some(ScimType::Mutability));
        let result = patched(
            user(),
            json!([{"op": "replace", "path": "meta.created", "value": "x"}]),
        );
        assert_eq!(scim_type(result), Some(ScimType::Mutability));
        // Sending the envelope's `schemas` back is tolerated.
        patched(
            user(),
            json!([{"op": "replace", "value": {"schemas": ["x"], "active": true}}]),
        )
        .unwrap();
    }

    #[test]
    fn sub_attribute_paths_and_schema_prefixes() {
        let user = patched(
            user(),
            json!([
                {"op": "replace", "path": "name.givenName", "value": "Alicia"},
                {"op": "add", "path": "name.middleName", "value": "M"},
                {"op": "remove", "path": "name.familyName"},
                {"op": "replace", "path": "urn:ietf:params:scim:schemas:core:2.0:User:displayName", "value": "Alicia"},
                {"op": "add", "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department", "value": "ops"},
                {"op": "add", "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.value", "value": "m1"},
            ]),
        )
        .unwrap();
        assert_eq!(
            user["name"],
            json!({"givenName": "Alicia", "middleName": "M"})
        );
        assert_eq!(user["displayName"], "Alicia");
        assert_eq!(
            user["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],
            json!({"department": "ops", "manager": {"value": "m1"}})
        );
    }

    #[test]
    fn adding_to_an_absent_complex_attribute_creates_it() {
        let user = patched(
            json!({"userName": "a"}),
            json!([{"op": "add", "path": "name.givenName", "value": "A"}]),
        )
        .unwrap();
        assert_eq!(user["name"]["givenName"], "A");
        let user = patched(
            json!({"userName": "a"}),
            json!([{"op": "remove", "path": "name.givenName"}]),
        )
        .unwrap();
        assert!(user.get("name").is_none());
    }

    #[test]
    fn pathless_add_merges_and_pathless_replace_keeps_other_sub_attributes() {
        let user = patched(
            user(),
            json!([{"op": "add", "value": {"name": {"middleName": "M"}, "title": "Eng"}}]),
        )
        .unwrap();
        assert_eq!(
            user["name"],
            json!({"givenName": "Alice", "familyName": "Smith", "middleName": "M"})
        );
        assert_eq!(user["title"], "Eng");
        let user = patched(
            user,
            json!([{"op": "replace", "value": {"name": {"givenName": "Alicia"}}}]),
        )
        .unwrap();
        assert_eq!(user["name"]["givenName"], "Alicia");
        assert_eq!(user["name"]["familyName"], "Smith");
    }

    #[test]
    fn multi_valued_add_appends_without_duplicates() {
        let user = patched(
            user(),
            json!([{"op": "add", "path": "emails", "value": [
                {"value": "ALICE@work.example", "type": "work"},
                {"value": "alice@other.example", "type": "other"}
            ]}]),
        )
        .unwrap();
        let emails = user["emails"].as_array().unwrap();
        assert_eq!(emails.len(), 3);
        assert_eq!(emails[2]["value"], "alice@other.example");
        // A single element in `value` is appended too.
        let user = patched(
            user,
            json!([{"op": "add", "path": "emails", "value": {"value": "x@y", "type": "x"}}]),
        )
        .unwrap();
        assert_eq!(user["emails"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn entra_member_add_and_filtered_remove() {
        let group = json!({"id": "g1", "displayName": "ops", "members": [{"value": "u1"}]});
        let group = patched(
            group,
            json!([{"op": "Add", "path": "members", "value": [{"value": "u2"}, {"value": "u1"}]}]),
        )
        .unwrap();
        assert_eq!(group["members"], json!([{"value": "u1"}, {"value": "u2"}]));
        let group = patched(
            group,
            json!([{"op": "Remove", "path": "members[value eq \"u1\"]"}]),
        )
        .unwrap();
        assert_eq!(group["members"], json!([{"value": "u2"}]));
        // Removing an element that is not there is not an error.
        let group = patched(
            group,
            json!([{"op": "remove", "path": "members[value eq \"nobody\"]"}]),
        )
        .unwrap();
        assert_eq!(group["members"], json!([{"value": "u2"}]));
        // Removing from a group with no members at all is fine too.
        patched(
            json!({"id": "g"}),
            json!([{"op": "remove", "path": "members[value eq \"u\"]"}]),
        )
        .unwrap();
    }

    #[test]
    fn okta_member_remove_with_value_and_replace_all() {
        let group = json!({"id": "g1", "members": [{"value": "u1"}, {"value": "u2"}]});
        let group = patched(
            group,
            json!([{"op": "remove", "path": "members", "value": [{"value": "u1"}]}]),
        )
        .unwrap();
        assert_eq!(group["members"], json!([{"value": "u2"}]));
        let group = patched(
            group,
            json!([{"op": "replace", "path": "members", "value": [{"value": "u3"}]}]),
        )
        .unwrap();
        assert_eq!(group["members"], json!([{"value": "u3"}]));
        let group = patched(group, json!([{"op": "replace", "value": {"members": []}}])).unwrap();
        assert_eq!(group["members"], json!([]));
        let group = patched(group, json!([{"op": "remove", "path": "members"}])).unwrap();
        assert!(group.get("members").is_none());
    }

    #[test]
    fn filtered_replace_and_sub_attribute_updates() {
        use super::super::ScimType;
        let user = patched(user(), json!([{"op": "replace", "path": "emails[type eq \"work\"].value", "value": "new@work.example"}])).unwrap();
        assert_eq!(user["emails"][0]["value"], "new@work.example");
        let user = patched(user, json!([{"op": "replace", "path": "emails[type eq \"home\"]", "value": {"value": "h@h", "type": "home"}}])).unwrap();
        assert_eq!(user["emails"][1], json!({"value": "h@h", "type": "home"}));
        let user = patched(
            user,
            json!([{"op": "add", "path": "emails[type eq \"home\"]", "value": {"primary": false}}]),
        )
        .unwrap();
        assert_eq!(user["emails"][1]["primary"], false);
        let user = patched(
            user,
            json!([{"op": "remove", "path": "emails[type eq \"home\"].primary"}]),
        )
        .unwrap();
        assert!(user["emails"][1].get("primary").is_none());
        let result = patched(
            user,
            json!([{"op": "replace", "path": "emails[type eq \"nope\"].value", "value": "x"}]),
        );
        assert_eq!(scim_type(result), Some(ScimType::NoTarget));
    }

    #[test]
    fn sub_attribute_without_filter_addresses_every_element() {
        let user = patched(
            user(),
            json!([{"op": "replace", "path": "emails.type", "value": "any"}]),
        )
        .unwrap();
        assert!(
            user["emails"]
                .as_array()
                .unwrap()
                .iter()
                .all(|e| e["type"] == "any")
        );
    }

    #[test]
    fn malformed_requests() {
        use super::super::ScimType;
        assert_eq!(
            scim_type(patched(user(), json!([]))),
            Some(ScimType::InvalidValue)
        );
        assert_eq!(
            scim_type(patched(user(), json!([{"path": "active", "value": true}]))),
            Some(ScimType::InvalidSyntax)
        );
        assert_eq!(
            scim_type(patched(user(), json!([{"op": "delete", "path": "active"}]))),
            Some(ScimType::InvalidValue)
        );
        assert_eq!(
            scim_type(patched(user(), json!([{"op": "remove"}]))),
            Some(ScimType::NoTarget)
        );
        assert_eq!(
            scim_type(patched(user(), json!([{"op": "add", "path": "title"}]))),
            Some(ScimType::InvalidValue)
        );
        assert_eq!(
            scim_type(patched(user(), json!([{"op": "add", "value": "scalar"}]))),
            Some(ScimType::InvalidValue)
        );
        assert_eq!(
            scim_type(patched(
                user(),
                json!([{"op": "add", "path": "bad path", "value": 1}])
            )),
            Some(ScimType::InvalidPath)
        );
        assert_eq!(
            scim_type(patched(
                user(),
                json!([{"op": "add", "path": 5, "value": 1}])
            )),
            Some(ScimType::InvalidPath)
        );
        assert_eq!(
            scim_type(patched(
                user(),
                json!([{"op": "add", "path": "userName.x", "value": 1}])
            )),
            Some(ScimType::InvalidPath)
        );
        let no_ops = PatchRequest::parse(&json!({"schemas": []}));
        assert!(no_ops.is_err());
    }

    #[test]
    fn a_failed_operation_stops_the_sequence() {
        let mut resource = user();
        let request = PatchRequest::parse(&json!({"Operations": [
            {"op": "replace", "path": "title", "value": "first"},
            {"op": "replace", "path": "id", "value": "nope"},
            {"op": "replace", "path": "title", "value": "third"},
        ]}))
        .unwrap();
        assert!(apply_patch(&mut resource, &request, READ_ONLY).is_err());
        assert_eq!(resource["title"], "first");
    }
}

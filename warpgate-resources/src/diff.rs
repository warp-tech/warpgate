use std::collections::{BTreeSet, HashSet};

use serde::Serialize;
use serde_json::{Map, Value, json};
use uuid::Uuid;
use warpgate_common::{
    MaybeSecretRef, ProviderId, StoredSecrets, TargetOptions, public_key_of_pem,
};
use warpgate_db_entities::ProviderSync::PlannedField;

use crate::path::{Path, Segment};
use crate::types::{ResourceKind, RoleSpec, SshClientKeySpec, TargetGroupSpec, TargetSpec};

/// A row as it is in the database, with its references by name
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row<S> {
    pub id: Uuid,
    pub name: String,
    pub provider: Option<ProviderId>,
    pub live: S,
}

impl<S: Comparable> Row<S> {
    pub fn compared(&self) -> ComparableValues {
        self.live.compared().named(&self.name)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValueChange {
    Value {
        from: Value,
        to: Value,
    },
    /// The values of a credential are never part of a diff
    Credential,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldChange {
    pub path: Path,
    pub change: ValueChange,
}

impl From<&FieldChange> for PlannedField {
    fn from(field: &FieldChange) -> Self {
        let (credential, from, to) = match &field.change {
            ValueChange::Value { from, to } => (false, Some(from.clone()), Some(to.clone())),
            ValueChange::Credential => (true, None, None),
        };
        Self {
            path: field.path.to_string(),
            credential,
            from,
            to,
        }
    }
}

/// A row, or a resource, reduced to what the diff compares
pub struct ComparableValues {
    value: Value,
    credentials: HashSet<Path>,
}

impl ComparableValues {
    /// A spec with no references and no credentials
    pub fn plain<S: Serialize>(spec: &S) -> Self {
        Self::redacting(spec, spec)
    }

    /// A spec with no references. `redacted` is the same spec with its
    /// credentials blanked. Fields that differ between the two are
    /// credentials
    pub fn redacting<S: Serialize>(spec: &S, redacted: &S) -> Self {
        let value = to_value(spec);
        Self {
            credentials: differing_paths(&value, &to_value(redacted), &["spec"])
                .into_iter()
                .collect(),
            value: json!({ "spec": value }),
        }
    }

    /// A spec doesn't hold its resource's name
    #[must_use]
    pub fn named(mut self, name: &str) -> Self {
        if let Value::Object(object) = &mut self.value {
            object.insert("name".into(), Value::String(name.to_owned()));
        }
        self
    }

    /// The compared value at a JSON pointer, such as `/spec/private_key`
    pub fn pointer(&self, pointer: &str) -> Option<&Value> {
        self.value.pointer(pointer)
    }

    /// The non-empty fields of the spec, in key order and in a plan's format.
    /// They describe a new row, so they have no `from`
    pub fn contents(&self) -> Vec<PlannedField> {
        let mut fields = Vec::new();
        let spec = self.value.get("spec").unwrap_or(&Value::Null);
        let mut path = Path::keys(&["spec"]).0;
        diff(
            &Value::Null,
            spec,
            &mut path,
            &self.credentials,
            &mut fields,
        );
        fields
            .iter()
            .map(PlannedField::from)
            .filter(|field| field.credential || !field.to.as_ref().is_none_or(is_blank))
            .map(|field| PlannedField {
                from: None,
                ..field
            })
            .collect()
    }

    /// The fields in which `to` differs, in key order
    pub fn changes_to(&self, to: &Self) -> Vec<FieldChange> {
        let credentials = &self.credentials | &to.credentials;
        let mut fields = Vec::new();
        diff(
            &self.value,
            &to.value,
            &mut Vec::new(),
            &credentials,
            &mut fields,
        );
        fields
    }
}

/// A spec as the diff compares it, with its references as written
pub trait Comparable {
    fn compared(&self) -> ComparableValues;
}

impl Comparable for TargetGroupSpec {
    fn compared(&self) -> ComparableValues {
        ComparableValues::plain(self)
    }
}

impl Comparable for RoleSpec {
    fn compared(&self) -> ComparableValues {
        ComparableValues::plain(self)
    }
}

impl Comparable for SshClientKeySpec {
    fn compared(&self) -> ComparableValues {
        ComparableValues {
            value: json!({ "spec": { "private_key": key_identity(self), "is_default": self.is_default } }),
            credentials: HashSet::from([Path::keys(&["spec", "private_key"])]),
        }
    }
}

impl Comparable for TargetSpec {
    fn compared(&self) -> ComparableValues {
        compare_target(self, |_, name| name.to_owned())
    }
}

/// `resolve` gives the name each reference compares by
pub fn compare_target(
    spec: &TargetSpec,
    resolve: impl Fn(ResourceKind, &str) -> String,
) -> ComparableValues {
    let mut spec = spec.clone();
    spec.group = spec
        .group
        .as_ref()
        .map(|group| resolve(ResourceKind::TargetGroup, group));
    let roles: BTreeSet<String> = spec
        .roles
        .iter()
        .map(|role| resolve(ResourceKind::Role, role))
        .collect();
    spec.roles = roles.into_iter().collect();
    spec.references.jump_host = spec
        .references
        .jump_host
        .as_ref()
        .map(|target| resolve(ResourceKind::Target, target));
    spec.references.client_key = spec
        .references
        .client_key
        .as_ref()
        .map(|key| resolve(ResourceKind::SshClientKey, key));

    let mut value = to_value(&spec);
    spec.references.put(&mut value);
    ComparableValues {
        credentials: credential_paths(&spec.options),
        value: json!({ "spec": value }),
    }
}

/// A literal key compares by its public key, so the same key in another
/// format is no change; a reference compares as written. Null if a literal
/// isn't a private key.
pub fn key_identity(spec: &SshClientKeySpec) -> Value {
    match &spec.private_key {
        MaybeSecretRef::Inline(secret) => secret
            .reveal()
            .ok()
            .and_then(|pem| public_key_of_pem(pem.expose_secret()).ok())
            .map_or(Value::Null, Value::String),
        other => to_value(other),
    }
}

/// Paths of every credential field, found as the fields that redaction
/// changes. The diff hides what the API hides.
fn credential_paths(options: &TargetOptions) -> HashSet<Path> {
    let mut redacted = options.clone();
    redacted.redact();
    changed_paths(options, &redacted).into_iter().collect()
}

/// Paths from the resource's root at which `altered` differs from `options`,
/// in key order
pub fn changed_paths(options: &TargetOptions, altered: &TargetOptions) -> Vec<Path> {
    differing_paths(&to_value(options), &to_value(altered), &["spec", "options"])
}

fn differing_paths(from: &Value, to: &Value, prefix: &[&str]) -> Vec<Path> {
    let mut changes = Vec::new();
    diff(
        from,
        to,
        &mut Path::keys(prefix).0,
        &HashSet::new(),
        &mut changes,
    );
    changes.into_iter().map(|change| change.path).collect()
}

fn is_blank(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(text) => text.is_empty(),
        Value::Array(items) => items.is_empty(),
        Value::Object(fields) => fields.is_empty(),
        Value::Bool(_) | Value::Number(_) => false,
    }
}

fn to_value<T: Serialize>(value: &T) -> Value {
    // cannot fail for these types
    serde_json::to_value(value).unwrap_or_default()
}

fn diff(
    from: &Value,
    to: &Value,
    path: &mut Vec<Segment>,
    credentials: &HashSet<Path>,
    out: &mut Vec<FieldChange>,
) {
    if from == to {
        return;
    }
    let here = Path(path.clone());
    if credentials.contains(&here) {
        out.push(FieldChange {
            path: here,
            change: ValueChange::Credential,
        });
        return;
    }
    // An absent object is compared as an empty one. Each field of the other
    // side is then reported separately, and a credential among them is hidden
    let absent = Map::new();
    let objects = match (from, to) {
        (Value::Object(a), Value::Object(b)) => Some((a, b)),
        (Value::Object(a), Value::Null) if !a.is_empty() => Some((a, &absent)),
        (Value::Null, Value::Object(b)) if !b.is_empty() => Some((&absent, b)),
        _ => None,
    };
    if let Some((a, b)) = objects {
        let keys: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
        for key in keys {
            path.push(Segment::Key(key.clone()));
            diff(
                a.get(key).unwrap_or(&Value::Null),
                b.get(key).unwrap_or(&Value::Null),
                path,
                credentials,
                out,
            );
            path.pop();
        }
        return;
    }
    // A value that can't be split into fields is hidden entirely if it
    // contains a credential
    let holds_credential = credentials
        .iter()
        .any(|credential| credential.0.starts_with(path));
    let change = if holds_credential {
        ValueChange::Credential
    } else {
        ValueChange::Value {
            from: from.clone(),
            to: to.clone(),
        }
    };
    out.push(FieldChange { path: here, change });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mysql(name: &str, port: u16, password: &str) -> Row<TargetSpec> {
        Row {
            id: Uuid::nil(),
            name: name.into(),
            provider: None,
            live: serde_json::from_value(json!({"options": {"mysql": {
                "host": "h",
                "port": port,
                "auth": {"kind": "password", "password": password},
            }}}))
            .unwrap(),
        }
    }

    fn planned(before: &Row<TargetSpec>, after: &Row<TargetSpec>) -> Vec<PlannedField> {
        let fields = before.compared().changes_to(&after.compared());
        fields.iter().map(PlannedField::from).collect()
    }

    #[test]
    fn changes_name_the_fields_and_hide_credentials() {
        let before = mysql("db", 3306, "old-secret");
        assert_eq!(planned(&before, &mysql("db", 3306, "old-secret")), []);

        let changes = planned(&before, &mysql("db2", 3307, "new-secret"));
        let summary: Vec<_> = changes
            .iter()
            .map(|field| {
                (
                    field.path.as_str(),
                    field.credential,
                    &field.from,
                    &field.to,
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                ("name", false, &Some(json!("db")), &Some(json!("db2"))),
                ("spec.options.mysql.auth.password", true, &None, &None),
                (
                    "spec.options.mysql.port",
                    false,
                    &Some(json!(3306)),
                    &Some(json!(3307))
                ),
            ]
        );
    }

    #[derive(Serialize)]
    struct Settings {
        source: Option<Source>,
    }

    #[derive(Clone, Serialize)]
    struct Source {
        url: String,
        password: String,
    }

    fn settings(source: Option<Source>) -> ComparableValues {
        let redacted = source.clone().map(|source| Source {
            password: String::new(),
            ..source
        });
        ComparableValues::redacting(&Settings { source }, &Settings { source: redacted })
    }

    fn summary(fields: &[FieldChange]) -> Vec<(String, &ValueChange)> {
        fields
            .iter()
            .map(|field| (field.path.to_string(), &field.change))
            .collect()
    }

    #[test]
    fn a_credential_in_an_object_that_appears_or_goes_is_hidden() {
        let unset = settings(None);
        let set = settings(Some(Source {
            url: "https://git".into(),
            password: "old-secret".into(),
        }));

        for (from, to) in [(&unset, &set), (&set, &unset)] {
            let fields = from.changes_to(to);
            let paths: Vec<_> = fields.iter().map(|field| field.path.to_string()).collect();
            assert_eq!(paths, ["spec.source.password", "spec.source.url"]);
            assert_eq!(fields[0].change, ValueChange::Credential);
            assert!(!format!("{fields:?}").contains("secret"));
        }
    }

    #[test]
    fn a_value_that_holds_a_credential_and_has_no_fields_is_hidden_whole() {
        let mut credentials = HashSet::new();
        credentials.insert(Path::keys(&["spec", "source", "password"]));
        let compared = |value: Value| ComparableValues {
            value: json!({ "spec": { "source": value } }),
            credentials: credentials.clone(),
        };
        let fields =
            compared(json!("disabled")).changes_to(&compared(json!({ "password": "old-secret" })));
        assert_eq!(
            summary(&fields),
            [("spec.source".to_owned(), &ValueChange::Credential)]
        );
    }

    #[test]
    fn contents_are_the_set_fields_without_credential_values() {
        let fields = mysql("db", 3306, "old-secret").compared().contents();
        let port = fields
            .iter()
            .find(|field| field.path == "spec.options.mysql.port");
        assert_eq!(
            port.map(|field| (&field.from, &field.to)),
            Some((&None, &Some(json!(3306))))
        );
        let password = fields
            .iter()
            .find(|field| field.path == "spec.options.mysql.auth.password");
        assert!(password.is_some_and(|field| field.credential));
        assert!(!fields.iter().any(|field| field.path == "spec.description"));
        assert!(!format!("{fields:?}").contains("secret"));
    }
}

use std::collections::{BTreeSet, HashSet};

use serde::Serialize;
use serde_json::{Value, json};
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
    pub fn compared(&self) -> Compared {
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
pub struct Compared {
    value: Value,
    credentials: HashSet<Path>,
    protocol: Option<String>,
}

impl Compared {
    /// A spec doesn't hold its resource's name
    #[must_use]
    pub fn named(mut self, name: &str) -> Self {
        if let Value::Object(object) = &mut self.value {
            object.insert("name".into(), Value::String(name.to_owned()));
        }
        self
    }

    /// A target's protocol, `None` for the other kinds
    pub fn protocol(&self) -> Option<&str> {
        self.protocol.as_deref()
    }

    /// The compared value at a JSON pointer, such as `/spec/private_key`
    pub fn pointer(&self, pointer: &str) -> Option<&Value> {
        self.value.pointer(pointer)
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
    fn compared(&self) -> Compared;
}

impl Comparable for TargetGroupSpec {
    fn compared(&self) -> Compared {
        plain(self)
    }
}

impl Comparable for RoleSpec {
    fn compared(&self) -> Compared {
        plain(self)
    }
}

impl Comparable for SshClientKeySpec {
    fn compared(&self) -> Compared {
        Compared {
            value: json!({ "spec": { "private_key": key_identity(self), "is_default": self.is_default } }),
            credentials: HashSet::from([Path::keys(&["spec", "private_key"])]),
            protocol: None,
        }
    }
}

impl Comparable for TargetSpec {
    fn compared(&self) -> Compared {
        compare_target(self, |_, name| name.to_owned())
    }
}

fn plain<S: Serialize>(spec: &S) -> Compared {
    Compared {
        value: json!({ "spec": to_value(spec) }),
        credentials: HashSet::new(),
        protocol: None,
    }
}

/// `resolve` gives the name each reference compares by
pub fn compare_target(
    spec: &TargetSpec,
    resolve: impl Fn(ResourceKind, &str) -> String,
) -> Compared {
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

    let options = to_value(&spec.options);
    let mut value = to_value(&spec);
    spec.references.put(&mut value);
    Compared {
        credentials: credential_paths(&spec.options),
        protocol: options.as_object().and_then(|o| o.keys().next().cloned()),
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
    let mut changes = Vec::new();
    let mut prefix = vec![Segment::Key("spec".into()), Segment::Key("options".into())];
    diff(
        &to_value(options),
        &to_value(altered),
        &mut prefix,
        &HashSet::new(),
        &mut changes,
    );
    changes.into_iter().map(|change| change.path).collect()
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
    if let (Value::Object(a), Value::Object(b)) = (from, to) {
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
    out.push(FieldChange {
        path: here,
        change: ValueChange::Value {
            from: from.clone(),
            to: to.clone(),
        },
    });
}

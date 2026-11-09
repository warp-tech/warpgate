//! What applying a fileset would change. Pure: the caller loads the current
//! rows, so every case is a test on plain values.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::Write;

use serde::Serialize;
use serde_json::{Value, json};
use uuid::Uuid;
use warpgate_common::{
    MaybeSecretRef, ProviderId, StoredSecrets, TargetOptions, public_key_of_pem,
};
use warpgate_db_entities::ProviderSync::{PlanAction, PlannedChange, PlannedField, SyncPlan};

use crate::diagnostic::{Path, Segment};
use crate::types::{Kind, Resource, RoleSpec, SshClientKeySpec, TargetGroupSpec, TargetSpec};

/// A row as it is in the database, with its references by name
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row<S> {
    pub id: Uuid,
    pub name: String,
    pub provider: Option<ProviderId>,
    pub live: S,
}

#[derive(Clone, Debug, Default)]
pub struct Current {
    pub groups: Vec<Row<TargetGroupSpec>>,
    pub roles: Vec<Row<RoleSpec>>,
    pub targets: Vec<Row<TargetSpec>>,
    pub ssh_client_keys: Vec<Row<SshClientKeySpec>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValueChange {
    Value {
        from: Value,
        to: Value,
    },
    /// The values of a credential are never part of a plan
    Credential,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldChange {
    pub path: Path,
    pub change: ValueChange,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    Create(Resource),
    Update {
        id: Uuid,
        desired: Resource,
        fields: Vec<FieldChange>,
    },
    /// Takes over a row created by hand, as the resource's annotation asks
    Adopt {
        id: Uuid,
        desired: Resource,
        fields: Vec<FieldChange>,
    },
    Unchanged {
        kind: Kind,
        name: String,
    },
    /// A row of that name exists and isn't this provider's to change
    Collision {
        kind: Kind,
        name: String,
        owner: Option<ProviderId>,
    },
    /// The row is this provider's, but the change isn't made
    Blocked {
        kind: Kind,
        name: String,
        reason: String,
    },
    /// This provider's row that no resource describes any more, kept because
    /// pruning is off
    WouldPrune {
        kind: Kind,
        name: String,
        id: Uuid,
    },
    /// This provider's row that no resource describes any more
    Delete {
        kind: Kind,
        name: String,
        id: Uuid,
    },
}

impl Change {
    pub const fn action(&self) -> PlanAction {
        match self {
            Self::Create(_) => PlanAction::Create,
            Self::Update { .. } => PlanAction::Update,
            Self::Adopt { .. } => PlanAction::Adopt,
            Self::Unchanged { .. } => PlanAction::Unchanged,
            Self::Collision { .. } => PlanAction::Collision,
            Self::Blocked { .. } => PlanAction::Blocked,
            Self::WouldPrune { .. } => PlanAction::WouldPrune,
            Self::Delete { .. } => PlanAction::Delete,
        }
    }

    pub fn kind(&self) -> Kind {
        match self {
            Self::Create(resource)
            | Self::Update {
                desired: resource, ..
            }
            | Self::Adopt {
                desired: resource, ..
            } => Kind::from(resource),
            Self::Unchanged { kind, .. }
            | Self::Collision { kind, .. }
            | Self::Blocked { kind, .. }
            | Self::WouldPrune { kind, .. }
            | Self::Delete { kind, .. } => *kind,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Create(resource)
            | Self::Update {
                desired: resource, ..
            }
            | Self::Adopt {
                desired: resource, ..
            } => &resource.metadata().name,
            Self::Unchanged { name, .. }
            | Self::Collision { name, .. }
            | Self::Blocked { name, .. }
            | Self::WouldPrune { name, .. }
            | Self::Delete { name, .. } => name,
        }
    }
}

/// What happens to this provider's rows that no resource describes any more
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Prune {
    /// Kept, and listed as [`Change::WouldPrune`]
    #[default]
    Off,
    /// Deleted, unless that would delete all of the provider's rows, or more
    /// than half of them: a source that lost most of its files is more likely
    /// broken (wrong branch or path) than meant
    On,
    /// Deleted however many there are
    Force,
}

/// Changes in the order they can be applied: groups, roles and keys before
/// the targets that reference them. Deletes run in the reverse order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Plan {
    pub changes: Vec<Change>,
    /// The policy the plan was made with, which applying it re-plans with
    pub prune: Prune,
}

impl Plan {
    pub fn has_errors(&self) -> bool {
        self.changes
            .iter()
            .any(|c| matches!(c, Change::Collision { .. } | Change::Blocked { .. }))
    }

    pub fn has_pending(&self) -> bool {
        self.changes.iter().any(|c| c.action().is_pending())
    }
}

/// A row, or a resource, reduced to what the diff compares
struct Compared {
    value: Value,
    credentials: HashSet<Path>,
    protocol: Option<String>,
}

struct LiveRow<'a> {
    id: Uuid,
    name: &'a str,
    provider: Option<ProviderId>,
    compared: Compared,
}

pub fn plan(provider: ProviderId, desired: &[Resource], current: &Current, prune: Prune) -> Plan {
    let canonical = canonical_names(desired, current);
    let ssh_targets = ssh_target_names(desired, current);
    let rows: HashMap<Kind, Vec<LiveRow<'_>>> = [
        (Kind::TargetGroup, live_rows(&current.groups, plain)),
        (Kind::Role, live_rows(&current.roles, plain)),
        (
            Kind::SshClientKey,
            live_rows(&current.ssh_client_keys, compare_client_key),
        ),
        (
            Kind::Target,
            live_rows(&current.targets, |s| compare_target(s, None)),
        ),
    ]
    .into_iter()
    .collect();

    let mut matched = HashSet::new();
    let mut changes = Vec::new();
    for resource in desired {
        let kind = Kind::from(resource);
        let name = &resource.metadata().name;
        let candidates = rows.get(&kind).map(Vec::as_slice).unwrap_or_default();
        let row = find_row(candidates, name);
        if let Some(row) = row {
            matched.insert(row.id);
        }
        if let Resource::Target(target) = resource
            && let Some(reason) = unresolved_reference(&target.spec, &canonical, &ssh_targets)
        {
            changes.push(Change::Blocked {
                kind,
                name: name.clone(),
                reason,
            });
            continue;
        }
        let Some(row) = row else {
            changes.push(Change::Create(resource.clone()));
            continue;
        };

        let adopting = match row.provider {
            Some(owner) if owner == provider => false,
            None if resource.metadata().adopt_existing => true,
            owner => {
                changes.push(Change::Collision {
                    kind,
                    name: name.clone(),
                    owner,
                });
                continue;
            }
        };

        let wanted = compare_resource(resource, &canonical);
        if wanted.protocol != row.compared.protocol {
            changes.push(Change::Blocked {
                kind,
                name: name.clone(),
                reason: "a target's protocol cannot change; remove the target and create it again"
                    .into(),
            });
            continue;
        }

        let credentials = &wanted.credentials | &row.compared.credentials;
        let mut fields = Vec::new();
        diff(
            &row.compared.value,
            &wanted.value,
            &mut Vec::new(),
            &credentials,
            &mut fields,
        );
        changes.push(match (adopting, fields.is_empty()) {
            (true, _) => Change::Adopt {
                id: row.id,
                desired: resource.clone(),
                fields,
            },
            (false, true) => Change::Unchanged {
                kind,
                name: name.clone(),
            },
            (false, false) => Change::Update {
                id: row.id,
                desired: resource.clone(),
                fields,
            },
        });
    }

    let referenced = referenced_names(desired, current, &matched, provider);
    let owned: Vec<(Kind, &LiveRow<'_>)> = rows
        .iter()
        .flat_map(|(kind, rows)| rows.iter().map(|row| (*kind, row)))
        .filter(|(_, row)| row.provider == Some(provider))
        .collect();
    let orphans: Vec<_> = owned
        .iter()
        .filter(|(_, row)| !matched.contains(&row.id))
        .collect();
    let deleting = orphans.len();
    let guard_trips = prune == Prune::On
        && deleting > 0
        && (deleting == owned.len() || deleting > (owned.len() / 2).max(1));
    for (kind, row) in orphans {
        let (kind, name, id) = (*kind, row.name.to_owned(), row.id);
        let referenced_by = referenced.get(&(kind, name.to_lowercase()));
        changes.push(match (prune, referenced_by) {
            (Prune::Off, _) => Change::WouldPrune { kind, name, id },
            (_, Some(target)) => Change::Blocked {
                kind,
                name,
                reason: format!("removed from the source, but Target `{target}` still refers to it"),
            },
            (Prune::On, None) if guard_trips => Change::Blocked {
                kind,
                name,
                reason: format!(
                    "removed from the source, but deleting {deleting} of {} managed resources at once needs a forced sync",
                    owned.len()
                ),
            },
            (Prune::On | Prune::Force, None) => Change::Delete { kind, name, id },
        });
    }

    changes.sort_by(|a, b| {
        apply_order(a.kind())
            .cmp(&apply_order(b.kind()))
            .then_with(|| a.name().cmp(b.name()))
    });
    Plan { changes, prune }
}

const fn apply_order(kind: Kind) -> u8 {
    match kind {
        Kind::TargetGroup => 0,
        Kind::Role => 1,
        Kind::SshClientKey => 2,
        Kind::Target => 3,
    }
}

/// An exact match wins over one that differs only in case, which a backend
/// with case-sensitive names can hold alongside it
fn find_row<'a, 'b>(rows: &'a [LiveRow<'b>], name: &str) -> Option<&'a LiveRow<'b>> {
    rows.iter().find(|row| row.name == name).or_else(|| {
        let name = name.to_lowercase();
        rows.iter().find(|row| row.name.to_lowercase() == name)
    })
}

fn live_rows<S>(rows: &[Row<S>], compare: impl Fn(&S) -> Compared) -> Vec<LiveRow<'_>> {
    rows.iter()
        .map(|row| {
            let mut compared = compare(&row.live);
            set_name(&mut compared.value, &row.name);
            LiveRow {
                id: row.id,
                name: &row.name,
                provider: row.provider,
                compared,
            }
        })
        .collect()
}

/// The names references resolve to, keyed by kind and lowercase name: a
/// resource in the files, else a row on the server
fn canonical_names(desired: &[Resource], current: &Current) -> HashMap<(Kind, String), String> {
    fn names<S>(kind: Kind, rows: &[Row<S>]) -> impl Iterator<Item = (Kind, &str)> {
        rows.iter().map(move |row| (kind, row.name.as_str()))
    }
    let live = names(Kind::TargetGroup, &current.groups)
        .chain(names(Kind::Role, &current.roles))
        .chain(names(Kind::SshClientKey, &current.ssh_client_keys))
        .chain(names(Kind::Target, &current.targets));
    let files = desired
        .iter()
        .map(|resource| (Kind::from(resource), resource.metadata().name.as_str()));
    // Later entries win
    live.chain(files)
        .map(|(kind, name)| ((kind, name.to_lowercase()), name.to_owned()))
        .collect()
}

/// Lowercase names of the SSH targets in the files, or else on the server
fn ssh_target_names(desired: &[Resource], current: &Current) -> HashSet<String> {
    let live = current
        .targets
        .iter()
        .map(|row| (row.name.as_str(), &row.live));
    let files = desired.iter().filter_map(|resource| match resource {
        Resource::Target(m) => Some((m.metadata.name.as_str(), &m.spec)),
        _ => None,
    });
    let mut names = HashMap::new();
    for (name, spec) in live.chain(files) {
        names.insert(
            name.to_lowercase(),
            matches!(spec.options, TargetOptions::Ssh(_)),
        );
    }
    names
        .into_iter()
        .filter_map(|(name, ssh)| ssh.then_some(name))
        .collect()
}

/// What the targets that stay after this plan refer to, keyed by kind and
/// lowercase name, each with the name of one target referring to it: the
/// targets in the files, and the live ones no file describes and this
/// provider doesn't own (the rest are rewritten or pruned by the plan)
fn referenced_names(
    desired: &[Resource],
    current: &Current,
    matched: &HashSet<Uuid>,
    provider: ProviderId,
) -> HashMap<(Kind, String), String> {
    let files = desired.iter().filter_map(|resource| match resource {
        Resource::Target(m) => Some((m.metadata.name.as_str(), &m.spec)),
        _ => None,
    });
    let live = current
        .targets
        .iter()
        .filter(|row| !matched.contains(&row.id) && row.provider != Some(provider))
        .map(|row| (row.name.as_str(), &row.live));
    let mut referenced = HashMap::new();
    for (target, spec) in files.chain(live) {
        for (kind, name) in references_of(spec) {
            referenced
                .entry((kind, name.to_lowercase()))
                .or_insert_with(|| target.to_owned());
        }
    }
    referenced
}

fn references_of(spec: &TargetSpec) -> impl Iterator<Item = (Kind, &String)> {
    spec.group
        .iter()
        .map(|name| (Kind::TargetGroup, name))
        .chain(spec.roles.iter().map(|name| (Kind::Role, name)))
        .chain(
            spec.references
                .client_key
                .iter()
                .map(|name| (Kind::SshClientKey, name)),
        )
        .chain(
            spec.references
                .jump_host
                .iter()
                .map(|name| (Kind::Target, name)),
        )
}

/// Why a target's references can't be resolved, if they can't
// ponytail: a jump host loop through server-side targets isn't detected here;
// validate catches loops within the files
fn unresolved_reference(
    spec: &TargetSpec,
    canonical: &HashMap<(Kind, String), String>,
    ssh_targets: &HashSet<String>,
) -> Option<String> {
    for (kind, name) in references_of(spec) {
        let lowercase = name.to_lowercase();
        if !canonical.contains_key(&(kind, lowercase.clone())) {
            return Some(format!("unknown {kind:?} `{name}`"));
        }
        if kind == Kind::Target && !ssh_targets.contains(&lowercase) {
            return Some(format!("jump host `{name}` is not an SSH target"));
        }
    }
    None
}

fn compare_resource(resource: &Resource, canonical: &HashMap<(Kind, String), String>) -> Compared {
    let mut compared = match resource {
        Resource::Target(m) => compare_target(&m.spec, Some(canonical)),
        Resource::TargetGroup(m) => plain(&m.spec),
        Resource::Role(m) => plain(&m.spec),
        Resource::SshClientKey(m) => compare_client_key(&m.spec),
    };
    set_name(&mut compared.value, &resource.metadata().name);
    compared
}

fn plain<S: Serialize>(spec: &S) -> Compared {
    Compared {
        value: json!({ "spec": to_value(spec) }),
        credentials: HashSet::new(),
        protocol: None,
    }
}

fn compare_target(
    spec: &TargetSpec,
    canonical: Option<&HashMap<(Kind, String), String>>,
) -> Compared {
    let resolve = |kind: Kind, name: &String| {
        canonical
            .and_then(|names| names.get(&(kind, name.to_lowercase())))
            .unwrap_or(name)
            .clone()
    };
    let mut spec = spec.clone();
    spec.group = spec
        .group
        .as_ref()
        .map(|group| resolve(Kind::TargetGroup, group));
    let roles: BTreeSet<String> = spec
        .roles
        .iter()
        .map(|role| resolve(Kind::Role, role))
        .collect();
    spec.roles = roles.into_iter().collect();
    spec.references.jump_host = spec
        .references
        .jump_host
        .as_ref()
        .map(|target| resolve(Kind::Target, target));
    spec.references.client_key = spec
        .references
        .client_key
        .as_ref()
        .map(|key| resolve(Kind::SshClientKey, key));

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
/// format is no change; a reference compares as written
fn compare_client_key(spec: &SshClientKeySpec) -> Compared {
    let private_key = match &spec.private_key {
        MaybeSecretRef::Inline(secret) => secret
            .reveal()
            .ok()
            .and_then(|pem| public_key_of_pem(pem.expose_secret()).ok())
            .map_or(Value::Null, Value::String),
        other => to_value(other),
    };
    Compared {
        value: json!({ "spec": { "private_key": private_key, "is_default": spec.is_default } }),
        credentials: HashSet::from([Path::keys(&["spec", "private_key"])]),
        protocol: None,
    }
}

/// Paths of every credential field: whatever redaction changes, so the
/// plan hides exactly what the API hides
fn credential_paths(options: &TargetOptions) -> HashSet<Path> {
    let mut redacted = options.clone();
    redacted.redact();
    let mut changes = Vec::new();
    let mut prefix = vec![Segment::Key("spec".into()), Segment::Key("options".into())];
    diff(
        &to_value(options),
        &to_value(&redacted),
        &mut prefix,
        &HashSet::new(),
        &mut changes,
    );
    changes.into_iter().map(|change| change.path).collect()
}

fn set_name(value: &mut Value, name: &str) {
    if let Value::Object(object) = value {
        object.insert("name".into(), Value::String(name.to_owned()));
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

fn collision_reason(owner: Option<ProviderId>) -> String {
    match owner {
        None => format!("created by hand; set metadata.adopt_existing to take it over"),
        Some(owner) => format!("managed by {}", owner.label()),
    }
}

pub fn format_plan(plan: &Plan) -> String {
    let mut out = String::new();
    let mut pruned = Vec::new();
    // writing to a String cannot fail
    for change in &plan.changes {
        let (kind, name) = (change.kind(), change.name());
        match change {
            Change::Create(_) => {
                let _ = writeln!(out, "create {kind:?} {name}");
            }
            Change::Update { fields, .. } | Change::Adopt { fields, .. } => {
                let verb = if matches!(change, Change::Adopt { .. }) {
                    "adopt"
                } else {
                    "update"
                };
                let _ = writeln!(out, "{verb} {kind:?} {name}");
                for field in fields {
                    let _ = match &field.change {
                        ValueChange::Value { from, to } => {
                            writeln!(out, "    {}: {from} -> {to}", field.path)
                        }
                        ValueChange::Credential => {
                            writeln!(out, "    {}: (credential changed)", field.path)
                        }
                    };
                }
            }
            Change::Unchanged { .. } => {}
            Change::Collision { .. } | Change::Blocked { .. } => {
                if let Some(line) = error_line(change) {
                    let _ = writeln!(out, "{line}");
                }
            }
            Change::Delete { .. } => {
                let _ = writeln!(out, "delete {kind:?} {name}");
            }
            Change::WouldPrune { .. } => pruned.push(format!("{kind:?} {name}")),
        }
    }
    if !pruned.is_empty() {
        let _ = writeln!(out, "\nwould prune (pruning is off):");
        for line in pruned {
            let _ = writeln!(out, "    {line}");
        }
    }
    let count = |f: fn(&Change) -> bool| plan.changes.iter().filter(|c| f(c)).count();
    let _ = writeln!(
        out,
        "\n{} to create, {} to update, {} to adopt, {} to delete, {} unchanged, {} errors",
        count(|c| matches!(c, Change::Create(_))),
        count(|c| matches!(c, Change::Update { .. })),
        count(|c| matches!(c, Change::Adopt { .. })),
        count(|c| matches!(c, Change::Delete { .. })),
        count(|c| matches!(c, Change::Unchanged { .. })),
        count(|c| matches!(c, Change::Collision { .. } | Change::Blocked { .. })),
    );
    out
}

/// The collisions and blocked changes alone, one line each
pub fn format_errors(plan: &Plan) -> String {
    plan.changes
        .iter()
        .filter_map(error_line)
        .fold(String::new(), |mut out, line| {
            // writing to a String cannot fail
            let _ = writeln!(out, "{line}");
            out
        })
}

fn error_line(change: &Change) -> Option<String> {
    let (kind, name) = (change.kind(), change.name());
    match change {
        Change::Collision { owner, .. } => Some(format!(
            "collision {kind:?} {name}: {}",
            collision_reason(*owner)
        )),
        Change::Blocked { reason, .. } => Some(format!("blocked {kind:?} {name}: {reason}")),
        _ => None,
    }
}

impl From<&Plan> for SyncPlan {
    fn from(plan: &Plan) -> Self {
        Self(plan.changes.iter().map(PlannedChange::from).collect())
    }
}

impl From<&Change> for PlannedChange {
    fn from(change: &Change) -> Self {
        let (fields, reason) = match change {
            Change::Update { fields, .. } | Change::Adopt { fields, .. } => {
                (fields.iter().map(PlannedField::from).collect(), None)
            }
            Change::Collision { owner, .. } => (vec![], Some(collision_reason(*owner))),
            Change::Blocked { reason, .. } => (vec![], Some(reason.clone())),
            Change::Create(_)
            | Change::Unchanged { .. }
            | Change::WouldPrune { .. }
            | Change::Delete { .. } => (vec![], None),
        };
        Self {
            kind: format!("{:?}", change.kind()),
            name: change.name().to_owned(),
            action: change.action(),
            fields,
            reason,
        }
    }
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

#[cfg(test)]
mod tests {
    use warpgate_common::SshHostKeyKind;

    use super::*;
    use crate::diagnostic::test::path;

    const GITOPS: ProviderId = ProviderId::GITOPS;

    fn resource(value: Value) -> Resource {
        Resource::from_value(&value).unwrap()
    }

    fn manifest(kind: &str, name: &str, spec: Value) -> Resource {
        resource(json!({
            "apiVersion": "warpgate/v1",
            "kind": kind,
            "metadata": {"name": name},
            "spec": spec,
        }))
    }

    fn ssh(name: &str, port: u16, roles: &[&str]) -> Resource {
        manifest(
            "Target",
            name,
            json!({"roles": roles, "options": {"ssh": {"host": "h", "port": port}}}),
        )
    }

    fn role(name: &str) -> Resource {
        manifest("Role", name, json!({}))
    }

    fn adopting(mut resource: Resource) -> Resource {
        let metadata = match &mut resource {
            Resource::Target(m) => &mut m.metadata,
            Resource::TargetGroup(m) => &mut m.metadata,
            Resource::Role(m) => &mut m.metadata,
            Resource::SshClientKey(m) => &mut m.metadata,
        };
        metadata.adopt_existing = true;
        resource
    }

    /// The rows the given resources would leave behind
    fn current(rows: &[(&Resource, Option<ProviderId>)]) -> Current {
        let mut current = Current::default();
        for (resource, provider) in rows {
            let (id, name, provider) =
                (Uuid::new_v4(), resource.metadata().name.clone(), *provider);
            match resource {
                Resource::Target(m) => current.targets.push(Row {
                    id,
                    name,
                    provider,
                    live: m.spec.clone(),
                }),
                Resource::TargetGroup(m) => current.groups.push(Row {
                    id,
                    name,
                    provider,
                    live: m.spec.clone(),
                }),
                Resource::Role(m) => current.roles.push(Row {
                    id,
                    name,
                    provider,
                    live: m.spec.clone(),
                }),
                Resource::SshClientKey(m) => current.ssh_client_keys.push(Row {
                    id,
                    name,
                    provider,
                    live: m.spec.clone(),
                }),
            }
        }
        current
    }

    #[test]
    fn stored_plans_load_and_print_unchanged() {
        let stored = json!([
            {"kind": "Target", "name": "db", "action": "update", "fields": [
                {"path": "spec.options.ssh.port", "from": 22, "to": 2222},
                {"path": "spec.options.mysql.auth.password", "credential": true},
            ]},
            {"kind": "Role", "name": "dba", "action": "create"},
            {"kind": "Role", "name": "ops", "action": "blocked", "reason": "removed"},
            {"kind": "Role", "name": "old", "action": "would_prune"},
        ]);
        let plan: SyncPlan = serde_json::from_value(stored.clone()).unwrap();
        assert_eq!(serde_json::to_value(&plan).unwrap(), stored);
    }

    fn summary(plan: &Plan) -> Vec<String> {
        plan.changes
            .iter()
            .map(|change| {
                let action = serde_json::to_value(change.action()).unwrap();
                format!(
                    "{} {:?} {}",
                    action.as_str().unwrap(),
                    change.kind(),
                    change.name()
                )
            })
            .collect()
    }

    fn fields(plan: &Plan, name: &str) -> Vec<FieldChange> {
        plan.changes
            .iter()
            .find_map(|change| match change {
                Change::Update { fields, .. } | Change::Adopt { fields, .. }
                    if change.name() == name =>
                {
                    Some(fields.clone())
                }
                _ => None,
            })
            .unwrap()
    }

    fn value(path_: &[&str], from: Value, to: Value) -> FieldChange {
        FieldChange {
            path: path(path_),
            change: ValueChange::Value { from, to },
        }
    }

    #[test]
    fn creates_in_the_order_they_can_be_applied() {
        let desired = [
            ssh("web", 22, &["dba"]),
            role("dba"),
            manifest("TargetGroup", "prod", json!({})),
        ];
        let plan = plan(GITOPS, &desired, &Current::default(), Prune::Off);
        assert_eq!(
            summary(&plan),
            [
                "create TargetGroup prod",
                "create Role dba",
                "create Target web"
            ]
        );
        assert!(plan.has_pending());
        assert!(!plan.has_errors());
    }

    #[test]
    fn diffs_own_rows_field_by_field() {
        let before = [ssh("web", 22, &["dba"]), role("dba")];
        let live = current(&[(&before[0], Some(GITOPS)), (&before[1], Some(GITOPS))]);
        let desired = [ssh("web", 2222, &["ops", "dba"]), role("dba"), role("ops")];

        let plan = plan(GITOPS, &desired, &live, Prune::Off);
        assert_eq!(
            summary(&plan),
            ["unchanged Role dba", "create Role ops", "update Target web"]
        );
        assert_eq!(
            fields(&plan, "web"),
            [
                value(&["spec", "options", "ssh", "port"], json!(22), json!(2222)),
                value(&["spec", "roles"], json!(["dba"]), json!(["dba", "ops"])),
            ]
        );
    }

    #[test]
    fn references_and_names_compare_ignoring_case() {
        let before = [ssh("web", 22, &["dba"]), role("dba")];
        let live = current(&[(&before[0], Some(GITOPS)), (&before[1], Some(GITOPS))]);

        let plan_ = plan(
            GITOPS,
            &[ssh("web", 22, &["DBA"]), role("dba")],
            &live,
            Prune::Off,
        );
        assert!(!plan_.has_pending(), "{:?}", summary(&plan_));

        let plan_ = plan(
            GITOPS,
            &[ssh("Web", 22, &["dba"]), role("dba")],
            &live,
            Prune::Off,
        );
        assert_eq!(
            fields(&plan_, "Web"),
            [value(&["name"], json!("web"), json!("Web"))]
        );
    }

    #[test]
    fn credentials_are_never_in_the_plan() {
        let with_password = |password: &str| {
            manifest(
                "Target",
                "db",
                json!({"options": {"mysql": {"host": "h", "auth": {"kind": "password", "password": password}}}}),
            )
        };
        let before = with_password("old-secret");
        let live = current(&[(&before, Some(GITOPS))]);

        let plan_ = plan(GITOPS, &[with_password("old-secret")], &live, Prune::Off);
        assert!(!plan_.has_pending());

        let plan_ = plan(GITOPS, &[with_password("new-secret")], &live, Prune::Off);
        assert_eq!(
            fields(&plan_, "db"),
            [FieldChange {
                path: path(&["spec", "options", "mysql", "auth", "password"]),
                change: ValueChange::Credential,
            }]
        );
        let rendered = format!(
            "{}{}",
            format_plan(&plan_),
            serde_json::to_string(&SyncPlan::from(&plan_)).unwrap()
        );
        assert!(!rendered.contains("secret"), "{rendered}");
    }

    #[test]
    fn http_headers_and_url_credentials_are_never_in_the_plan() {
        let with = |token: &str| {
            manifest(
                "Target",
                "web",
                json!({"options": {"http": {
                    "url": format!("https://user:{token}@web"),
                    "headers": {"Authorization": token},
                }}}),
            )
        };
        let before = with("old-secret");
        let live = current(&[(&before, Some(GITOPS))]);
        let plan_ = plan(GITOPS, &[with("new-secret")], &live, Prune::Off);
        assert_eq!(
            fields(&plan_, "web")
                .iter()
                .map(|f| f.path.to_string())
                .collect::<Vec<_>>(),
            [
                "spec.options.http.headers.Authorization",
                "spec.options.http.url"
            ]
        );
        let rendered = format!(
            "{}{}",
            format_plan(&plan_),
            serde_json::to_string(&SyncPlan::from(&plan_)).unwrap()
        );
        assert!(!rendered.contains("secret"), "{rendered}");
    }

    #[test]
    fn only_annotated_resources_adopt_hand_made_rows() {
        let other = ProviderId(Uuid::new_v4());
        let (legacy, adoptable, theirs) = (role("legacy"), role("adoptable"), role("theirs"));
        let live = current(&[(&legacy, None), (&adoptable, None), (&theirs, Some(other))]);
        let desired = [legacy, adopting(adoptable), adopting(theirs)];

        let plan = plan(GITOPS, &desired, &live, Prune::Off);
        assert_eq!(
            summary(&plan),
            [
                "adopt Role adoptable",
                "collision Role legacy",
                "collision Role theirs",
            ]
        );
        assert!(plan.has_errors());
        assert!(plan.changes.contains(&Change::Collision {
            kind: Kind::Role,
            name: "theirs".into(),
            owner: Some(other),
        }));
    }

    #[test]
    fn prunes_only_its_own_rows() {
        let (kept, gone, mine, theirs) = (role("kept"), role("gone"), role("mine"), role("theirs"));
        let live = current(&[
            (&kept, Some(GITOPS)),
            (&gone, Some(GITOPS)),
            (&mine, None),
            (&theirs, Some(ProviderId(Uuid::new_v4()))),
        ]);

        let kept_only = plan(GITOPS, &[kept.clone()], &live, Prune::Off);
        assert_eq!(
            summary(&kept_only),
            ["would_prune Role gone", "unchanged Role kept"]
        );
        assert!(!kept_only.has_pending());

        let pruned = plan(GITOPS, &[kept], &live, Prune::On);
        assert_eq!(
            summary(&pruned),
            ["delete Role gone", "unchanged Role kept"]
        );
        assert!(pruned.has_pending());
        assert!(!pruned.has_errors());
    }

    #[test]
    fn prune_refuses_to_delete_most_rows_unless_forced() {
        let (a, b, c) = (role("a"), role("b"), role("c"));
        let live = current(&[(&a, Some(GITOPS)), (&b, Some(GITOPS)), (&c, Some(GITOPS))]);

        let blocked = plan(GITOPS, &[a.clone()], &live, Prune::On);
        assert_eq!(
            summary(&blocked),
            ["unchanged Role a", "blocked Role b", "blocked Role c"]
        );
        assert!(blocked.has_errors());

        let forced = plan(GITOPS, &[a], &live, Prune::Force);
        assert_eq!(
            summary(&forced),
            ["unchanged Role a", "delete Role b", "delete Role c"]
        );
        assert!(!forced.has_errors());
    }

    #[test]
    fn the_last_managed_rows_are_never_pruned_unless_forced() {
        let only = role("only");
        let live = current(&[(&only, Some(GITOPS))]);
        assert!(plan(GITOPS, &[], &live, Prune::On).has_errors());
        let replaced = plan(GITOPS, &[role("other")], &live, Prune::On);
        assert!(replaced.has_errors(), "{:?}", summary(&replaced));
        assert_eq!(
            format_errors(&replaced),
            "blocked Role only: removed from the source, but deleting 1 of 1 managed resources at once needs a forced sync\n"
        );
        assert_eq!(
            summary(&plan(GITOPS, &[], &live, Prune::Force)),
            ["delete Role only"]
        );
    }

    #[test]
    fn rows_still_referred_to_are_never_pruned() {
        let (dba, ops) = (role("dba"), role("ops"));
        let bastion = ssh("bastion", 22, &[]);
        let managed = manifest(
            "Target",
            "app",
            json!({"roles": ["dba"], "options": {"ssh": {"host": "h", "jump_host": "bastion"}}}),
        );
        let hand_made = ssh("legacy", 22, &["ops"]);
        let live = current(&[
            (&dba, Some(GITOPS)),
            (&ops, Some(GITOPS)),
            (&bastion, Some(GITOPS)),
            (&managed, Some(GITOPS)),
            (&hand_made, None),
        ]);

        // dba and bastion are gone from the files but `app` still uses them;
        // ops is gone but a hand-made target still grants it
        let forced = plan(GITOPS, &[managed], &live, Prune::Force);
        assert_eq!(
            summary(&forced),
            [
                "blocked Role dba",
                "blocked Role ops",
                "unchanged Target app",
                "blocked Target bastion",
            ]
        );
        assert!(format_errors(&forced).contains("Target `app` still refers to it"));
        assert!(format_errors(&forced).contains("Target `legacy` still refers to it"));

        // Dropping the references along with the rows is fine
        let dropped = plan(GITOPS, &[ssh("app", 22, &[])], &live, Prune::Force);
        assert_eq!(
            summary(&dropped),
            [
                "delete Role dba",
                "blocked Role ops",
                "update Target app",
                "delete Target bastion",
            ]
        );
    }

    #[test]
    fn references_resolve_to_files_or_server_rows() {
        let hand_made = role("Ops");
        let bastion = ssh("bastion", 22, &[]);
        let web = manifest(
            "Target",
            "web",
            json!({"options": {"http": {"url": "https://web"}}}),
        );
        let live = current(&[(&hand_made, None), (&bastion, None), (&web, None)]);
        let target = |roles: &[&str], jump: &str| {
            manifest(
                "Target",
                "app",
                json!({"roles": roles, "options": {"ssh": {"host": "h", "jump_host": jump}}}),
            )
        };

        let resolved = plan(
            GITOPS,
            &[role("dba"), target(&["dba", "ops"], "Bastion")],
            &live,
            Prune::Off,
        );
        assert!(!resolved.has_errors(), "{resolved:?}");

        let unknown = plan(GITOPS, &[target(&["dev"], "bastion")], &live, Prune::Off);
        assert_eq!(summary(&unknown), ["blocked Target app"]);
        assert_eq!(
            format_errors(&unknown),
            "blocked Target app: unknown Role `dev`\n"
        );

        let not_ssh = plan(GITOPS, &[target(&[], "web")], &live, Prune::Off);
        assert!(format_errors(&not_ssh).contains("jump host `web` is not an SSH target"));
    }

    #[test]
    fn a_protocol_change_is_blocked() {
        let before = ssh("web", 22, &[]);
        let live = current(&[(&before, Some(GITOPS))]);
        let http = manifest(
            "Target",
            "web",
            json!({"options": {"http": {"url": "https://web"}}}),
        );
        let plan = plan(GITOPS, &[http], &live, Prune::Off);
        assert_eq!(summary(&plan), ["blocked Target web"]);
        assert!(plan.has_errors());
    }

    #[test]
    fn formats_a_plan() {
        let (old, legacy) = (role("old"), role("legacy"));
        let before = ssh("web", 22, &[]);
        let live = current(&[
            (&old, Some(GITOPS)),
            (&legacy, None),
            (&before, Some(GITOPS)),
        ]);
        let plan = plan(
            GITOPS,
            &[role("new"), legacy, ssh("web", 2222, &[])],
            &live,
            Prune::Off,
        );
        assert_eq!(
            format_plan(&plan),
            "collision Role legacy: created by hand; set metadata.adopt_existing to take it over\n\
             create Role new\n\
             update Target web\n    \
                 spec.options.ssh.port: 22 -> 2222\n\
             \n\
             would prune (pruning is off):\n    \
                 Role old\n\
             \n\
             1 to create, 1 to update, 0 to adopt, 0 to delete, 0 unchanged, 1 errors\n"
        );
    }

    #[test]
    fn jump_hosts_compare_by_name() {
        let through = |jump_host: &str| {
            manifest(
                "Target",
                "app",
                json!({"options": {"ssh": {"host": "h", "jump_host": jump_host}}}),
            )
        };
        let bastion = ssh("bastion", 22, &[]);
        let other = ssh("other", 22, &[]);
        let before = through("bastion");
        let live = current(&[
            (&bastion, Some(GITOPS)),
            (&other, Some(GITOPS)),
            (&before, Some(GITOPS)),
        ]);

        let unchanged = plan(
            GITOPS,
            &[bastion.clone(), other.clone(), through("BASTION")],
            &live,
            Prune::Off,
        );
        assert!(!unchanged.has_pending(), "{:?}", summary(&unchanged));

        let moved = plan(
            GITOPS,
            &[bastion, other, through("other")],
            &live,
            Prune::Off,
        );
        assert_eq!(
            fields(&moved, "app"),
            [value(
                &["spec", "options", "ssh", "jump_host"],
                json!("bastion"),
                json!("other")
            )]
        );
    }

    #[test]
    fn client_keys_compare_without_showing_the_key() {
        let key = |name: &str, private_key: &str| {
            manifest(
                "SshClientKey",
                name,
                json!({"private_key": private_key, "is_default": true}),
            )
        };
        let (pem, other_pem) = (
            SshHostKeyKind::Ed25519.generate_pem().unwrap(),
            SshHostKeyKind::Ed25519.generate_pem().unwrap(),
        );
        let reference = "secret://vault/kv/keys#deploy";
        let (literal, referenced) = (key("deploy", &pem), key("ci", reference));
        let live = current(&[(&literal, Some(GITOPS)), (&referenced, Some(GITOPS))]);

        let unchanged = plan(GITOPS, &[literal, referenced], &live, Prune::Off);
        assert!(!unchanged.has_pending(), "{:?}", summary(&unchanged));

        let changed = plan(
            GITOPS,
            &[
                key("deploy", &other_pem),
                key("ci", "secret://vault/kv/keys#ci"),
            ],
            &live,
            Prune::Off,
        );
        let credential = [FieldChange {
            path: path(&["spec", "private_key"]),
            change: ValueChange::Credential,
        }];
        assert_eq!(fields(&changed, "deploy"), credential);
        assert_eq!(fields(&changed, "ci"), credential);
        let rendered = format!(
            "{}{}",
            format_plan(&changed),
            serde_json::to_string(&SyncPlan::from(&changed)).unwrap()
        );
        assert!(!rendered.contains("PRIVATE"), "{rendered}");
        assert!(!rendered.contains("ssh-ed25519"), "{rendered}");
        assert!(!rendered.contains("secret://"), "{rendered}");
    }
}

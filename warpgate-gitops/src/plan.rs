//! What applying a fileset would change. Pure: the caller loads the current
//! rows, so every case is a test on plain values.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::Write;

use serde::Serialize;
use serde_json::{Value, json};
use uuid::Uuid;
use warpgate_common::{ProviderId, StoredSecrets, TargetOptions};

use crate::diagnostic::{Path, Segment};
use crate::types::{ADOPT_EXISTING, Kind, Resource, RoleSpec, TargetGroupSpec, TargetSpec};

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
    /// The row is this provider's, but the change can't be made in place
    Blocked {
        kind: Kind,
        name: String,
        reason: String,
    },
    /// This provider's row that no resource describes any more
    WouldPrune {
        kind: Kind,
        name: String,
        id: Uuid,
    },
}

impl Change {
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
            | Self::WouldPrune { kind, .. } => *kind,
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
            | Self::WouldPrune { name, .. } => name,
        }
    }
}

/// Changes in the order they can be applied: groups and roles before the
/// targets that reference them
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Plan {
    pub changes: Vec<Change>,
}

impl Plan {
    pub fn has_errors(&self) -> bool {
        self.changes
            .iter()
            .any(|c| matches!(c, Change::Collision { .. } | Change::Blocked { .. }))
    }

    pub fn has_pending(&self) -> bool {
        self.changes.iter().any(|c| {
            matches!(
                c,
                Change::Create(_) | Change::Update { .. } | Change::Adopt { .. }
            )
        })
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

pub fn plan(provider: ProviderId, desired: &[Resource], current: &Current) -> Plan {
    let canonical = canonical_names(desired);
    let rows: HashMap<Kind, Vec<LiveRow<'_>>> = [
        (Kind::TargetGroup, live_rows(&current.groups, plain)),
        (Kind::Role, live_rows(&current.roles, plain)),
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
        let Some(row) = find_row(candidates, name) else {
            changes.push(Change::Create(resource.clone()));
            continue;
        };
        matched.insert(row.id);

        let adopting = match row.provider {
            Some(owner) if owner == provider => false,
            None if resource.metadata().adopts_existing() => true,
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

    for (kind, rows) in &rows {
        for row in rows {
            if row.provider == Some(provider) && !matched.contains(&row.id) {
                changes.push(Change::WouldPrune {
                    kind: *kind,
                    name: row.name.to_owned(),
                    id: row.id,
                });
            }
        }
    }

    changes.sort_by(|a, b| {
        apply_order(a.kind())
            .cmp(&apply_order(b.kind()))
            .then_with(|| a.name().cmp(b.name()))
    });
    Plan { changes }
}

const fn apply_order(kind: Kind) -> u8 {
    match kind {
        Kind::TargetGroup => 0,
        Kind::Role => 1,
        Kind::Target => 2,
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

/// The names references resolve to, keyed by kind and lowercase name
fn canonical_names(desired: &[Resource]) -> HashMap<(Kind, String), String> {
    desired
        .iter()
        .map(|resource| {
            let name = &resource.metadata().name;
            ((Kind::from(resource), name.to_lowercase()), name.clone())
        })
        .collect()
}

fn compare_resource(resource: &Resource, canonical: &HashMap<(Kind, String), String>) -> Compared {
    let mut compared = match resource {
        Resource::Target(m) => compare_target(&m.spec, Some(canonical)),
        Resource::TargetGroup(m) => plain(&m.spec),
        Resource::Role(m) => plain(&m.spec),
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

    let value = to_value(&spec.options);
    Compared {
        credentials: credential_paths(&spec.options),
        protocol: value.as_object().and_then(|o| o.keys().next().cloned()),
        value: json!({ "spec": to_value(&spec) }),
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
        None => format!(
            "created by hand; set the {ADOPT_EXISTING}: \"true\" annotation to take it over"
        ),
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
            Change::Collision { owner, .. } => {
                let _ = writeln!(
                    out,
                    "collision {kind:?} {name}: {}",
                    collision_reason(*owner)
                );
            }
            Change::Blocked { reason, .. } => {
                let _ = writeln!(out, "blocked {kind:?} {name}: {reason}");
            }
            Change::WouldPrune { .. } => pruned.push(format!("{kind:?} {name}")),
        }
    }
    if !pruned.is_empty() {
        let _ = writeln!(out, "\nwould prune (disabled in this phase):");
        for line in pruned {
            let _ = writeln!(out, "    {line}");
        }
    }
    let count = |f: fn(&Change) -> bool| plan.changes.iter().filter(|c| f(c)).count();
    let _ = writeln!(
        out,
        "\n{} to create, {} to update, {} to adopt, {} unchanged, {} errors",
        count(|c| matches!(c, Change::Create(_))),
        count(|c| matches!(c, Change::Update { .. })),
        count(|c| matches!(c, Change::Adopt { .. })),
        count(|c| matches!(c, Change::Unchanged { .. })),
        count(|c| matches!(c, Change::Collision { .. } | Change::Blocked { .. })),
    );
    out
}

pub fn format_plan_json(plan: &Plan) -> Value {
    plan.changes
        .iter()
        .map(|change| {
            let mut entry =
                json!({ "kind": format!("{:?}", change.kind()), "name": change.name() });
            let (action, extra) = match change {
                Change::Create(_) => ("create", json!({})),
                Change::Update { fields, .. } => {
                    ("update", json!({ "fields": fields_json(fields) }))
                }
                Change::Adopt { fields, .. } => ("adopt", json!({ "fields": fields_json(fields) })),
                Change::Unchanged { .. } => ("unchanged", json!({})),
                Change::Collision { owner, .. } => {
                    ("collision", json!({ "reason": collision_reason(*owner) }))
                }
                Change::Blocked { reason, .. } => ("blocked", json!({ "reason": reason })),
                Change::WouldPrune { .. } => ("would_prune", json!({})),
            };
            if let (Value::Object(entry), Value::Object(extra)) = (&mut entry, extra) {
                entry.insert("action".into(), Value::String(action.into()));
                entry.extend(extra);
            }
            entry
        })
        .collect()
}

fn fields_json(fields: &[FieldChange]) -> Value {
    fields
        .iter()
        .map(|field| match &field.change {
            ValueChange::Value { from, to } => {
                json!({ "path": field.path.to_string(), "from": from, "to": to })
            }
            ValueChange::Credential => {
                json!({ "path": field.path.to_string(), "credential": true })
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
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
        };
        metadata
            .annotations
            .insert(ADOPT_EXISTING.into(), "true".into());
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
            }
        }
        current
    }

    fn summary(plan: &Plan) -> Vec<String> {
        plan.changes
            .iter()
            .map(|change| {
                let action = match change {
                    Change::Create(_) => "create",
                    Change::Update { .. } => "update",
                    Change::Adopt { .. } => "adopt",
                    Change::Unchanged { .. } => "unchanged",
                    Change::Collision { .. } => "collision",
                    Change::Blocked { .. } => "blocked",
                    Change::WouldPrune { .. } => "would_prune",
                };
                format!("{action} {:?} {}", change.kind(), change.name())
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
        let plan = plan(GITOPS, &desired, &Current::default());
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

        let plan = plan(GITOPS, &desired, &live);
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

        let plan_ = plan(GITOPS, &[ssh("web", 22, &["DBA"]), role("dba")], &live);
        assert!(!plan_.has_pending(), "{:?}", summary(&plan_));

        let plan_ = plan(GITOPS, &[ssh("Web", 22, &["dba"]), role("dba")], &live);
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

        let plan_ = plan(GITOPS, &[with_password("old-secret")], &live);
        assert!(!plan_.has_pending());

        let plan_ = plan(GITOPS, &[with_password("new-secret")], &live);
        assert_eq!(
            fields(&plan_, "db"),
            [FieldChange {
                path: path(&["spec", "options", "mysql", "auth", "password"]),
                change: ValueChange::Credential,
            }]
        );
        let rendered = format!("{}{}", format_plan(&plan_), format_plan_json(&plan_));
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
        let plan_ = plan(GITOPS, &[with("new-secret")], &live);
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
        let rendered = format!("{}{}", format_plan(&plan_), format_plan_json(&plan_));
        assert!(!rendered.contains("secret"), "{rendered}");
    }

    #[test]
    fn only_annotated_resources_adopt_hand_made_rows() {
        let other = ProviderId(Uuid::new_v4());
        let (legacy, adoptable, theirs) = (role("legacy"), role("adoptable"), role("theirs"));
        let live = current(&[(&legacy, None), (&adoptable, None), (&theirs, Some(other))]);
        let desired = [legacy, adopting(adoptable), adopting(theirs)];

        let plan = plan(GITOPS, &desired, &live);
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
        let (old, mine, theirs) = (role("old"), role("mine"), role("theirs"));
        let live = current(&[
            (&old, Some(GITOPS)),
            (&mine, None),
            (&theirs, Some(ProviderId(Uuid::new_v4()))),
        ]);
        let plan = plan(GITOPS, &[], &live);
        assert_eq!(summary(&plan), ["would_prune Role old"]);
        assert!(!plan.has_pending());
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
        let plan = plan(GITOPS, &[http], &live);
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
        let plan = plan(GITOPS, &[role("new"), legacy, ssh("web", 2222, &[])], &live);
        assert_eq!(
            format_plan(&plan),
            "collision Role legacy: created by hand; set the warpgate.dev/adopt-existing: \"true\" annotation to take it over\n\
             create Role new\n\
             update Target web\n    \
                 spec.options.ssh.port: 22 -> 2222\n\
             \n\
             would prune (disabled in this phase):\n    \
                 Role old\n\
             \n\
             1 to create, 1 to update, 0 to adopt, 0 unchanged, 1 errors\n"
        );
    }
}

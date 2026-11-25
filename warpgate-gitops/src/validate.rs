use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::path::{Path as FilePath, PathBuf};

use poem_openapi::types::{ParseFromJSON, ToJSON};
use serde_json::Value;
use warpgate_common::{
    MaybeSecretRef, TargetDataRequest, TargetOptions, TargetSecrets, public_key_of_pem,
};
use warpgate_resources::{OptionReferences, Path, ResourceKind, Segment, changed_paths};

use crate::diagnostic::{Diagnostic, Level, Location, error_path};
use crate::parse::{Document, parse};
use crate::types::Resource;

/// A valid fileset
#[derive(Debug)]
pub struct Checked<'a> {
    pub resources: Vec<Resource>,
    /// References to resources the files don't define, which plan and apply
    /// look up on the server
    pub notes: Vec<(&'a FilePath, Diagnostic)>,
}

/// Checks every document of every file, then the names and references
/// across all of them. On failure, returns the errors.
pub fn check_files(
    files: &[(PathBuf, String)],
) -> Result<Checked<'_>, Vec<(&FilePath, Diagnostic)>> {
    let mut diagnostics = Vec::new();
    let mut documents = Vec::new();
    for (file, source) in files {
        match parse(source) {
            Err(error) => diagnostics.push((file.as_path(), error)),
            Ok(docs) => {
                for doc in docs {
                    let (resource, found) = check_document(&doc);
                    diagnostics.extend(found.into_iter().map(|d| (file.as_path(), d)));
                    if let Some(resource) = resource {
                        documents.push((file.as_path(), doc, resource));
                    }
                }
            }
        }
    }

    // A set with a broken document is rejected as a whole, and checking
    // references into it would only add knock-on errors
    let mut notes = Vec::new();
    if diagnostics.is_empty() {
        check_names_and_references(&documents, &mut diagnostics);
        (notes, diagnostics) = diagnostics
            .into_iter()
            .partition(|(_, d)| d.level == Level::Note);
    }

    let by_position = |(a, x): &(&FilePath, Diagnostic), (b, y): &(&FilePath, Diagnostic)| {
        a.cmp(b).then(x.location.cmp(&y.location))
    };
    if diagnostics.is_empty() {
        notes.sort_by(by_position);
        return Ok(Checked {
            resources: documents
                .into_iter()
                .map(|(_, _, resource)| resource)
                .collect(),
            notes,
        });
    }
    diagnostics.sort_by(by_position);
    Err(diagnostics)
}

/// Names are compared ignoring case, like MySQL's unique index on them
fn check_names_and_references<'a>(
    documents: &[(&'a FilePath, Document, Resource)],
    diagnostics: &mut Vec<(&'a FilePath, Diagnostic)>,
) {
    let name_path = Path::keys(&["metadata", "name"]);
    let mut names: HashMap<(ResourceKind, String), (&FilePath, Location)> = HashMap::new();
    for (file, doc, resource) in documents {
        let kind = ResourceKind::from(resource);
        let name = &resource.metadata().name;
        let location = doc.value_location(&name_path);
        match names.entry((kind, name.to_lowercase())) {
            Entry::Vacant(entry) => {
                entry.insert((file, location));
            }
            Entry::Occupied(entry) => {
                let (first_file, first) = entry.get();
                diagnostics.push((
                    file,
                    Diagnostic::new(
                        location,
                        name_path.clone(),
                        format!(
                            "duplicate {kind:?} name `{name}`, first defined at {}:{first}",
                            first_file.display()
                        ),
                    ),
                ));
            }
        }
    }

    // For each SSH target, its lowercase name and that of its jump host
    let mut jump_hosts: HashMap<String, Option<String>> = HashMap::new();
    let targets: HashSet<String> = documents
        .iter()
        .filter_map(|(_, _, resource)| match resource {
            Resource::Target(target) => Some(target.metadata.name.to_lowercase()),
            _ => None,
        })
        .collect();
    for (_, _, resource) in documents {
        if let Resource::Target(target) = resource
            && let TargetOptions::Ssh(_) = target.spec.options
        {
            jump_hosts.insert(
                target.metadata.name.to_lowercase(),
                target
                    .spec
                    .references
                    .jump_host
                    .as_ref()
                    .map(|name| name.to_lowercase()),
            );
        }
    }

    for (file, doc, resource) in documents {
        let Resource::Target(target) = resource else {
            continue;
        };
        if let Some(jump_host) = &target.spec.references.jump_host {
            let path = Path::pointer(&format!("/spec{}", OptionReferences::JUMP_HOST));
            let location = doc.value_location(&path);
            let lowercase = jump_host.to_lowercase();
            let found = if !targets.contains(&lowercase) {
                Some(Diagnostic::note(
                    location,
                    path,
                    not_in_files(ResourceKind::Target, jump_host),
                ))
            } else if !jump_hosts.contains_key(&lowercase) {
                Some(Diagnostic::new(
                    location,
                    path,
                    format!("`{jump_host}` is not an SSH target"),
                ))
            } else if leads_back(&jump_hosts, &target.metadata.name.to_lowercase()) {
                Some(Diagnostic::new(
                    location,
                    path,
                    "jump hosts must not form a loop",
                ))
            } else {
                None
            };
            diagnostics.extend(found.map(|d| (*file, d)));
        }
        let group = target.spec.group.iter().map(|name| {
            (
                Path::keys(&["spec", "group"]),
                ResourceKind::TargetGroup,
                name,
            )
        });
        let roles = target.spec.roles.iter().enumerate().map(|(index, name)| {
            let mut path = Path::keys(&["spec", "roles"]);
            path.0.push(Segment::Index(index));
            (path, ResourceKind::Role, name)
        });
        let client_key = target.spec.references.client_key.iter().map(|name| {
            let path = Path::pointer(&format!("/spec{}", OptionReferences::CLIENT_KEY));
            (path, ResourceKind::SshClientKey, name)
        });
        for (path, kind, name) in group.chain(roles).chain(client_key) {
            if !names.contains_key(&(kind, name.to_lowercase())) {
                diagnostics.push((
                    file,
                    Diagnostic::note(doc.value_location(&path), path, not_in_files(kind, name)),
                ));
            }
        }
    }
}

fn not_in_files(kind: ResourceKind, name: &str) -> String {
    format!("{kind:?} `{name}` is not in these files and must exist on the server")
}

/// Whether following jump hosts from `start` comes back to it
fn leads_back(jump_hosts: &HashMap<String, Option<String>>, start: &str) -> bool {
    let mut seen = HashSet::new();
    let mut next = jump_hosts.get(start).cloned().flatten();
    while let Some(name) = next {
        if name == start {
            return true;
        }
        if !seen.insert(name.clone()) {
            return false;
        }
        next = jump_hosts.get(&name).cloned().flatten();
    }
    false
}

pub fn check_document(doc: &Document) -> (Option<Resource>, Vec<Diagnostic>) {
    let mut diagnostics = doc.errors.clone();

    let resource = match Resource::from_value(&doc.value) {
        Ok(resource) => resource,
        Err(error) => {
            let path = error_path(error.path());
            // A node without a JSON representation was already reported and reads as null.
            // serde loses track inside internally tagged enums, so it may point at an ancestor.
            if !doc.errors.iter().any(|e| e.path.0.starts_with(&path.0)) {
                let location = doc.value_location(&path);
                diagnostics.push(Diagnostic::new(
                    location,
                    path,
                    without_value(&error.into_inner().to_string()),
                ));
            }
            return (None, diagnostics);
        }
    };

    // cannot fail for these types
    let canonical = serde_json::to_value(&resource).unwrap_or_default();
    unknown_fields(
        doc,
        &doc.value,
        &canonical,
        &mut Vec::new(),
        &mut diagnostics,
    );

    if get(&canonical, &["metadata", "name"])
        .and_then(Value::as_str)
        .is_some_and(|name| name.trim().is_empty())
    {
        let path = Path::keys(&["metadata", "name"]);
        diagnostics.push(Diagnostic::new(
            doc.value_location(&path),
            path,
            "must not be empty",
        ));
    }
    if let Resource::Target(target) = &resource {
        let options = &target.spec.options;
        let malformed = malformed_references(options);
        // The target is parsed as the admin API would parse it. That applies
        // the API's validators here, which keeps the two inputs from drifting
        // apart. poem reports only the first violation.
        let request = target
            .spec
            .data_request(&target.metadata.name, options.clone(), None);
        let rejected = TargetDataRequest::parse_from_json(request.to_json())
            .err()
            .map(|error| innermost(&error.into_message()));
        let root = Path::keys(&["spec"]);
        let constraint = rejected
            .as_deref()
            .and_then(|message| broken_constraint(get(&canonical, &["spec"])?, &root, message));
        let located = match (constraint, rejected) {
            (Some(constraint), _) => Some(constraint),
            // The API rejected a malformed reference, which is reported separately
            (None, Some(_)) if !malformed.is_empty() => None,
            (None, rejected) => rejected.map(|message| (root, message)),
        };
        let malformed = malformed
            .into_iter()
            .map(|path| (path, MALFORMED_REFERENCE.to_owned()));
        for (path, message) in malformed.chain(located) {
            diagnostics.push(Diagnostic::new(doc.value_location(&path), path, message));
        }
    }

    if let Resource::SshClientKey(key) = &resource {
        let problem = match &key.spec.private_key {
            MaybeSecretRef::Inline(pem) => pem
                .reveal()
                .ok()
                .and_then(|pem| public_key_of_pem(pem.expose_secret()).ok())
                .is_none()
                .then_some(
                    "not a private key in OpenSSH or PKCS#8 PEM format without a passphrase",
                ),
            MaybeSecretRef::Reference(_) => None,
            MaybeSecretRef::Malformed(_) => Some(MALFORMED_REFERENCE),
        };
        if let Some(problem) = problem {
            let path = Path::keys(&["spec", "private_key"]);
            diagnostics.push(Diagnostic::new(doc.value_location(&path), path, problem));
        }
    }

    (Some(resource), diagnostics)
}

const MALFORMED_REFERENCE: &str = "not a valid secret://backend/mount/path#field reference";

/// Paths of the `secret://` references in the options that don't parse
fn malformed_references(options: &TargetOptions) -> Vec<Path> {
    let mut blanked = options.clone();
    for secret in blanked.secrets_mut() {
        if matches!(secret, MaybeSecretRef::Malformed(_)) {
            *secret = MaybeSecretRef::default();
        }
    }
    changed_paths(options, &blanked)
}

/// The path and rule of the validator that poem's error `message` reports.
/// poem gives the field's name but not its parent object, so this searches
/// `spec` for the name. `root` is the path of `spec`. Returns `None` unless
/// exactly one field matches.
fn broken_constraint(spec: &Value, root: &Path, message: &str) -> Option<(Path, String)> {
    let (field, rule) = message
        .strip_prefix("field `")?
        .split_once("` verification failed. ")?;
    let mut found = Vec::new();
    paths_to_key(spec, field, &mut root.0.clone(), &mut found);
    match found.as_slice() {
        [path] => Some((path.clone(), format!("must satisfy {rule}"))),
        _ => None,
    }
}

fn paths_to_key(value: &Value, key: &str, here: &mut Vec<Segment>, found: &mut Vec<Path>) {
    let children: Vec<(Segment, &Value)> = match value {
        Value::Object(fields) => fields
            .iter()
            .map(|(name, child)| (Segment::Key(name.clone()), child))
            .collect(),
        Value::Array(items) => items
            .iter()
            .enumerate()
            .map(|(index, child)| (Segment::Index(index), child))
            .collect(),
        _ => return,
    };
    for (segment, child) in children {
        let is_match = segment == Segment::Key(key.to_owned());
        here.push(segment);
        if is_match {
            found.push(Path(here.clone()));
        }
        paths_to_key(child, key, here, found);
        here.pop();
    }
}

/// serde quotes the value it could not use, which may be a credential, and
/// the message ends up in logs and in the sync history. This keeps the
/// value's type and drops the value.
fn without_value(message: &str) -> String {
    let Some(rest) = message.strip_prefix("invalid type: ") else {
        return message.to_owned();
    };
    // For a type without a value, such as `null` or `map`, `found` is only
    // the type's name
    let (found, expected) = match rest.rsplit_once(", expected ") {
        Some((found, expected)) => (found, Some(expected)),
        None => (rest, None),
    };
    let kind = found
        .split(['`', '"'])
        .next()
        .unwrap_or_default()
        .trim_end();
    match expected {
        Some(expected) => format!("invalid type: {kind}, expected {expected}"),
        None => format!("invalid type: {kind}"),
    }
}

/// The cause in a poem parse error, without the chain of types around it:
/// `failed to parse "A": cause (occurred while parsing "B")`
fn innermost(message: &str) -> String {
    let cause = message
        .split(" (occurred while parsing ")
        .next()
        .unwrap_or(message);
    match cause.split_once("\": ") {
        Some((outer, cause)) if outer.starts_with("failed to parse \"") => cause,
        _ => cause,
    }
    .to_owned()
}

fn unknown_fields(
    doc: &Document,
    input: &Value,
    known: &Value,
    path: &mut Vec<Segment>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    match (input, known) {
        (Value::Object(input), Value::Object(known)) => {
            for (key, value) in input {
                path.push(Segment::Key(key.clone()));
                if let Some(known_value) = known.get(key) {
                    unknown_fields(doc, value, known_value, path, diagnostics);
                } else {
                    let expected = known
                        .keys()
                        .map(|k| format!("`{k}`"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    let path = Path(path.clone());
                    diagnostics.push(Diagnostic::new(
                        doc.key_location(&path),
                        path,
                        format!("unknown field `{key}`, expected one of {expected}"),
                    ));
                }
                path.pop();
            }
        }
        (Value::Array(input), Value::Array(known)) => {
            for (index, (value, known_value)) in input.iter().zip(known).enumerate() {
                path.push(Segment::Index(index));
                unknown_fields(doc, value, known_value, path, diagnostics);
                path.pop();
            }
        }
        _ => {}
    }
}

fn get<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().try_fold(value, |value, key| value.get(key))
}

#[cfg(test)]
mod tests {
    use super::without_value;

    #[test]
    fn invalid_type_messages_lose_the_value_and_nothing_else() {
        for (message, kept) in [
            (
                "invalid type: string \"hunter2\", expected a boolean",
                "invalid type: string, expected a boolean",
            ),
            (
                "invalid type: integer `90210`, expected a string",
                "invalid type: integer, expected a string",
            ),
            (
                "invalid type: null, expected a string",
                "invalid type: null, expected a string",
            ),
            (
                "invalid type: map, expected a sequence",
                "invalid type: map, expected a sequence",
            ),
            ("unknown variant `x`", "unknown variant `x`"),
        ] {
            assert_eq!(without_value(message), kept);
        }
    }
}

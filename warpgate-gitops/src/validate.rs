use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::path::{Path as FilePath, PathBuf};

use serde_json::Value;
use warpgate_common::{MaybeSecretRef, TargetOptions, public_key_of_pem};

use crate::diagnostic::{Diagnostic, Location, Path, Segment};
use crate::parse::{Document, parse};
use crate::types::{ADOPT_EXISTING, Kind, OptionReferences, Resource};

/// Checks every document of every file, then the names and references across all of them
/// The resources of a valid fileset, or every problem found in it
pub fn check_files(
    files: &[(PathBuf, String)],
) -> Result<Vec<Resource>, Vec<(&FilePath, Diagnostic)>> {
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
    if diagnostics.is_empty() {
        check_names_and_references(&documents, &mut diagnostics);
    }

    if diagnostics.is_empty() {
        return Ok(documents
            .into_iter()
            .map(|(_, _, resource)| resource)
            .collect());
    }
    diagnostics.sort_by(|(a, x), (b, y)| a.cmp(b).then(x.location.cmp(&y.location)));
    Err(diagnostics)
}

/// Names are compared ignoring case, like MySQL's unique index on them
fn check_names_and_references<'a>(
    documents: &[(&'a FilePath, Document, Resource)],
    diagnostics: &mut Vec<(&'a FilePath, Diagnostic)>,
) {
    let name_path = Path::keys(&["metadata", "name"]);
    let mut names: HashMap<(Kind, String), (&FilePath, Location)> = HashMap::new();
    for (file, doc, resource) in documents {
        let kind = Kind::from(resource);
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

    // Lowercase target names to the target their jump host names, for SSH targets
    let mut jump_hosts: HashMap<String, Option<String>> = HashMap::new();
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
            let problem = if !jump_hosts.contains_key(&jump_host.to_lowercase()) {
                Some(format!("no SSH target named `{jump_host}`"))
            } else if leads_back(&jump_hosts, &target.metadata.name.to_lowercase()) {
                Some("jump hosts must not form a loop".to_owned())
            } else {
                None
            };
            if let Some(problem) = problem {
                diagnostics.push((
                    file,
                    Diagnostic::new(doc.value_location(&path), path, problem),
                ));
            }
        }
        let group = target
            .spec
            .group
            .iter()
            .map(|name| (Path::keys(&["spec", "group"]), Kind::TargetGroup, name));
        let roles = target.spec.roles.iter().enumerate().map(|(index, name)| {
            let mut path = Path::keys(&["spec", "roles"]);
            path.0.push(Segment::Index(index));
            (path, Kind::Role, name)
        });
        let client_key = target.spec.references.client_key.iter().map(|name| {
            let path = Path::pointer(&format!("/spec{}", OptionReferences::CLIENT_KEY));
            (path, Kind::SshClientKey, name)
        });
        for (path, kind, name) in group.chain(roles).chain(client_key) {
            if !names.contains_key(&(kind, name.to_lowercase())) {
                diagnostics.push((
                    file,
                    Diagnostic::new(
                        doc.value_location(&path),
                        path,
                        format!("unknown {kind:?} `{name}`"),
                    ),
                ));
            }
        }
    }
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
            let path = Path::from(error.path());
            // A node without a JSON representation was already reported and reads as null.
            // serde loses track inside internally tagged enums, so it may point at an ancestor.
            if !doc.errors.iter().any(|e| e.path.0.starts_with(&path.0)) {
                let location = doc.value_location(&path);
                diagnostics.push(Diagnostic::new(
                    location,
                    path,
                    error.into_inner().to_string(),
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
    let adopt_path = Path::keys(&["metadata", "annotations", ADOPT_EXISTING]);
    if get(&canonical, &["metadata", "annotations", ADOPT_EXISTING])
        .and_then(Value::as_str)
        .is_some_and(|value| value != "true" && value != "false")
    {
        diagnostics.push(Diagnostic::new(
            doc.value_location(&adopt_path),
            adopt_path,
            "must be \"true\" or \"false\"",
        ));
    }
    let ports = get(&canonical, &["spec", "options"])
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|protocols| protocols.keys())
        .map(|protocol| vec!["spec", "options", protocol.as_str(), "port"]);
    let ticket_limits = [
        vec!["spec", "ticket_max_uses"],
        vec!["spec", "ticket_max_duration_seconds"],
    ];
    for keys in ports.chain(ticket_limits) {
        if get(&canonical, &keys)
            .and_then(Value::as_i64)
            .is_some_and(|value| value < 1)
        {
            let path = Path::keys(&keys);
            diagnostics.push(Diagnostic::new(
                doc.value_location(&path),
                path,
                "must be at least 1",
            ));
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
            MaybeSecretRef::Malformed(_) => {
                Some("not a valid secret://backend/mount/path#field reference")
            }
        };
        if let Some(problem) = problem {
            let path = Path::keys(&["spec", "private_key"]);
            diagnostics.push(Diagnostic::new(doc.value_location(&path), path, problem));
        }
    }

    (Some(resource), diagnostics)
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
    use super::*;
    use crate::diagnostic::test::{at, path};
    use crate::parse::parse;

    fn check(source: &str) -> Vec<Diagnostic> {
        let docs = parse(source).unwrap();
        assert_eq!(docs.len(), 1);
        docs.iter().flat_map(|doc| check_document(doc).1).collect()
    }

    const TARGET: &str = "apiVersion: warpgate/v1\nkind: Target\nmetadata:\n  name: a\nspec:\n";

    #[test]
    fn every_field_is_known() {
        let docs = parse(include_str!("../tests/fixtures/valid/every-field.yaml")).unwrap();
        assert_eq!(docs.len(), 18);
        for doc in &docs {
            let (resource, diagnostics) = check_document(doc);
            assert!(resource.is_some());
            assert_eq!(diagnostics, vec![], "{}", doc.value);
        }
    }

    #[test]
    fn unknown_fields_point_at_their_key() {
        let diagnostics = check(&format!(
            "{TARGET}  \
               options:\n    \
                 ssh:\n      \
                   host: h\n      \
                   usrname: x\n      \
                   auth:\n        \
                     kind: password\n        \
                     password: secret://vault/kv/a#pw\n        \
                     passwrd: y\n  \
               labels: {{}}\n"
        ));
        let found: Vec<_> = diagnostics
            .iter()
            .map(|d| (d.location, d.path.to_string()))
            .collect();
        assert_eq!(
            found,
            vec![
                (at(14, 3), "spec.labels".to_owned()),
                (at(13, 9), "spec.options.ssh.auth.passwrd".to_owned()),
                (at(9, 7), "spec.options.ssh.usrname".to_owned()),
            ]
        );
        assert!(
            diagnostics
                .iter()
                .all(|d| d.message.starts_with("unknown field"))
        );
        assert!(
            diagnostics[2]
                .message
                .contains("expected one of `allow_insecure_algos`, `auth`")
        );
    }

    #[test]
    fn a_type_error_points_at_its_value() {
        let diagnostics = check(&format!(
            "{TARGET}  options:\n    ssh:\n      host: h\n      port: \"22\"\n"
        ));
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].location, at(9, 13));
        assert_eq!(
            diagnostics[0].path,
            path(&["spec", "options", "ssh", "port"])
        );
        assert!(
            diagnostics[0].message.contains("expected u16"),
            "{}",
            diagnostics[0].message
        );
    }

    #[test]
    fn an_unknown_kind_is_reported_once() {
        let diagnostics = check("apiVersion: warpgate/v1\nkind: Pod\nspec: {}\n");
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].location, at(2, 7));
        assert!(
            diagnostics[0]
                .message
                .contains("expected one of `Target`, `TargetGroup`, `Role`")
        );
    }

    #[test]
    fn an_alias_is_not_reported_again_as_a_type_error() {
        let diagnostics = check(&format!(
            "{TARGET}  description: &d x\n  options:\n    ssh:\n      host: h\n      auth:\n        kind: password\n        password: *d\n"
        ));
        assert_eq!(
            diagnostics,
            vec![Diagnostic::new(
                at(12, 19),
                path(&["spec", "options", "ssh", "auth", "password"]),
                "YAML aliases are not supported",
            )]
        );
    }

    #[test]
    fn values_out_of_range() {
        let diagnostics = check(
            "apiVersion: warpgate/v1\nkind: Target\nmetadata:\n  name: ' '\nspec:\n  \
               ticket_max_uses: 0\n  \
               ticket_max_duration_seconds: -5\n  \
               options:\n    \
                 ssh:\n      \
                   host: h\n      \
                   port: 0\n",
        );
        let found: Vec<_> = diagnostics
            .iter()
            .map(|d| (d.location, d.path.to_string(), d.message.as_str()))
            .collect();
        assert_eq!(
            found,
            vec![
                (at(4, 9), "metadata.name".into(), "must not be empty"),
                (
                    at(11, 13),
                    "spec.options.ssh.port".into(),
                    "must be at least 1"
                ),
                (
                    at(6, 20),
                    "spec.ticket_max_uses".into(),
                    "must be at least 1"
                ),
                (
                    at(7, 32),
                    "spec.ticket_max_duration_seconds".into(),
                    "must be at least 1"
                ),
            ]
        );
    }

    fn check_all(files: &[(&str, &str)]) -> Vec<String> {
        let files: Vec<_> = files
            .iter()
            .map(|(file, source)| (PathBuf::from(file), (*source).to_owned()))
            .collect();
        check_files(&files)
            .unwrap_err()
            .into_iter()
            .map(|(file, d)| {
                format!(
                    "{}:{} {}: {}",
                    file.display(),
                    d.location,
                    d.path,
                    d.message
                )
            })
            .collect()
    }

    const ROLE_DBA: &str =
        "apiVersion: warpgate/v1\nkind: Role\nmetadata:\n  name: dba\nspec: {}\n";

    #[test]
    fn names_and_references_across_files() {
        let found = check_all(&[
            (
                "a.yaml",
                &format!(
                    "{ROLE_DBA}---\n\
                     apiVersion: warpgate/v1\nkind: TargetGroup\nmetadata:\n  name: dba\nspec: {{}}\n"
                ),
            ),
            (
                "b.yaml",
                "apiVersion: warpgate/v1\nkind: Role\nmetadata:\n  name: DBA\nspec: {}\n\
                 ---\n\
                 apiVersion: warpgate/v1\nkind: Target\nmetadata:\n  name: web\nspec:\n  \
                   group: prod\n  \
                   roles: [dba, ops]\n  \
                   options:\n    ssh:\n      host: h\n",
            ),
        ]);
        assert_eq!(
            found,
            vec![
                "b.yaml:4:9 metadata.name: duplicate Role name `DBA`, first defined at a.yaml:4:9",
                "b.yaml:12:10 spec.group: unknown TargetGroup `prod`",
                "b.yaml:13:16 spec.roles[1]: unknown Role `ops`",
            ]
        );
    }

    #[test]
    fn a_broken_document_skips_the_cross_document_checks() {
        let found = check_all(&[
            ("a.yaml", &format!("{ROLE_DBA}---\n{ROLE_DBA}")),
            ("b.yaml", "a: [\n"),
        ]);
        assert_eq!(
            found,
            vec!["b.yaml:2:1 : while parsing a node, did not find expected node content"]
        );
    }
}

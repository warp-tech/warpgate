use serde_json::Value;

use crate::diagnostic::{Diagnostic, Path, Segment};
use crate::parse::Document;
use crate::types::Resource;

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
        assert_eq!(docs.len(), 16);
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
}

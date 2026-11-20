//! Writes resources as a YAML stream that `check_files` reads back as the
//! same resources.

use std::borrow::Cow;

use saphyr::{Mapping, Scalar, Yaml, YamlEmitter};
use serde_json::Value;

use crate::types::Resource;

pub fn to_yaml(resources: &[Resource]) -> String {
    let mut out = String::new();
    for resource in resources {
        let mut value = serde_json::to_value(resource).unwrap_or_default();
        if let (Resource::Target(target), Some(spec)) = (resource, value.get_mut("spec")) {
            target.spec.references.put(spec);
        }
        let mut emitter = YamlEmitter::new(&mut out);
        // PEM keys and certificates as `|` blocks
        emitter.multiline_strings(true);
        // writing to a String cannot fail
        let _ = emitter.dump(&to_node(&value));
        out.push('\n');
    }
    out
}

/// Nulls are left out: every optional field reads a missing key as null
fn to_node(value: &Value) -> Yaml<'_> {
    match value {
        Value::Null => Yaml::Value(Scalar::Null),
        Value::Bool(b) => Yaml::Value(Scalar::Boolean(*b)),
        Value::Number(n) => match n.as_i64() {
            Some(i) => Yaml::Value(Scalar::Integer(i)),
            None => Yaml::Value(Scalar::String(Cow::Owned(n.to_string()))),
        },
        Value::String(s) => Yaml::Value(Scalar::String(Cow::Borrowed(s))),
        Value::Array(items) => Yaml::Sequence(items.iter().map(to_node).collect()),
        Value::Object(object) => {
            let mut mapping = Mapping::new();
            for (key, value) in object.iter().filter(|(_, v)| !v.is_null()) {
                mapping.insert(
                    Yaml::Value(Scalar::String(Cow::Borrowed(key))),
                    to_node(value),
                );
            }
            Yaml::Mapping(mapping)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::to_yaml;
    use crate::read_files;
    use crate::validate::check_files;

    #[test]
    fn every_field_reads_back_unchanged() {
        let files = read_files(&["tests/fixtures/valid".into()]).unwrap();
        let resources = check_files(&files).unwrap().resources;

        let yaml = to_yaml(&resources);
        assert!(yaml.contains("private_key: |\n"), "{yaml}");
        let again = [("export.yaml".into(), yaml)];
        let read_back = check_files(&again)
            .unwrap_or_else(|e| panic!("{}", crate::format_text(&e)))
            .resources;
        assert_eq!(read_back, resources);
    }
}

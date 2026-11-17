//! YAML source → one JSON value tree per document, plus the source position of
//! every node in it.
//!
//! Validation works on [`Value`] so that typed deserialization, unknown-field
//! detection and cross-document checks all address nodes the same way, by
//! [`Path`]. [`Document::value_location`] and [`Document::key_location`] map
//! any such path back to a position in the file.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use saphyr::{MarkedYaml, Scalar, YamlData, YamlLoader};
use saphyr_parser::{Event, Marker, Parser, ScalarStyle, ScanError, Span, SpannedEventReceiver};
use serde_json::{Map, Number, Value};

use crate::diagnostic::{Diagnostic, Location, Path, Segment};

/// Deeper input is rejected before it is loaded: converting a node tree and
/// dropping it both recurse once per level.
const MAX_DEPTH: usize = 64;

const ALIAS_UNSUPPORTED: &str = "YAML aliases are not supported";

impl From<&Marker> for Location {
    fn from(marker: &Marker) -> Self {
        // saphyr counts lines from 1 but columns from 0
        Self {
            line: marker.line(),
            column: marker.col() + 1,
        }
    }
}

impl From<&ScanError> for Diagnostic {
    fn from(error: &ScanError) -> Self {
        Self::new(error.marker().into(), Path::default(), error.info())
    }
}

#[derive(Clone, Copy, Debug)]
struct NodeLocation {
    /// The mapping key that names the node; the node itself for the root and sequence items
    key: Location,
    value: Location,
}

#[derive(Debug)]
pub struct Document {
    pub value: Value,
    /// Nodes that have no JSON representation. Each reads as `null` in
    /// [`Self::value`], or is left out if it was a mapping key.
    pub errors: Vec<Diagnostic>,
    locations: HashMap<Path, NodeLocation>,
}

impl Document {
    /// Where the node at `path` starts, or its closest existing ancestor
    pub fn value_location(&self, path: &Path) -> Location {
        self.nearest(path).value
    }

    /// Where the mapping key naming the node at `path` starts, or that of its
    /// closest existing ancestor
    pub fn key_location(&self, path: &Path) -> Location {
        self.nearest(path).key
    }

    fn nearest(&self, path: &Path) -> NodeLocation {
        const START: Location = Location { line: 1, column: 1 };
        (0..=path.0.len())
            .rev()
            .find_map(|len| self.locations.get(path.0.get(..len)?))
            .copied()
            .unwrap_or(NodeLocation {
                key: START,
                value: START,
            })
    }
}

pub fn parse(source: &str) -> Result<Vec<Document>, Diagnostic> {
    let mut loader = GuardedLoader {
        loader: YamlLoader::default(),
        depth: 0,
        aliases: HashSet::new(),
    };

    // `load` is recursive and can overflow the stack on a deeply nested document
    for event in Parser::new_from_str(source) {
        let (event, span) = event.map_err(|error| Diagnostic::from(&error))?;
        loader.feed(event, span)?;
    }
    if let Some(error) = loader.loader.error() {
        return Err(error.into());
    }

    let aliases = loader.aliases;
    Ok(loader
        .loader
        .into_documents()
        .iter()
        .filter(|root| {
            !matches!(
                root.data,
                YamlData::Value(Scalar::Null) | YamlData::BadValue
            )
        })
        .map(|root| {
            let mut converter = Converter {
                aliases: &aliases,
                locations: HashMap::new(),
                errors: Vec::new(),
            };
            let value = converter.convert(root, &mut Vec::new(), (&root.span.start).into());
            Document {
                value,
                errors: converter.errors,
                locations: converter.locations,
            }
        })
        .collect())
}

/// Does not expand aliases, and limits nesting depth
struct GuardedLoader<'input> {
    loader: YamlLoader<'input, MarkedYaml<'input>>,
    depth: usize,
    /// Start offsets of the aliases
    aliases: HashSet<usize>,
}

impl<'input> GuardedLoader<'input> {
    fn feed(&mut self, event: Event<'input>, span: Span) -> Result<(), Diagnostic> {
        let event = match event {
            Event::MappingStart(..) | Event::SequenceStart(..) => {
                self.depth += 1;
                if self.depth > MAX_DEPTH {
                    return Err(Diagnostic::new(
                        (&span.start).into(),
                        Path::default(),
                        format!("nesting is deeper than {MAX_DEPTH} levels"),
                    ));
                }
                event
            }
            Event::MappingEnd | Event::SequenceEnd => {
                self.depth = self.depth.saturating_sub(1);
                event
            }
            Event::Alias(_) => {
                self.aliases.insert(span.start.index());
                Event::Scalar(Cow::Borrowed("~"), ScalarStyle::Plain, 0, None)
            }
            event => event,
        };
        self.loader.on_event(event, span);
        Ok(())
    }
}

/// Converts a saphyr tree into a `serde_json` value
struct Converter<'a> {
    aliases: &'a HashSet<usize>,
    locations: HashMap<Path, NodeLocation>,
    errors: Vec<Diagnostic>,
}

impl Converter<'_> {
    fn convert(&mut self, node: &MarkedYaml<'_>, path: &mut Vec<Segment>, key: Location) -> Value {
        let location = Location::from(&node.span.start);
        self.locations.insert(
            Path(path.clone()),
            NodeLocation {
                key,
                value: location,
            },
        );

        match &node.data {
            YamlData::Value(Scalar::Null) if self.is_alias(node) => {
                self.error(path, location, ALIAS_UNSUPPORTED)
            }
            YamlData::Value(Scalar::Null) => Value::Null,
            YamlData::Value(Scalar::Boolean(b)) => Value::Bool(*b),
            YamlData::Value(Scalar::Integer(i)) => Value::from(*i),
            YamlData::Value(Scalar::FloatingPoint(f)) => match Number::from_f64(f.0) {
                Some(n) => Value::Number(n),
                None => self.error(path, location, "non-finite numbers are not supported"),
            },
            YamlData::Value(Scalar::String(s)) => Value::String(s.to_string()),
            YamlData::Sequence(items) => Value::Array(
                items
                    .iter()
                    .enumerate()
                    .map(|(index, item)| {
                        path.push(Segment::Index(index));
                        let value = self.convert(item, path, (&item.span.start).into());
                        path.pop();
                        value
                    })
                    .collect(),
            ),
            YamlData::Mapping(entries) => {
                let mut map = Map::new();
                for (key_node, value_node) in entries {
                    let key_location = Location::from(&key_node.span.start);
                    let YamlData::Value(Scalar::String(key)) = &key_node.data else {
                        let message = if self.is_alias(key_node) {
                            ALIAS_UNSUPPORTED
                        } else {
                            "mapping keys must be strings"
                        };
                        self.error(path, key_location, message);
                        continue;
                    };
                    path.push(Segment::Key(key.to_string()));
                    let value = self.convert(value_node, path, key_location);
                    path.pop();
                    map.insert(key.to_string(), value);
                }
                Value::Object(map)
            }
            YamlData::Tagged(..) => self.error(path, location, "YAML tags are not supported"),
            YamlData::Alias(_) => self.error(path, location, ALIAS_UNSUPPORTED),
            YamlData::Representation(..) | YamlData::BadValue => {
                self.error(path, location, "invalid value")
            }
        }
    }

    fn is_alias(&self, node: &MarkedYaml<'_>) -> bool {
        self.aliases.contains(&node.span.start.index())
    }

    /// Reports a node that has no JSON representation
    fn error(&mut self, path: &[Segment], location: Location, message: &str) -> Value {
        self.errors
            .push(Diagnostic::new(location, Path(path.to_vec()), message));
        Value::Null
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::diagnostic::test::{at, path};

    fn single(source: &str) -> Document {
        let mut docs = parse(source).unwrap();
        assert_eq!(docs.len(), 1);
        docs.remove(0)
    }

    #[test]
    fn splits_documents_with_file_relative_locations() {
        let docs = parse(
            "kind: Role\n\
             ---\n\
             kind: Target\n\
             spec:\n  \
               port: 22\n  \
               roles: [a, b]\n",
        )
        .unwrap();
        assert_eq!(docs.len(), 2);
        assert_eq!(docs[0].value, json!({"kind": "Role"}));

        let doc = &docs[1];
        assert_eq!(
            doc.value,
            json!({"kind": "Target", "spec": {"port": 22, "roles": ["a", "b"]}})
        );
        assert_eq!(doc.key_location(&path(&["spec", "port"])), at(5, 3));
        assert_eq!(doc.value_location(&path(&["spec", "port"])), at(5, 9));
        assert_eq!(
            doc.value_location(&path(&["spec", "roles", "1"])),
            at(6, 14)
        );
        assert!(doc.errors.is_empty());
    }

    #[test]
    fn unknown_paths_fall_back_to_the_closest_ancestor() {
        let doc = single("spec:\n  port: 22\n");
        assert_eq!(
            doc.value_location(&path(&["spec", "missing", "deeper"])),
            at(2, 3)
        );
        assert_eq!(doc.value_location(&path(&["nowhere"])), at(1, 1));
    }

    #[test]
    fn keys_with_dots_stay_one_segment() {
        let doc = single("labels:\n  example.com/team: x\n");
        assert_eq!(
            doc.key_location(&path(&["labels", "example.com/team"])),
            at(2, 3)
        );
        assert_eq!(
            path(&["labels", "example.com/team"]).to_string(),
            "labels.example.com/team"
        );
        assert_eq!(path(&["spec", "roles", "0"]).to_string(), "spec.roles[0]");
    }

    #[test]
    fn scalars_follow_the_yaml_1_2_core_schema() {
        let doc = single("a: \"22\"\nb: 22\nc: yes\nd: true\ne: ~\nf: 1.5\n");
        assert_eq!(
            doc.value,
            json!({"a": "22", "b": 22, "c": "yes", "d": true, "e": null, "f": 1.5})
        );
    }

    #[test]
    fn empty_documents_are_skipped() {
        assert_eq!(parse("").unwrap().len(), 0);
        assert_eq!(parse("# only a comment\n").unwrap().len(), 0);
        assert_eq!(parse("---\n---\na: 1\n---\n").unwrap().len(), 1);
    }

    #[test]
    fn aliases_are_reported_without_being_expanded() {
        let doc = single("x: &A {k: v}\ny: *A\nz: [*A]\n");
        assert_eq!(doc.value, json!({"x": {"k": "v"}, "y": null, "z": [null]}));
        assert_eq!(
            doc.errors,
            vec![
                Diagnostic::new(at(2, 4), path(&["y"]), ALIAS_UNSUPPORTED),
                Diagnostic::new(at(3, 5), path(&["z", "0"]), ALIAS_UNSUPPORTED),
            ]
        );

        // Fully expanded, this is 10^9 nodes
        let mut bomb = String::from("a: &a [x, x, x, x, x, x, x, x, x, x]\n");
        for level in b'b'..=b'j' {
            let (name, prev) = (level as char, (level - 1) as char);
            let refs = vec![format!("*{prev}"); 10].join(", ");
            bomb += &format!("{name}: &{name} [{refs}]\n");
        }
        assert_eq!(single(&bomb).errors.len(), 90);
    }

    #[test]
    fn deep_nesting_fails_the_file() {
        // Block sequences nest two characters per level
        let error = parse(&format!("{}x", "- ".repeat(100_000))).unwrap_err();
        assert_eq!(error.location, at(1, 2 * MAX_DEPTH + 1));
        assert_eq!(
            parse(&format!("{}x", "- ".repeat(MAX_DEPTH)))
                .unwrap()
                .len(),
            1
        );

        // The scanner itself caps flow nesting
        let flow = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
        assert!(parse(&flow).is_err());
    }

    #[test]
    fn unrepresentable_nodes_are_reported() {
        let doc = single("a: !secret foo\n1: dropped\nb: .nan\nc: ok\n");
        assert_eq!(doc.value, json!({"a": null, "b": null, "c": "ok"}));
        let messages: Vec<_> = doc
            .errors
            .iter()
            .map(|e| (e.location.line, e.message.as_str()))
            .collect();
        assert_eq!(
            messages,
            vec![
                (1, "YAML tags are not supported"),
                (2, "mapping keys must be strings"),
                (3, "non-finite numbers are not supported"),
            ]
        );
    }
}

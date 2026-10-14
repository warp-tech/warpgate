use std::borrow::Borrow;
use std::fmt;

/// A 1-based position in the source
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Location {
    pub line: usize,
    pub column: usize,
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.line, self.column)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Segment {
    Key(String),
    Index(usize),
}

/// The address of a node within its document. Mapping keys are kept whole, so
/// a label key such as `example.com/team` stays a single segment.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Path(pub Vec<Segment>);

impl Path {
    pub fn keys(keys: &[&str]) -> Self {
        Self(keys.iter().map(|k| Segment::Key((*k).to_owned())).collect())
    }
}

impl Borrow<[Segment]> for Path {
    fn borrow(&self) -> &[Segment] {
        &self.0
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, segment) in self.0.iter().enumerate() {
            match segment {
                Segment::Key(key) if i == 0 => f.write_str(key)?,
                Segment::Key(key) => write!(f, ".{key}")?,
                Segment::Index(index) => write!(f, "[{index}]")?,
            }
        }
        Ok(())
    }
}

impl From<&serde_path_to_error::Path> for Path {
    fn from(path: &serde_path_to_error::Path) -> Self {
        use serde_path_to_error::Segment as S;
        Self(
            path.iter()
                .map_while(|segment| match segment {
                    S::Seq { index } => Some(Segment::Index(*index)),
                    S::Map { key } | S::Enum { variant: key } => Some(Segment::Key(key.clone())),
                    S::Unknown => None,
                })
                .collect(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    pub location: Location,
    pub path: Path,
    pub message: String,
}

impl Diagnostic {
    pub fn new(location: Location, path: Path, message: impl Into<String>) -> Self {
        Self {
            location,
            path,
            message: message.into(),
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;

    /// Segments that parse as integers become indices
    pub fn path(segments: &[&str]) -> Path {
        Path(
            segments
                .iter()
                .map(|s| match s.parse() {
                    Ok(index) => Segment::Index(index),
                    Err(_) => Segment::Key((*s).to_owned()),
                })
                .collect(),
        )
    }

    pub const fn at(line: usize, column: usize) -> Location {
        Location { line, column }
    }
}

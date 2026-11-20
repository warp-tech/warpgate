use std::fmt;

use warpgate_resources::{Path, Segment};

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

/// As far as a deserialization error knows where it happened
pub fn error_path(path: &serde_path_to_error::Path) -> Path {
    use serde_path_to_error::Segment as S;
    Path(
        path.iter()
            .map_while(|segment| match segment {
                S::Seq { index } => Some(Segment::Index(*index)),
                S::Map { key } | S::Enum { variant: key } => Some(Segment::Key(key.clone())),
                S::Unknown => None,
            })
            .collect(),
    )
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Level {
    /// Makes the fileset invalid
    #[default]
    Error,
    /// Worth knowing, but the fileset is still valid
    Note,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    pub level: Level,
    pub location: Location,
    pub path: Path,
    pub message: String,
}

impl Diagnostic {
    pub fn new(location: Location, path: Path, message: impl Into<String>) -> Self {
        Self {
            level: Level::Error,
            location,
            path,
            message: message.into(),
        }
    }

    pub fn note(location: Location, path: Path, message: impl Into<String>) -> Self {
        Self {
            level: Level::Note,
            ..Self::new(location, path, message)
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

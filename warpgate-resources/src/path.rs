use std::borrow::Borrow;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Segment {
    Key(String),
    Index(usize),
}

/// The address of a node within its document. Mapping keys are kept whole, so
/// a key that contains a dot stays a single segment.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Path(pub Vec<Segment>);

impl Path {
    pub fn keys(keys: &[&str]) -> Self {
        Self(keys.iter().map(|k| Segment::Key((*k).to_owned())).collect())
    }

    /// From a JSON pointer of plain keys, such as `/spec/options`
    pub fn pointer(pointer: &str) -> Self {
        Self::keys(&pointer.split('/').skip(1).collect::<Vec<_>>())
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

//! The resources a provider can manage, described as specs that refer to
//! each other by name, and the field-by-field difference between two of them

mod diff;
mod path;
mod types;

pub use diff::{
    Comparable, ComparableValues, FieldChange, Row, ValueChange, changed_paths, compare_target,
    key_identity,
};
pub use path::{Path, Segment};
pub use types::{
    OptionReferences, ResourceKind, RoleSpec, SshClientKeySpec, TargetGroupSpec, TargetSpec,
};

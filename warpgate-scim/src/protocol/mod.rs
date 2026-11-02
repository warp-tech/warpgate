//! The SCIM wire format, independent of any storage.

pub mod discovery;
pub mod error;
pub mod filter;
pub mod patch;
pub mod query;
pub mod resource;

pub use error::{ScimError, ScimType};
pub use filter::{AttrPath, CompareOp, Filter};
pub use patch::{PatchOperation, PatchRequest, apply_patch};
pub use query::{ListQuery, SortOrder};

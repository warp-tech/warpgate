//! SCP Protocol Parser
//!
//! Parses SCP commands from exec requests for access control.

mod parser;
mod types;

pub use parser::ScpParser;
pub use types::*;

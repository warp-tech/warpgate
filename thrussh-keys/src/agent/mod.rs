/// Write clients for SSH agents.
pub mod client;
mod msg;
/// Write servers for SSH agents.
pub mod server;

/// Constraints on how keys can be used
#[derive(Debug, PartialEq, Eq)]
pub enum Constraint {
    /// The key shall disappear from the agent's memory after that many seconds.
    KeyLifetime { seconds: u32 },
    /// Signatures need to be confirmed by the agent (for instance using a dialog).
    Confirm,
    /// Custom constraints
    Extensions { name: Vec<u8>, details: Vec<u8> },
}

mod connection;
mod error;
mod queries;
mod types;

pub use connection::{connect, discover_base_dns, test_connection};
pub use error::{LdapError, Result};
pub use queries::{find_user_by_email, list_users};
pub use types::{LdapConfig, LdapUser};

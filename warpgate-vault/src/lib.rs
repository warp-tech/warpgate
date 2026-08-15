mod client;
mod error;
mod metadata;

pub use client::{VaultClient, grown_without_leaving_a_copy, login_payload};
pub use error::{Result, VaultError};

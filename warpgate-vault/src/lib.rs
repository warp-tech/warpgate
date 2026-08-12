mod client;
mod error;
mod metadata;

pub use client::{VaultClient, login_payload};
pub use error::{Result, VaultError};

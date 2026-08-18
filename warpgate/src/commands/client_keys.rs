use std::str::FromStr;

use anyhow::Result;
use warpgate_common::secrets::is_secret_reference;
use warpgate_common::{GlobalParams, SecretRef};
use warpgate_core::db::connect_to_db_and_migrate;
use warpgate_db_entities::SshClientKey;

use crate::config::load_config;

pub async fn command(params: &GlobalParams) -> Result<()> {
    let config = load_config(params, true)?;
    let db = connect_to_db_and_migrate(&config, params).await?;
    warpgate_protocol_ssh::ensure_client_keys(&db, &config, params).await?;

    let keys = SshClientKey::Entity::find_ordered().all(&db).await?;

    println!("Warpgate SSH client keys:");
    println!("(add these to your target's authorized_keys file)");
    println!();
    for key in keys {
        let default = if key.is_default { " (default)" } else { "" };
        let backend = is_secret_reference(&key.secret_key)
            .then(|| SecretRef::from_str(&key.secret_key).ok())
            .flatten()
            .map(|r| format!(" (from secret backend '{}')", r.backend))
            .unwrap_or_default();
        println!("{} {}{default}{backend}", key.public_key, key.label);
    }
    Ok(())
}

use anyhow::Result;
use warpgate_common::GlobalParams;

use crate::config::load_config;

pub fn command(params: &GlobalParams) -> Result<()> {
    let config = load_config(params, true)?;
    if let Some(backend) = warpgate_protocol_ssh::keys_managed_externally(&config) {
        println!("Warpgate SSH client keys are managed by secret backend '{backend}'.");
        println!(
            "Inspect them in your secret store, or via the admin UI (Config → SSH Keys page)."
        );
        return Ok(());
    }
    let keys = warpgate_protocol_ssh::load_keys_on_disk(&config, params, "client")?;
    println!("Warpgate SSH client keys:");
    println!("(add these to your target's authorized_keys file)");
    println!();
    for key in keys {
        println!("{}", key.public_key().to_openssh()?);
    }
    Ok(())
}

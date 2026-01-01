use anyhow::Result;
use warpgate_common::GlobalParams;

use crate::config::load_config;

pub(crate) async fn command(params: &GlobalParams) -> Result<()> {
    let config = load_config(params, true)?;
    let keys = warpgate_protocol_ssh::load_keys(&config, params, "client")?;
    println!("Warpgate SSH client keys:");
    println!("(add these to your target's authorized_keys file)");
    println!();
    for key in keys {
        println!("{}", key.public_key().to_openssh()?);
    }
    Ok(())
}

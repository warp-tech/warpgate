use anyhow::Result;

use crate::config::load_config;

pub(crate) async fn command(cli: &crate::Cli) -> Result<()> {
    let config = load_config(&cli.config, true)?;
    let keys = warpgate_protocol_ssh::load_keys(&config, "client")?;
    println!("Warpgate SSH client keys:");
    println!("(add these to your target's authorized_keys file)");
    println!();
    for key in keys {
        println!("{}", key.public_key().to_openssh()?);
    }
    Ok(())
}

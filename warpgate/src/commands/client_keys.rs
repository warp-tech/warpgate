use crate::config::load_config;
use anyhow::Result;
use warpgate_protocol_ssh::helpers::PublicKeyAsOpenSSH;

pub(crate) async fn command(cli: &crate::Cli) -> Result<()> {
    let config = load_config(&cli.config)?;
    let keys = warpgate_protocol_ssh::load_client_keys(&config)?;
    println!("Warpgate SSH client keys:");
    println!("(add these to your target's authorized_hosts file)");
    println!();
    for key in keys {
        println!("{}", key.as_openssh());
    }
    Ok(())
}

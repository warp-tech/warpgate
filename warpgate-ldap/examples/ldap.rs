use warpgate_tls::TlsMode;
use warpgate_ldap::*;

#[tokio::main]
async fn main() -> Result<()> {
    let config = LdapConfig {
        host: "192.168.77.97".into(),
        port: 389,
        bind_dn: "administrator@elements.intern".into(),
        bind_password: "syslink".into(),
        base_dns: vec!["dc=elements,dc=intern".into()],
        user_filter: "(objectClass=user)".into(),
        tls_mode: TlsMode::Disabled,
        tls_verify: false,
    };
    let mut ldap = connect(&config).await?;

    for dn in discover_base_dns(&config).await? {
        println!("Discovered base DN: {}", dn);
    }
    let users = list_users(&config).await?;
    for user in users {
        println!("Found user: {:?}", user);
    }
    Ok(())
}

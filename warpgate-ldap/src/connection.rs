use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use tracing::{debug, info, warn};

use crate::error::{LdapError, Result};
use crate::types::{LdapConfig, TlsMode};

pub async fn connect(config: &LdapConfig) -> Result<Ldap> {
    let url = build_ldap_url(config);
    debug!("Connecting to LDAP server: {}", url);

    // Configure connection settings based on TLS mode
    let settings = LdapConnSettings::new()
        .set_starttls(matches!(config.tls_mode, TlsMode::Preferred | TlsMode::Required))
        .set_no_tls_verify(!config.tls_verify);

    let (conn, mut ldap) = if matches!(config.tls_mode, TlsMode::Disabled) {
        // No TLS
        LdapConnAsync::new(&url)
            .await
            .map_err(|e| LdapError::ConnectionFailed(e.to_string()))?
    } else {
        // TLS or STARTTLS
        LdapConnAsync::with_settings(settings, &url)
            .await
            .map_err(|e| LdapError::ConnectionFailed(e.to_string()))?
    };

    // Bind with credentials
    ldap.simple_bind(&config.bind_dn, &config.bind_password)
        .await
        .map_err(|e| LdapError::AuthenticationFailed(e.to_string()))?
        .success()
        .map_err(|e| LdapError::AuthenticationFailed(e.to_string()))?;

    info!("Successfully connected and authenticated to LDAP server");

    // Spawn the connection driver
    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            warn!("LDAP connection driver error: {}", e);
        }
    });

    Ok(ldap)
}

pub async fn test_connection(config: &LdapConfig) -> Result<bool> {
    match connect(config).await {
        Ok(mut ldap) => {
            // Try to unbind cleanly
            let _ = ldap.unbind().await;
            Ok(true)
        }
        Err(e) => {
            debug!("Test connection failed: {}", e);
            Err(e)
        }
    }
}

pub async fn discover_base_dns(config: &LdapConfig) -> Result<Vec<String>> {
    let mut ldap = connect(config).await?;

    debug!("Querying rootDSE for naming contexts");

    // Query rootDSE for namingContexts
    let (rs, _res) = ldap
        .search(
            "",
            Scope::Base,
            "(objectClass=*)",
            vec!["namingContexts"],
        )
        .await
        .map_err(|e| LdapError::QueryFailed(e.to_string()))?
        .success()
        .map_err(|e| LdapError::QueryFailed(e.to_string()))?;

    let mut base_dns = Vec::new();

    for entry in rs {
        let entry = SearchEntry::construct(entry);
        if let Some(contexts) = entry.attrs.get("namingContexts") {
            for context in contexts {
                if !context.is_empty() {
                    base_dns.push(context.clone());
                }
            }
        }
    }

    let _ = ldap.unbind().await;

    if base_dns.is_empty() {
        warn!("No naming contexts found in rootDSE");
    } else {
        info!("Discovered {} base DN(s): {:?}", base_dns.len(), base_dns);
    }

    Ok(base_dns)
}

fn build_ldap_url(config: &LdapConfig) -> String {
    let scheme = match (&config.tls_mode, config.port) {
        (TlsMode::Disabled, _) => "ldap",
        (_, 636) => "ldaps",
        _ => "ldap",
    };

    format!("{}://{}:{}", scheme, config.host, config.port)
}

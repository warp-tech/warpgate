use std::collections::HashSet;

use ldap3::{Scope, SearchEntry};
use tracing::{debug, info};

use crate::connection::connect;
use crate::error::{LdapError, Result};
use crate::types::{LdapConfig, LdapUser};

// Attributes we request from LDAP for user discovery and SSH key sync.
// Kept as a single constant so all searches use the same set.
const LDAP_USER_ATTRIBUTES: &[&str] = &[
    "uid",
    "cn",
    "mail",
    "displayName",
    "sAMAccountName",
    "objectGUID",
    "entryUUID",
    "sshPublicKey",
];

/// Extract user details from an LDAP SearchEntry.
/// Returns None if no valid username can be determined.
fn extract_ldap_user(search_entry: SearchEntry) -> Option<LdapUser> {
    let dn = search_entry.dn.clone();

    // Extract username - try different attributes
    let username = search_entry
        .attrs
        .get("uid")
        .or_else(|| search_entry.attrs.get("sAMAccountName"))
        .or_else(|| search_entry.attrs.get("cn"))
        .and_then(|v| v.first())
        .cloned()?;

    let email = search_entry
        .attrs
        .get("mail")
        .and_then(|v| v.first())
        .cloned();

    let display_name = search_entry
        .attrs
        .get("displayName")
        .or_else(|| search_entry.attrs.get("cn"))
        .and_then(|v| v.first())
        .cloned();

    // Extract object UUID (Active Directory uses objectGUID, OpenLDAP uses entryUUID)
    let object_uuid = search_entry
        .attrs
        .get("objectGUID")
        .or_else(|| search_entry.attrs.get("entryUUID"))
        .and_then(|v| v.first())
        .cloned();

    // Extract SSH public keys
    let ssh_public_keys = search_entry
        .attrs
        .get("sshPublicKey")
        .cloned()
        .unwrap_or_default();

    Some(LdapUser {
        username,
        email,
        display_name,
        dn,
        object_uuid,
        ssh_public_keys,
    })
}

pub async fn list_users(config: &LdapConfig) -> Result<Vec<LdapUser>> {
    let mut ldap = connect(config).await?;

    let mut all_users = Vec::new();
    let mut seen_dns = HashSet::new();

    // Query each base DN
    for base_dn in &config.base_dns {
        debug!("Searching for users in base DN: {}", base_dn);

        let (rs, _res) = ldap
            .search(base_dn, Scope::Subtree, &config.user_filter, LDAP_USER_ATTRIBUTES.to_vec())
            .await
            .map_err(|e| LdapError::QueryFailed(format!("Search failed in {}: {}", base_dn, e)))?
            .success()
            .map_err(|e| LdapError::QueryFailed(format!("Search failed in {}: {}", base_dn, e)))?;

        for entry in rs {
            let search_entry = SearchEntry::construct(entry);
            let dn = search_entry.dn.clone();

            // Skip duplicates (same DN might appear in multiple searches)
            if seen_dns.contains(&dn) {
                continue;
            }
            seen_dns.insert(dn.clone());

            if let Some(user) = extract_ldap_user(search_entry) {
                all_users.push(user);
            }
        }
    }

    let _ = ldap.unbind().await;

    Ok(all_users)
}

pub async fn find_user_by_email(config: &LdapConfig, email: &str) -> Result<Option<LdapUser>> {
    let mut ldap = connect(config).await?;

    // Search all base DNs for a user with the given email
    for base_dn in &config.base_dns {
        let filter = format!("(&{}(mail={}))", config.user_filter, email);

        let (rs, _res) = ldap
            .search(base_dn, Scope::Subtree, &filter, LDAP_USER_ATTRIBUTES.to_vec())
            .await
            .map_err(|e| LdapError::QueryFailed(format!("Search failed in {}: {}", base_dn, e)))?
            .success()
            .map_err(|e| LdapError::QueryFailed(format!("Search failed in {}: {}", base_dn, e)))?;

        if !rs.is_empty() {
            let search_entry = SearchEntry::construct(rs.into_iter().next().unwrap());

            if let Some(user) = extract_ldap_user(search_entry) {
                let _ = ldap.unbind().await;

                info!("Found LDAP user with email {}: {}", email, user.username);

                return Ok(Some(user));
            }
        }
    }

    let _ = ldap.unbind().await;
    debug!("No user found with email: {}", email);
    Ok(None)
}

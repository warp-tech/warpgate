use std::collections::HashSet;
use std::fmt::Write;

use ldap3::{Scope, SearchEntry};
use tracing::{debug, info};
use uuid::Uuid;

use crate::connection::connect;
use crate::error::{LdapError, Result};
use crate::types::{LdapConfig, LdapUser};

fn ldap_user_attributes(config: &LdapConfig) -> Vec<String> {
    let mut attrs: Vec<String> = vec![
        "mail".into(),
        "displayName".into(),
        "userPrincipalName".into(),
    ];

    // Add UUID attributes - either custom or default ones
    if let Some(custom_uuid_attr) = &config.uuid_attribute {
        if !attrs.contains(custom_uuid_attr) {
            attrs.push(custom_uuid_attr.clone());
        }
    } else {
        // Default behavior: query both objectGUID and entryUUID
        attrs.push("objectGUID".into());
        attrs.push("entryUUID".into());
    }

    let username_attribute = config.username_attribute.attribute_name().to_string();
    if !attrs.contains(&username_attribute) {
        attrs.push(username_attribute);
    }
    if !attrs.contains(&config.ssh_key_attribute) {
        attrs.push(config.ssh_key_attribute.clone());
    }
    attrs
}

/// Extract user details from an LDAP [SearchEntry].
/// Returns None if no valid username can be determined.
fn extract_ldap_user(search_entry: SearchEntry, config: &LdapConfig) -> Option<LdapUser> {
    let dn = search_entry.dn.clone();

    // Extract username - try different attributes
    let username = search_entry
        .attrs
        .get(config.username_attribute.attribute_name())
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
        .and_then(|v| v.first())
        .cloned();

    // Extract object UUID - use custom attribute if set, otherwise default to objectGUID/entryUUID
    let object_uuid = if let Some(custom_uuid_attr) = &config.uuid_attribute {
        // Try custom attribute from binary attributes first
        search_entry
            .bin_attrs
            .get(custom_uuid_attr)
            .and_then(|v: &Vec<Vec<u8>>| v.first())
            .and_then(|b| Uuid::from_slice(&b[..]).ok())
    } else {
        // Default behavior: Active Directory uses objectGUID, OpenLDAP uses entryUUID
        search_entry
            .bin_attrs
            .get("objectGUID")
            .or_else(|| search_entry.bin_attrs.get("entryUUID"))
            .and_then(|v: &Vec<Vec<u8>>| v.first())
            .and_then(|b| Uuid::from_slice(&b[..]).ok())
    };

    // Extract SSH public keys
    let ssh_public_keys = search_entry
        .attrs
        .get(&config.ssh_key_attribute)
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
            .search(
                base_dn,
                Scope::Subtree,
                &config.user_filter,
                &ldap_user_attributes(config),
            )
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

            if let Some(user) = extract_ldap_user(search_entry, config) {
                all_users.push(user);
            }
        }
    }

    let _ = ldap.unbind().await;

    Ok(all_users)
}

pub async fn find_user_by_username(
    config: &LdapConfig,
    username: &str,
) -> Result<Option<LdapUser>> {
    let mut ldap = connect(config).await?;

    for base_dn in &config.base_dns {
        let filter = format!(
            "(&{}({}={}))",
            config.user_filter,
            config.username_attribute.attribute_name(),
            username
        );

        let (rs, _res) = ldap
            .search(
                base_dn,
                Scope::Subtree,
                &filter,
                &ldap_user_attributes(config),
            )
            .await
            .map_err(|e| LdapError::QueryFailed(format!("Search failed in {}: {}", base_dn, e)))?
            .success()
            .map_err(|e| LdapError::QueryFailed(format!("Search failed in {}: {}", base_dn, e)))?;

        if let Some(first_result) = rs.into_iter().next() {
            let search_entry = SearchEntry::construct(first_result);

            if let Some(user) = extract_ldap_user(search_entry, config) {
                let _ = ldap.unbind().await;

                info!(
                    "Found LDAP user with username {}: {}",
                    username, user.username
                );

                return Ok(Some(user));
            }
        }
    }

    let _ = ldap.unbind().await;
    debug!("No user found with username: {}", username);
    Ok(None)
}

pub async fn find_user_by_uuid(
    config: &LdapConfig,
    object_uuid: &Uuid,
) -> Result<Option<LdapUser>> {
    let mut ldap = connect(config).await?;

    // Convert UUID to different formats for searching
    // OpenLDAP uses standard UUID string format (with dashes)
    let uuid_str = object_uuid.to_string();

    // Active Directory stores objectGUID as binary and requires hex encoding in filters
    // Convert UUID bytes to escaped hex string for LDAP filter (e.g., \01\02\03...)
    let uuid_bytes = object_uuid.as_bytes();
    let ad_guid_hex = uuid_bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(&mut s, "\\{:02x}", b);
        s
    });

    // Build the filter based on whether we have a custom UUID attribute
    let filter = if let Some(custom_uuid_attr) = &config.uuid_attribute {
        // Use custom UUID attribute
        format!(
            "(&{}(|({custom_uuid_attr}={uuid_str})({custom_uuid_attr}={ad_guid_hex})))",
            config.user_filter,
        )
    } else {
        // Default behavior: query both objectGUID and entryUUID
        format!(
            "(&{}(|(objectGUID={uuid_str})(objectGUID={ad_guid_hex})(entryUUID={uuid_str})))",
            config.user_filter,
        )
    };

    for base_dn in &config.base_dns {
        let (rs, _res) = ldap
            .search(
                base_dn,
                Scope::Subtree,
                &filter,
                vec!["*", "+"], // Request all user attributes (*) and operational attributes (+)
            )
            .await
            .map_err(|e| LdapError::QueryFailed(format!("Search failed in {}: {}", base_dn, e)))?
            .success()
            .map_err(|e| LdapError::QueryFailed(format!("Search failed in {}: {}", base_dn, e)))?;

        if !rs.is_empty() {
            #[allow(clippy::unwrap_used, reason = "length checked")]
            let search_entry = SearchEntry::construct(rs.into_iter().next().unwrap());

            if let Some(user) = extract_ldap_user(search_entry, config) {
                let _ = ldap.unbind().await;

                debug!(
                    "Found LDAP user with UUID {}: {}",
                    object_uuid, user.username
                );

                return Ok(Some(user));
            }
        }
    }

    let _ = ldap.unbind().await;
    debug!("No user found with UUID: {}", object_uuid);
    Ok(None)
}

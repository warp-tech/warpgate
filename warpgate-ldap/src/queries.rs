use std::collections::HashSet;
use std::fmt::Write;

use ldap3::{Scope, SearchEntry};
use tracing::{debug, warn};
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
/// Returns None if no valid username or UUID can be determined.
fn extract_ldap_user(search_entry: SearchEntry, config: &LdapConfig) -> Result<LdapUser> {
    let dn = search_entry.dn.clone();

    // Extract username - try different attributes
    let username = search_entry
        .attrs
        .get(config.username_attribute.attribute_name())
        .and_then(|v| v.first())
        .cloned()
        .ok_or(LdapError::NoUsername(dn.clone()))?;

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

    let object_uuid = if let Some(custom_uuid_attr) = &config.uuid_attribute {
        // Try parsing as a binary UUID
        search_entry
            .bin_attrs
            .get(custom_uuid_attr)
            .and_then(|v: &Vec<Vec<u8>>| v.first())
            .and_then(|b|
                Uuid::from_slice(&b[..])
                    .inspect_err(|e| {
                        warn!("Failed to parse UUID {b:?} from LDAP attribute {custom_uuid_attr}: {e}");
                    })
                    .ok())
            .or_else(|| {
                // Try parsing as a string UUID
                search_entry
                    .attrs
                    .get(custom_uuid_attr)
                    .and_then(|v| v.first())
                    .and_then(|s| {
                        Uuid::parse_str(&s)
                            .inspect_err(|e| {
                                warn!("Failed to parse UUID {s} from LDAP attribute {custom_uuid_attr}: {e}");
                            })
                            .ok()
                    })
            })
    } else {
        // Default behavior: Active Directory uses objectGUID, OpenLDAP uses entryUUID
        search_entry
            .bin_attrs
            .get("objectGUID")
            .or_else(|| search_entry.bin_attrs.get("entryUUID"))
            .and_then(|v: &Vec<Vec<u8>>| v.first())
            .and_then(|b| Uuid::from_slice(&b[..]).ok())
    }
    .ok_or(LdapError::NoUUID(dn.clone()))?;

    // Extract SSH public keys
    let ssh_public_keys = search_entry
        .attrs
        .get(&config.ssh_key_attribute)
        .cloned()
        .unwrap_or_default();

    Ok(LdapUser {
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

            match extract_ldap_user(search_entry, config) {
                Ok(user) => {
                    all_users.push(user);
                }
                Err(e) => {
                    warn!("Skipping LDAP user {dn}: {e}");
                    continue;
                }
            }
        }
    }

    Ok(all_users)
}

pub async fn find_user_by_username(
    config: &LdapConfig,
    username: &str,
) -> Result<Option<LdapUser>> {
    let mut ldap = connect(config).await?;

    let filter = format!(
        "(&{}({}={}))",
        config.user_filter,
        config.username_attribute.attribute_name(),
        username
    );

    if let Some(user) = find_user_by_filter(&mut ldap, config, &filter).await? {
        return Ok(Some(user));
    }

    debug!("No user found with username: {username}");
    Ok(None)
}

async fn find_user_by_filter(
    ldap: &mut ldap3::Ldap,
    config: &LdapConfig,
    filter: &str,
) -> Result<Option<LdapUser>> {
    debug!("Searching LDAP with filter: {filter}");
    for base_dn in &config.base_dns {
        let (rs, _res) = ldap
            .search(
                base_dn,
                Scope::Subtree,
                filter,
                vec!["*", "+"], // Request all user attributes (*) and operational attributes (+)
            )
            .await
            .map_err(|e| LdapError::QueryFailed(e.to_string()))?
            .success()
            .map_err(|e| LdapError::QueryFailed(e.to_string()))?;

        if !rs.is_empty() {
            #[allow(clippy::unwrap_used, reason = "length checked")]
            let search_entry = SearchEntry::construct(rs.into_iter().next().unwrap());

            match extract_ldap_user(search_entry, config) {
                Ok(user) => {
                    debug!("Found LDAP user with filter {filter}: {user:?}");
                    return Ok(Some(user));
                }
                Err(e) => {
                    warn!("LDAP result extraction failed for filter {filter}: {e}");
                    continue;
                }
            }
        }
    }
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
    let binary_guid_str = {
        let uuid_bytes = object_uuid.as_bytes();
        uuid_bytes.iter().fold(String::new(), |mut s, b| {
            let _ = write!(&mut s, "\\{:02x}", b);
            s
        })
    };

    let user_filter = &config.user_filter;

    if let Some(custom_uuid_attr) = &config.uuid_attribute {
        // Note: the reason for doing multiple separate requests is for `lldap` compatibility
        // lldap does not support queries with non-UTF8 attribute values and fails if
        // we try to query with multiple values OR'ed

        if let Some(user) = find_user_by_filter(
            &mut ldap,
            config,
            &format!("(&{user_filter}({custom_uuid_attr}={uuid_str}))"),
        )
        .await?
        {
            return Ok(Some(user));
        }

        // Active Directory
        if let Some(user) = find_user_by_filter(
            &mut ldap,
            config,
            &format!("(&{user_filter}({custom_uuid_attr}={binary_guid_str}))"),
        )
        .await?
        {
            return Ok(Some(user));
        }
    } else {
        if let Some(user) = find_user_by_filter(
            &mut ldap,
            config,
            // OpenLDAP style
            &format!("(&{user_filter}(entryUUID={uuid_str}))"),
        )
        .await?
        {
            return Ok(Some(user));
        }

        if let Some(user) = find_user_by_filter(
            &mut ldap,
            config,
            &format!("(&{user_filter}(objectGUID={uuid_str}))"),
        )
        .await?
        {
            return Ok(Some(user));
        }

        if let Some(user) = find_user_by_filter(
            &mut ldap,
            config,
            // Active Directory
            &format!("(&{user_filter}(objectGUID={binary_guid_str}))"),
        )
        .await?
        {
            return Ok(Some(user));
        }
    }

    debug!("No user found with UUID: {}", object_uuid);
    Ok(None)
}

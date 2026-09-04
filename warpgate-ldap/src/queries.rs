use std::collections::HashSet;
use std::fmt::Write;

use ldap3::{Scope, SearchEntry, ldap_escape};
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
fn extract_ldap_user(search_entry: &SearchEntry, config: &LdapConfig) -> Result<LdapUser> {
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

    #[allow(clippy::option_if_let_else)]
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
                        Uuid::parse_str(s)
                            .inspect_err(|e| {
                                warn!("Failed to parse UUID {s} from LDAP attribute {custom_uuid_attr}: {e}");
                            })
                            .ok()
                    })
            })
    } else {
        // Active Directory returns objectGUID as 16 raw bytes, so it lands in
        // bin_attrs. entryUUID is a dashed string, which ldap3 decodes into
        // attrs instead, so it has to be parsed from there.
        search_entry
            .bin_attrs
            .get("objectGUID")
            .or_else(|| search_entry.bin_attrs.get("entryUUID"))
            .and_then(|v: &Vec<Vec<u8>>| v.first())
            .and_then(|b| Uuid::from_slice(&b[..]).ok())
            .or_else(|| {
                search_entry
                    .attrs
                    .get("entryUUID")
                    .and_then(|v| v.first())
                    .and_then(|s| Uuid::parse_str(s).ok())
            })
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
            .map_err(|e| LdapError::QueryFailed(format!("Search failed in {base_dn}: {e}")))?
            .success()
            .map_err(|e| LdapError::QueryFailed(format!("Search failed in {base_dn}: {e}")))?;

        for entry in rs {
            let search_entry = SearchEntry::construct(entry);
            let dn = search_entry.dn.clone();

            // Skip duplicates (same DN might appear in multiple searches)
            if seen_dns.contains(&dn) {
                continue;
            }
            seen_dns.insert(dn.clone());

            match extract_ldap_user(&search_entry, config) {
                Ok(user) => {
                    all_users.push(user);
                }
                Err(e) => {
                    warn!("Skipping LDAP user {dn}: {e}");
                }
            }
        }
    }

    Ok(all_users)
}

/// Filter matching a single user by their username attribute.
///
/// The username is attacker-influenced — an OIDC `preferred_username` claim
/// reaches here through SSO auto-create — so it is escaped as a filter *value*.
/// `config.user_filter` is deliberately left raw: it is an admin-authored filter
/// fragment, and escaping it would break every existing configuration.
fn username_filter(config: &LdapConfig, username: &str) -> String {
    format!(
        "(&{}({}={}))",
        config.user_filter,
        config.username_attribute.attribute_name(),
        ldap_escape(username)
    )
}

pub async fn find_user_by_username(
    config: &LdapConfig,
    username: &str,
) -> Result<Option<LdapUser>> {
    let mut ldap = connect(config).await?;

    let filter = username_filter(config, username);

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

        // More than one match means the filter didn't identify a single person.
        // Taking the first would let a widened filter — say a username of `*`,
        // turning this into a presence search — bind an account to an arbitrary
        // directory entry, so an ambiguous result is an error rather than a
        // choice.
        if rs.len() > 1 {
            return Err(LdapError::AmbiguousMatch {
                filter: filter.to_owned(),
                count: rs.len(),
            });
        }

        if let Some(entry) = rs.into_iter().next() {
            let search_entry = SearchEntry::construct(entry);

            match extract_ldap_user(&search_entry, config) {
                Ok(user) => {
                    debug!("Found LDAP user with filter {filter}: {user:?}");
                    return Ok(Some(user));
                }
                Err(e) => {
                    warn!("LDAP result extraction failed for filter {filter}: {e}");
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
            let _ = write!(&mut s, "\\{b:02x}");
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

#[cfg(test)]
mod tests {
    use ldap3::SearchEntry;
    use uuid::Uuid;
    use warpgate_tls::TlsMode;

    use super::{extract_ldap_user, username_filter};
    use crate::types::{LdapConfig, LdapUsernameAttribute};

    fn config() -> LdapConfig {
        LdapConfig {
            host: "ldap.example.com".into(),
            port: 389,
            bind_dn: String::new(),
            bind_password: String::new(),
            tls_mode: TlsMode::Preferred,
            tls_verify: true,
            base_dns: vec!["dc=example,dc=com".into()],
            user_filter: "(objectClass=person)".into(),
            username_attribute: LdapUsernameAttribute::Cn,
            ssh_key_attribute: "sshPublicKey".into(),
            uuid_attribute: None,
        }
    }

    #[test]
    fn plain_username_is_unchanged() {
        assert_eq!(
            username_filter(&config(), "alice"),
            "(&(objectClass=person)(cn=alice))"
        );
    }

    #[test]
    fn filter_metacharacters_in_a_username_are_escaped() {
        // A bare `*` would otherwise turn this into a presence filter matching
        // every entry, and `)(` would let the username close the clause and
        // append one of its own.
        for (username, escaped) in [
            ("*", "\\2a"),
            ("(", "\\28"),
            (")", "\\29"),
            ("\\", "\\5c"),
            ("\0", "\\00"),
        ] {
            let filter = username_filter(&config(), username);
            assert_eq!(filter, format!("(&(objectClass=person)(cn={escaped}))"));
        }

        assert_eq!(
            username_filter(&config(), "x)(uid=admin"),
            "(&(objectClass=person)(cn=x\\29\\28uid=admin))"
        );
    }

    #[test]
    fn admin_authored_user_filter_is_left_raw() {
        let mut config = config();
        config.user_filter = "(&(objectClass=person)(!(disabled=TRUE)))".into();
        assert!(
            username_filter(&config, "alice")
                .starts_with("(&(&(objectClass=person)(!(disabled=TRUE)))")
        );
    }

    const ENTRY_UUID: &str = "94708f40-8e23-103d-8006-951699206877";

    fn search_entry(attrs: &[(&str, &str)], bin_attrs: &[(&str, Vec<u8>)]) -> SearchEntry {
        SearchEntry {
            dn: "cn=alice,dc=example,dc=com".into(),
            attrs: attrs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), vec![(*v).to_owned()]))
                .collect(),
            bin_attrs: bin_attrs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), vec![v.clone()]))
                .collect(),
        }
    }

    #[test]
    fn a_string_entry_uuid_is_read_when_no_uuid_attribute_is_configured() {
        // ldap3 decodes a dashed entryUUID as UTF-8 into `attrs`, so looking
        // only in `bin_attrs` misses what OpenLDAP and hosted directories
        // return, and the entry is discarded as having no UUID.
        let entry = search_entry(&[("cn", "alice"), ("entryUUID", ENTRY_UUID)], &[]);
        let user = extract_ldap_user(&entry, &config()).unwrap();
        assert_eq!(user.username, "alice");
        assert_eq!(user.object_uuid, Uuid::parse_str(ENTRY_UUID).unwrap());
    }

    #[test]
    fn a_binary_object_guid_is_still_read() {
        let raw = vec![7u8; 16];
        let entry = search_entry(&[("cn", "alice")], &[("objectGUID", raw.clone())]);
        let user = extract_ldap_user(&entry, &config()).unwrap();
        assert_eq!(user.object_uuid, Uuid::from_slice(&raw).unwrap());
    }

    #[test]
    fn a_configured_uuid_attribute_may_hold_a_string() {
        let mut config = config();
        config.uuid_attribute = Some("entryUUID".into());
        let entry = search_entry(&[("cn", "alice"), ("entryUUID", ENTRY_UUID)], &[]);
        let user = extract_ldap_user(&entry, &config).unwrap();
        assert_eq!(user.object_uuid, Uuid::parse_str(ENTRY_UUID).unwrap());
    }

    #[test]
    fn an_entry_carrying_no_uuid_is_rejected() {
        let entry = search_entry(&[("cn", "alice")], &[]);
        assert!(extract_ldap_user(&entry, &config()).is_err());
    }
}

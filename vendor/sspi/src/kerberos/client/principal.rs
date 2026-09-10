//! Helpers deriving the Kerberos client principal (name, name type and realm) from credentials.

use std::env;
use std::path::Path;

use picky_krb::constants::types::{NT_ENTERPRISE, NT_PRINCIPAL};

use crate::krb::Krb5Conf;
use crate::{Username, UsernameParts};

/// [MS-KILE] 3.3.5.6.1 Client Principal Lookup
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6435d3fb-8cf6-4df5-a156-1277690ed59c
//
// FIXME: this should take a `&Username` instead of two `&str` parameters. It currently sniffs for an
// `@` to guess the name type (and ignores `_domain` entirely), which is exactly the lossy heuristic
// `Username`/`UsernameParts` exist to replace: the name type can be read off the user name format
// directly (see `get_client_principal_name`). Once the deprecated string-based callers are gone (#708),
// fold this into `get_client_principal_name`.
pub fn get_client_principal_name_type(username: &str, _domain: &str) -> u8 {
    if username.contains('@') {
        NT_ENTERPRISE
    } else {
        NT_PRINCIPAL
    }
}

/// The Kerberos client name (cname) derived from a [`Username`], along with the pieces needed to
/// build the AS-REQ.
///
/// This centralizes the mapping from a [`UserNameFormat`](crate::UserNameFormat) to a Kerberos
/// principal name type: it reads the name type off the username format explicitly instead of
/// sniffing for an `@`, so a UPN principal is an NT-ENTERPRISE name (whose full value is the client
/// name) and a down-level logon name is an NT-PRINCIPAL name identified by its account name alone.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ClientPrincipalName<'a> {
    /// The name to place in the AS-REQ as the Kerberos client name (cname).
    pub name: &'a str,
    /// The domain used to resolve the client realm (the UPN suffix or the NetBIOS domain).
    pub realm_domain: &'a str,
    /// The Kerberos principal name type (`NT-ENTERPRISE` or `NT-PRINCIPAL`).
    pub name_type: u8,
}

/// Derives the [`ClientPrincipalName`] for a principal from its user name format.
pub fn get_client_principal_name(username: &Username) -> ClientPrincipalName<'_> {
    match username.parts() {
        UsernameParts::UserPrincipalName(parts) => ClientPrincipalName {
            name: parts.upn(),
            realm_domain: parts.suffix(),
            name_type: NT_ENTERPRISE,
        },
        UsernameParts::DownLevelLogonName(parts) => ClientPrincipalName {
            name: parts.account_name(),
            realm_domain: parts.netbios_domain().unwrap_or_default(),
            name_type: NT_PRINCIPAL,
        },
    }
}

// FIXME: like `get_client_principal_name_type`, this should take a `&Username` (or a `UsernameParts`)
// instead of two `&str` parameters. `get_client_principal_realm_impl` re-derives the suffix by
// splitting on `@` to reconcile the `username`/`domain` pair, which duplicates the parsing
// `Username::parts()` already does. Migrating callers off the raw-string form (#708) would
// let this take the parsed username directly and drop the ad-hoc split.
pub fn get_client_principal_realm(username: &str, domain: &str) -> String {
    // https://web.mit.edu/kerberos/krb5-current/doc/user/user_config/kerberos.html#environment-variables

    let krb5_config = env::var("KRB5_CONFIG").unwrap_or_else(|_| "/etc/krb5.conf:/usr/local/etc/krb5.conf".to_string());
    let krb5_conf_paths = krb5_config.split(':').map(Path::new).collect::<Vec<&Path>>();

    get_client_principal_realm_impl(&krb5_conf_paths, username, domain)
}

fn get_client_principal_realm_impl(krb5_conf_paths: &[&Path], username: &str, domain: &str) -> String {
    let domain = if domain.is_empty() {
        // Match `Username::parse`, which splits a UPN on its *last* `@` (account names may contain `@`).
        if let Some((_left, right)) = username.rsplit_once('@') {
            right.to_string()
        } else {
            String::new()
        }
    } else {
        domain.to_string()
    };

    for krb5_conf_path in krb5_conf_paths {
        if !krb5_conf_path.exists() {
            continue;
        }

        if let Some(krb5_conf) = Krb5Conf::new_from_file(krb5_conf_path)
            && let Some(mappings) = krb5_conf.get_values_in_section(&["domain_realm"])
        {
            for (mapping_domain, realm) in mappings {
                if matches_domain(&domain, mapping_domain) {
                    return realm.to_owned();
                }
            }
        }
    }

    domain.to_uppercase()
}

/// Checks if the given domain matches the mapping domain (usually from krb5.conf file).
///
/// # Mapping rules
///
/// We follow the MIT KRB5 behavior: https://github.com/krb5/krb5/commit/8f5ce824012f2caab6770df464f096c38dc4cb2e.
///
/// - If the mapping domain starts with a dot (e.g., `.example.com`),
///   it matches all hosts under the domain, but not the host with the name `example.com`.
///   For example, "test.example.com" or "d1.example.com" will match `.example.com`, but `example.com` will not.
/// - If the mapping domain does not start with a dot (e.g., `example.com`),
///   it matches all hosts under the domain `example.com` (including `example.com`).
///
/// So, the mappings order in `krb5.conf` matters.
fn matches_domain(domain: &str, mapping_domain: &str) -> bool {
    let domain = domain.to_lowercase();
    let mapping_domain = mapping_domain.to_lowercase();

    if mapping_domain.starts_with('.') {
        // If mapping_domain starts with a dot, it matches subdomains only
        // e.g., `.example.com` matches `test.example.com` but not `example.com`
        domain.ends_with(&mapping_domain)
    } else {
        // If mapping_domain doesn't start with a dot, it matches the domain itself
        // and all subdomains (e.g., `example.com` matches `example.com` and `test.example.com`).
        domain == mapping_domain || domain.ends_with(&format!(".{mapping_domain}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KRB5_CONFIG_FILE_PATH: &str = "test_assets/krb5.conf";

    #[test]
    fn client_principal_name_from_upn_is_enterprise() {
        let username = Username::parse("user@example.com").expect("UPN");
        let cname = get_client_principal_name(&username);
        assert_eq!(cname.name, "user@example.com");
        assert_eq!(cname.realm_domain, "example.com");
        assert_eq!(cname.name_type, NT_ENTERPRISE);
    }

    #[test]
    fn client_principal_name_from_down_level_is_principal() {
        let username = Username::parse("EXAMPLE\\user").expect("down-level logon name");
        let cname = get_client_principal_name(&username);
        assert_eq!(cname.name, "user");
        assert_eq!(cname.realm_domain, "EXAMPLE");
        assert_eq!(cname.name_type, NT_PRINCIPAL);
    }

    #[test]
    fn client_principal_name_from_bare_name_has_empty_realm_domain() {
        let username = Username::parse("user").expect("bare name");
        let cname = get_client_principal_name(&username);
        assert_eq!(cname.name, "user");
        assert_eq!(cname.realm_domain, "");
        assert_eq!(cname.name_type, NT_PRINCIPAL);
    }

    #[test]
    fn test_get_client_principal_realm_from_domain() {
        let realm = get_client_principal_realm_impl(&[Path::new(KRB5_CONFIG_FILE_PATH)], "", "TBT.COM");
        assert_eq!(realm, "TBT.COM");

        let realm = get_client_principal_realm_impl(&[Path::new(KRB5_CONFIG_FILE_PATH)], "", "C1.DEV.TBT.COM");
        assert_eq!(realm, "TEST.TBT.COM");

        let realm = get_client_principal_realm_impl(&[Path::new(KRB5_CONFIG_FILE_PATH)], "", "P1.C2.DEV.TBT.COM");
        assert_eq!(realm, "TEST.TBT.COM");

        let realm = get_client_principal_realm_impl(&[Path::new(KRB5_CONFIG_FILE_PATH)], "", "DEV.TBT.COM");
        assert_eq!(realm, "DEV.TBT.COM");

        let realm = get_client_principal_realm_impl(&[Path::new(KRB5_CONFIG_FILE_PATH)], "", "TEST.TBT.COM");
        assert_eq!(realm, "STAGE.TBT.COM");
    }

    #[test]
    fn test_get_client_principal_realm_from_username() {
        let realm = get_client_principal_realm_impl(&[Path::new(KRB5_CONFIG_FILE_PATH)], "user@tbt.com", "");
        assert_eq!(realm, "TBT.COM");

        let realm = get_client_principal_realm_impl(&[Path::new(KRB5_CONFIG_FILE_PATH)], "user@c1.dev.tbt.com", "");
        assert_eq!(realm, "TEST.TBT.COM");

        let realm = get_client_principal_realm_impl(&[Path::new(KRB5_CONFIG_FILE_PATH)], "user@p1.c2.dev.tbt.com", "");
        assert_eq!(realm, "TEST.TBT.COM");

        let realm = get_client_principal_realm_impl(&[Path::new(KRB5_CONFIG_FILE_PATH)], "user@dev.tbt.com", "");
        assert_eq!(realm, "DEV.TBT.COM");

        let realm = get_client_principal_realm_impl(&[Path::new(KRB5_CONFIG_FILE_PATH)], "user@test.tbt.com", "");
        assert_eq!(realm, "STAGE.TBT.COM");
    }

    #[test]
    fn realm_from_username_splits_on_last_at() {
        // `Username::parse` splits a UPN on its *last* `@`, so the realm must be derived from the
        // suffix after the final `@` even when the account name itself contains an `@`.
        let realm = get_client_principal_realm_impl(&[Path::new(KRB5_CONFIG_FILE_PATH)], "user@dept@tbt.com", "");
        assert_eq!(realm, "TBT.COM");
    }
}

//! Shared fixtures for this crate's tests.
//!
//! `Target` and `User` have more fields than any single test cares about, so they are built
//! here once: a new required field on either is then one edit rather than one per test module.

#![allow(
    dead_code,
    reason = "not every fixture is used under every feature combination"
)]

use uuid::Uuid;
use warpgate_common::{Target, TargetHTTPOptions, TargetOptions, Tls, User};

/// An HTTP target reachable at `http://target`.
pub(crate) fn http_target(name: &str, require_approval: bool) -> Target {
    Target {
        id: Uuid::new_v4(),
        name: name.into(),
        description: String::new(),
        allow_roles: vec![],
        options: TargetOptions::Http(TargetHTTPOptions {
            url: "http://target".into(),
            tls: Tls::default(),
            headers: Default::default(),
            external_host: None,
        }),
        rate_limit_bytes_per_second: None,
        group_id: None,
        ticket_max_duration_seconds: None,
        ticket_requests_disabled: false,
        ticket_require_approval: false,
        require_approval,
        ticket_max_uses: None,
    }
}

pub(crate) fn test_user(username: &str) -> User {
    User {
        id: Uuid::new_v4(),
        username: username.into(),
        description: String::new(),
        credential_policy: None,
        rate_limit_bytes_per_second: None,
        ldap_server_id: None,
        allowed_ip_ranges: None,
    }
}

//! Maps SCIM resources onto Warpgate's tables.
//!
//! A SCIM User is a row of `users`; a SCIM Group is an access role (`roles`)
//! whose members are the active `user_roles` assignments. Mutations return the
//! [`Effects`] the caller must apply with the running services (closing
//! sessions), so the store itself needs only a database connection and can be
//! tested on an in-memory one.

mod common;
pub mod groups;
pub mod sso_link;
pub mod users;

pub use common::ScimTimestamps;
use sea_orm::DatabaseConnection;
use uuid::Uuid;

/// What a mutation changed beyond the rows: sessions the caller has to end.
#[derive(Debug, Default, PartialEq, Eq)]
#[must_use = "the sessions this names must be closed"]
pub struct Effects {
    /// Users whose every open session must end (disabled or deleted).
    pub close_sessions_of_users: Vec<Uuid>,
    /// A role membership was revoked or a role deleted: sessions admitted by
    /// it must end (`Services::close_sessions_without_role_access`).
    pub role_access_changed: bool,
}

impl Effects {
    pub fn merge(&mut self, other: Self) {
        self.close_sessions_of_users
            .extend(other.close_sessions_of_users);
        self.role_access_changed |= other.role_access_changed;
    }
}

/// The store for one request.
pub struct Store<'a> {
    pub db: &'a DatabaseConnection,
    /// Absolute URL of the SCIM root without a trailing slash, for `$ref`
    /// and `meta.location`.
    pub base: &'a str,
    /// The SSO provider whose credential follows the user's primary email
    /// (see `sso_link`); `None` leaves SSO credentials alone.
    pub sso_provider: Option<&'a str>,
}

impl Store<'_> {
    pub fn user_location(&self, id: Uuid) -> String {
        format!("{}/Users/{id}", self.base)
    }

    pub fn group_location(&self, id: Uuid) -> String {
        format!("{}/Groups/{id}", self.base)
    }
}

#[cfg(test)]
pub(crate) mod tests;

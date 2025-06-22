use std::net::{Ipv6Addr, SocketAddr};
use std::time::Duration;

use crate::{ListenEndpoint, Secret};

pub(crate) const fn _default_true() -> bool {
    true
}

pub(crate) const fn _default_false() -> bool {
    false
}

pub(crate) const fn _default_ssh_port() -> u16 {
    22
}

pub(crate) const fn _default_mysql_port() -> u16 {
    3306
}

#[inline]
pub(crate) fn _default_username() -> String {
    "root".to_owned()
}

#[inline]
pub(crate) fn _default_empty_string() -> String {
    "".to_owned()
}

#[inline]
pub(crate) fn _default_recordings_path() -> String {
    "./data/recordings".to_owned()
}

#[inline]
pub(crate) fn _default_database_url() -> Secret<String> {
    Secret::new("sqlite:data/db".to_owned())
}

#[inline]
pub(crate) fn _default_http_listen() -> ListenEndpoint {
    ListenEndpoint::from(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 8888))
}

#[inline]
pub(crate) fn _default_mysql_listen() -> ListenEndpoint {
    ListenEndpoint::from(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 33306))
}

#[inline]
pub(crate) fn _default_postgres_listen() -> ListenEndpoint {
    ListenEndpoint::from(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 55432))
}

#[inline]
pub(crate) fn _default_kubernetes_listen() -> ListenEndpoint {
    ListenEndpoint::from(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 8443))
}

#[inline]
pub(crate) fn _default_retention() -> Duration {
    Duration::from_secs(60 * 60 * 24 * 7)
}

#[inline]
pub(crate) fn _default_session_max_age() -> Duration {
    Duration::from_secs(60 * 30)
}

#[inline]
pub(crate) fn _default_cookie_max_age() -> Duration {
    Duration::from_secs(60 * 60 * 24)
}

#[inline]
pub(crate) fn _default_empty_vec<T>() -> Vec<T> {
    vec![]
}

pub(crate) fn _default_ssh_listen() -> ListenEndpoint {
    ListenEndpoint::from(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 2222))
}

pub(crate) fn _default_ssh_keys_path() -> String {
    "./data/keys".to_owned()
}

pub(crate) fn _default_ssh_inactivity_timeout() -> Duration {
    Duration::from_secs(60 * 5)
}

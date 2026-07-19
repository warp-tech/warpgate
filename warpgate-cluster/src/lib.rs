//! Cluster-internal transport: proxying node-owned resources between nodes, and
//! the RPCs that ride on it.
//!
//! Split out from `warpgate-common-http` so that the HTTP middleware crate every
//! endpoint depends on doesn't drag in a TLS client stack (reqwest, rustls,
//! tokio-tungstenite) and the CA/TLS crates that only peer-to-peer traffic needs.

pub mod approvals;
pub mod proxy;

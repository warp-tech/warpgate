//! SCIM 2.0 (RFC 7643 / RFC 7644) provisioning server for Warpgate.
//!
//! * [`protocol`] — the wire format: resources, filters, PATCH, errors and
//!   discovery documents. Pure, no database.
//! * [`store`] — maps SCIM Users to Warpgate users and SCIM Groups to access
//!   roles and their memberships.
//! * [`http`] — the `poem` app mounted at `/@warpgate/scim/v2`, with its own
//!   bearer-token gate.

pub mod http;
pub mod protocol;
pub mod store;

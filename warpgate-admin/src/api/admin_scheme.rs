//! The admin-API auth gate: a `SecurityScheme` that both *checks* admin access and *extracts*
//! the request context + the caller's permission set at once. Obtaining an [`AdminContext`]
//! (or [`ClusterOrAdminContext`]) IS the admin check — a handler cannot be reached without it,
//! so the gate can't be forgotten the way a hand-written first line can. This is the admin
//! counterpart to the gateway's `AuthedSession`.

use poem::Request;
use poem_openapi::SecurityScheme;
use poem_openapi::auth::ApiKey;
use warpgate_common::{AdminPermission, AdminPermissionSet, WarpgateError};
use warpgate_common_http::{AuthenticatedRequestContext, RequestAuthorization};

use super::common::admin_permission_set;

/// Proof that a specific [`AdminPermission`] was checked. Minted only by
/// [`AdminContext::require`]; take it where a permission must have been verified so
/// "checked before acting" is enforced by the type rather than by convention.
#[must_use = "obtain from AdminContext::require to prove the permission was checked"]
pub(crate) struct PermissionGranted(());

/// The authenticated context plus the resolved admin permission set, shared by both gates.
#[derive(Clone)]
struct AdminAccess {
    ctx: AuthenticatedRequestContext,
    permissions: AdminPermissionSet,
}

impl AdminAccess {
    fn require(&self, permission: AdminPermission) -> Result<(), WarpgateError> {
        if self.permissions.contains(permission) {
            Ok(())
        } else {
            Err(WarpgateError::NoAdminPermission(permission))
        }
    }
}

/// Checker for [`AdminContext`]: authenticated **and** holding at least one admin permission.
/// A DB error resolving the permission set rejects (fail closed).
async fn admin_access(req: &Request, _key: ApiKey) -> Option<AdminAccess> {
    let ctx = req.data::<AuthenticatedRequestContext>().cloned()?;
    let permissions = admin_permission_set(&ctx).await.ok()?;
    if permissions.is_admin() {
        Some(AdminAccess { ctx, permissions })
    } else {
        None
    }
}

/// Checker for [`ClusterOrAdminContext`]: as above, but a cluster peer is also accepted — the
/// origin node has already authorized the admin before forwarding, so it gets every permission.
async fn cluster_or_admin_access(req: &Request, _key: ApiKey) -> Option<AdminAccess> {
    let ctx = req.data::<AuthenticatedRequestContext>().cloned()?;
    if matches!(ctx.auth, RequestAuthorization::ClusterToken) {
        return Some(AdminAccess {
            ctx,
            permissions: AdminPermissionSet::all(),
        });
    }
    let permissions = admin_permission_set(&ctx).await.ok()?;
    if permissions.is_admin() {
        Some(AdminAccess { ctx, permissions })
    } else {
        None
    }
}

#[derive(SecurityScheme)]
#[oai(
    rename = "TokenSecurityScheme",
    ty = "api_key",
    key_name = "X-Warpgate-Token",
    key_in = "header",
    checker = "admin_access"
)]
pub(crate) struct AdminTokenAuth(AdminAccess);

#[derive(SecurityScheme)]
#[oai(
    rename = "CookieSecurityScheme",
    ty = "api_key",
    key_name = "warpgate-http-session",
    key_in = "cookie",
    checker = "admin_access"
)]
pub(crate) struct AdminCookieAuth(AdminAccess);

/// Admin gate + context extractor. Obtaining it proves the caller is an administrator;
/// per-permission gating goes through [`AdminContext::require`].
#[derive(SecurityScheme)]
pub(crate) enum AdminContext {
    Token(AdminTokenAuth),
    Cookie(AdminCookieAuth),
}

impl AdminContext {
    fn access(&self) -> &AdminAccess {
        match self {
            Self::Token(t) => &t.0,
            Self::Cookie(c) => &c.0,
        }
    }

    /// Require a specific permission, yielding a [`PermissionGranted`] proof or a 403.
    pub(crate) fn require(&self, permission: AdminPermission) -> Result<(), WarpgateError> {
        self.access().require(permission)
    }
}

impl std::ops::Deref for AdminContext {
    type Target = AuthenticatedRequestContext;

    fn deref(&self) -> &Self::Target {
        &self.access().ctx
    }
}

#[derive(SecurityScheme)]
#[oai(
    rename = "TokenSecurityScheme",
    ty = "api_key",
    key_name = "X-Warpgate-Token",
    key_in = "header",
    checker = "cluster_or_admin_access"
)]
pub(crate) struct ClusterOrAdminTokenAuth(AdminAccess);

#[derive(SecurityScheme)]
#[oai(
    rename = "CookieSecurityScheme",
    ty = "api_key",
    key_name = "warpgate-http-session",
    key_in = "cookie",
    checker = "cluster_or_admin_access"
)]
pub(crate) struct ClusterOrAdminCookieAuth(AdminAccess);

/// Like [`AdminContext`], but also accepts a cluster token (peer-forwarded admin requests).
/// Use only on endpoints that are legitimately cross-node forwardable.
#[derive(SecurityScheme)]
pub(crate) enum ClusterOrAdminContext {
    Token(ClusterOrAdminTokenAuth),
    Cookie(ClusterOrAdminCookieAuth),
}

impl ClusterOrAdminContext {
    fn access(&self) -> &AdminAccess {
        match self {
            Self::Token(t) => &t.0,
            Self::Cookie(c) => &c.0,
        }
    }

    pub(crate) fn require(&self, permission: AdminPermission) -> Result<(), WarpgateError> {
        self.access().require(permission)
    }
}

impl std::ops::Deref for ClusterOrAdminContext {
    type Target = AuthenticatedRequestContext;

    fn deref(&self) -> &Self::Target {
        &self.access().ctx
    }
}

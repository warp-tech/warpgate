use sea_orm::prelude::Expr;
use sea_orm::sea_query::{Func, IntoCondition};
use sea_orm::{ColumnTrait, Condition, EntityTrait, ModelTrait, QueryFilter};
use warpgate_common::{AdminPermission, AdminPermissionSet, WarpgateError};
pub use warpgate_common_http::RequestAuthorization;
use warpgate_db_entities::{AdminRole, User};

/// The admin permissions the request's principal holds — the single place that resolves the
/// permission model from the DB. `has_admin_permission`, `is_user_admin` and the `/info` UI
/// serialization all read the result instead of re-deriving it three different ways.
///
/// An admin token holds every permission; a ticket, a cluster token, or an unauthenticated
/// caller holds none (a ticket is scoped to one target and must never confer admin rights).
pub async fn admin_permission_set(
    ctx: &warpgate_common_http::AuthenticatedRequestContext,
) -> Result<AdminPermissionSet, WarpgateError> {
    if matches!(ctx.auth, RequestAuthorization::AdminToken) {
        return Ok(AdminPermissionSet::all());
    }
    let Some(full) = ctx.auth.as_full_user() else {
        return Ok(AdminPermissionSet::none());
    };

    let db = &ctx.services().db;
    let Some(user_model) = User::Entity::find()
        .filter(User::Entity::username_eq_ci(full.username()))
        .one(db)
        .await?
    else {
        return Ok(AdminPermissionSet::none());
    };

    let roles = user_model.find_related(AdminRole::Entity).all(db).await?;
    Ok(AdminPermissionSet::from_roles(
        roles.into_iter().map(Into::into),
    ))
}

pub async fn has_admin_permission(
    ctx: &warpgate_common_http::AuthenticatedRequestContext,
    specific_permission: Option<AdminPermission>,
) -> Result<bool, WarpgateError> {
    let permissions = admin_permission_set(ctx).await?;
    Ok(match specific_permission {
        Some(permission) => permissions.contains(permission),
        None => permissions.is_admin(),
    })
}

pub async fn require_admin_permission(
    ctx: &warpgate_common_http::AuthenticatedRequestContext,
    specific_permission: Option<AdminPermission>,
) -> Result<(), WarpgateError> {
    if has_admin_permission(ctx, specific_permission).await? {
        Ok(())
    } else {
        Err(match specific_permission {
            Some(p) => WarpgateError::NoAdminPermission(p),
            None => WarpgateError::NoAdminAccess,
        })
    }
}

/// Gate for endpoints that might have to be forwarded between nodes - so they
/// accept a cluster token as auth (the origin node has already authorized the
/// admin before forwarding)
pub async fn require_cluster_or_admin_permission(
    ctx: &warpgate_common_http::AuthenticatedRequestContext,
    permission: AdminPermission,
) -> Result<(), WarpgateError> {
    if matches!(ctx.auth, RequestAuthorization::ClusterToken) {
        return Ok(());
    }
    require_admin_permission(ctx, Some(permission)).await
}

pub fn case_insensitive_search<C, I>(search: &str, columns: I) -> impl IntoCondition
where
    C: ColumnTrait,
    I: IntoIterator<Item = C>,
{
    let search_pattern = format!("%{}%", search.to_lowercase());

    columns
        .into_iter()
        .fold(Condition::any(), |condition, column| {
            condition.add(Expr::expr(Func::lower(Expr::col(column))).like(search_pattern.clone()))
        })
}

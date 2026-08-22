use sea_orm::prelude::Expr;
use sea_orm::sea_query::{Alias, Func, IntoCondition, SimpleExpr};
use sea_orm::{
    ColumnTrait, Condition, DbBackend, DbErr, EntityTrait, ModelTrait, QueryFilter, SqlErr,
};
use warpgate_common::{AdminPermission, AdminPermissionSet, WarpgateError};
pub use warpgate_common_http::RequestAuthorization;
use warpgate_db_entities::{AdminRole, User};

/// Lets a handler answer a unique-name collision with a 409 instead of a 500. What counts
/// as a duplicate is whatever the index's collation says, which is also what the queries
/// looking a row up by that name will see.
pub fn is_unique_violation(err: &DbErr) -> bool {
    matches!(err.sql_err(), Some(SqlErr::UniqueConstraintViolation(_)))
}

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
    case_insensitive_search_expr(search, columns.into_iter().map(|c| Expr::col(c).into()))
}

/// [`case_insensitive_search`] over arbitrary expressions, for columns that need
/// to be coerced into text first - see [`json_as_text`].
pub fn case_insensitive_search_expr<I>(search: &str, expressions: I) -> impl IntoCondition
where
    I: IntoIterator<Item = SimpleExpr>,
{
    let search_pattern = format!("%{}%", search.to_lowercase());

    expressions
        .into_iter()
        .fold(Condition::any(), |condition, expression| {
            condition.add(Expr::expr(Func::lower(expression)).like(search_pattern.clone()))
        })
}

/// Casts a JSON column to text so that string functions such as `lower()` can be
/// applied to it.
///
/// Postgres has no `lower(json)` overload and won't coerce implicitly, unlike
/// SQLite and MySQL. MySQL in turn spells the cast target `char`, not `text`.
pub fn json_as_text<C: ColumnTrait>(backend: DbBackend, column: C) -> SimpleExpr {
    Expr::col(column).cast_as(match backend {
        DbBackend::MySql => Alias::new("char"),
        DbBackend::Postgres | DbBackend::Sqlite => Alias::new("text"),
    })
}

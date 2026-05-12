use sea_orm::prelude::Expr;
use sea_orm::sea_query::{Func, IntoCondition};
use sea_orm::{
    ColumnTrait, Condition, EntityTrait, JoinType, PaginatorTrait, QueryFilter, QuerySelect,
    RelationTrait,
};
use warpgate_common::{AdminPermission, WarpgateError};
pub use warpgate_common_http::{RequestAuthorization, SessionAuthorization};
use warpgate_db_entities::{AdminRole, User, UserAdminRoleAssignment};

pub async fn has_admin_permission(
    ctx: &warpgate_common_http::AuthenticatedRequestContext,
    specific_permission: Option<AdminPermission>,
) -> Result<bool, WarpgateError> {
    // Admin tokens have all permissions
    let auth = &ctx.auth;
    if matches!(auth, RequestAuthorization::AdminToken) {
        return Ok(true);
    }

    let username = match auth {
        RequestAuthorization::Session(
            SessionAuthorization::User { username, .. }
            | SessionAuthorization::Ticket { username, .. },
        )
        | RequestAuthorization::UserToken { username, .. } => username,
        RequestAuthorization::AdminToken => unreachable!(),
    };

    let db = ctx.services().db.lock().await;

    let Some(user_model) = User::Entity::find()
        .filter(User::Column::Username.eq(username))
        .one(&*db)
        .await?
    else {
        return Ok(false);
    };

    let mut query = UserAdminRoleAssignment::Entity::find()
        .filter(UserAdminRoleAssignment::Column::UserId.eq(user_model.id))
        .join(
            JoinType::InnerJoin,
            UserAdminRoleAssignment::Relation::AdminRole.def(),
        );

    if let Some(perm) = specific_permission {
        query = query.filter(match perm {
            AdminPermission::TargetsCreate => AdminRole::Column::TargetsCreate.eq(true),
            AdminPermission::TargetsEdit => AdminRole::Column::TargetsEdit.eq(true),
            AdminPermission::TargetsDelete => AdminRole::Column::TargetsDelete.eq(true),

            AdminPermission::UsersCreate => AdminRole::Column::UsersCreate.eq(true),
            AdminPermission::UsersEdit => AdminRole::Column::UsersEdit.eq(true),
            AdminPermission::UsersDelete => AdminRole::Column::UsersDelete.eq(true),

            AdminPermission::AccessRolesCreate => AdminRole::Column::AccessRolesCreate.eq(true),
            AdminPermission::AccessRolesEdit => AdminRole::Column::AccessRolesEdit.eq(true),
            AdminPermission::AccessRolesDelete => AdminRole::Column::AccessRolesDelete.eq(true),
            AdminPermission::AccessRolesAssign => AdminRole::Column::AccessRolesAssign.eq(true),

            AdminPermission::SessionsView => AdminRole::Column::SessionsView.eq(true),
            AdminPermission::SessionsTerminate => AdminRole::Column::SessionsTerminate.eq(true),

            AdminPermission::RecordingsView => AdminRole::Column::RecordingsView.eq(true),

            AdminPermission::TicketsCreate => AdminRole::Column::TicketsCreate.eq(true),
            AdminPermission::TicketsDelete => AdminRole::Column::TicketsDelete.eq(true),

            AdminPermission::ConfigEdit => AdminRole::Column::ConfigEdit.eq(true),

            AdminPermission::AdminRolesManage => AdminRole::Column::AdminRolesManage.eq(true),

            AdminPermission::TicketRequestsManage => {
                AdminRole::Column::TicketRequestsManage.eq(true)
            }
        });
    }

    let count = query.count(&*db).await?;
    Ok(count > 0)
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

pub fn case_insensitive_search<C, I>(search: &str, columns: I) -> impl IntoCondition
where
    C: ColumnTrait,
    I: IntoIterator<Item = C>,
{
    let search_pattern = format!("%{}%", search.to_lowercase());

    columns.into_iter().fold(Condition::any(), |condition, column| {
        condition.add(Expr::expr(Func::lower(Expr::col(column))).like(search_pattern.clone()))
    })
}

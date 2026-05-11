use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use uuid::Uuid;
use warpgate_common::{
    GlobalParams, Secret, UserPasswordCredential, UserRequireCredentialsPolicy, WarpgateError,
};
use warpgate_core::Services;
use warpgate_db_entities::{
    AdminRole, PasswordCredential, Role, User, UserAdminRoleAssignment, UserRoleAssignment,
};

use crate::config::load_config;

pub async fn command(
    params: &GlobalParams,
    username: &str,
    password: &Secret<String>,
    role: Option<&String>,
) -> anyhow::Result<()> {
    let config = load_config(params, true)?;
    let services = Services::new(config.clone(), None, params.clone()).await?;

    let db = services.db.lock().await;

    let db_user = if let Some(x) = User::Entity::find()
        .filter(User::Column::Username.eq(username))
        .all(&*db)
        .await?
        .first()
    {
        x.to_owned()
    } else {
        let values = User::ActiveModel {
            id: Set(Uuid::new_v4()),
            username: Set(username.to_owned()),
            description: Set("".into()),
            credential_policy: Set(serde_json::to_value(None::<UserRequireCredentialsPolicy>)?),
            rate_limit_bytes_per_second: Set(None),
            ldap_server_id: Set(None),
            ldap_object_uuid: Set(None),
            allowed_ip_ranges: Set(serde_json::Value::Null),
        };
        values.insert(&*db).await.map_err(WarpgateError::from)?
    };

    PasswordCredential::ActiveModel {
        user_id: Set(db_user.id),
        id: Set(Uuid::new_v4()),
        ..UserPasswordCredential::from_password(password).into()
    }
    .insert(&*db)
    .await?;

    if let Some(role_name) = role {
        // try regular role first
        if let Some(db_role) = Role::Entity::find()
            .filter(Role::Column::Name.eq(role_name.clone()))
            .one(&*db)
            .await?
        {
            UserRoleAssignment::Entity::idempotent_grant(&db, db_user.id, db_role.id, None).await?;
        }

        // admin role
        if let Some(db_admin) = AdminRole::Entity::find()
            .filter(AdminRole::Column::Name.eq(role_name.clone()))
            .one(&*db)
            .await?
            && UserAdminRoleAssignment::Entity::find()
                .filter(UserAdminRoleAssignment::Column::UserId.eq(db_user.id))
                .filter(UserAdminRoleAssignment::Column::AdminRoleId.eq(db_admin.id))
                .all(&*db)
                .await?
                .is_empty()
        {
            let values = UserAdminRoleAssignment::ActiveModel {
                user_id: Set(db_user.id),
                admin_role_id: Set(db_admin.id),
                ..Default::default()
            };
            values.insert(&*db).await.map_err(WarpgateError::from)?;
        }
    }

    Ok(())
}

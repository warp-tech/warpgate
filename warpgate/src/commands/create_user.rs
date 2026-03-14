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

pub(crate) async fn command(
    params: &GlobalParams,
    username: &str,
    password: &Secret<String>,
    role: &Option<String>,
) -> anyhow::Result<()> {
    let config = load_config(params, true)?;
    let services = Services::new(config.clone(), None, params.clone()).await?;

    let db = services.db.lock().await;

    let db_user = match User::Entity::find()
        .filter(User::Column::Username.eq(username))
        .all(&*db)
        .await?
        .first()
    {
        Some(x) => x.to_owned(),
        None => {
            let values = User::ActiveModel {
                id: Set(Uuid::new_v4()),
                username: Set(username.to_owned()),
                description: Set("".into()),
                credential_policy: Set(serde_json::to_value(None::<UserRequireCredentialsPolicy>)?),
                rate_limit_bytes_per_second: Set(None),
                ldap_server_id: Set(None),
                ldap_object_uuid: Set(None),
            };
            values.insert(&*db).await.map_err(WarpgateError::from)?
        }
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
            if UserRoleAssignment::Entity::find()
                .filter(UserRoleAssignment::Column::UserId.eq(db_user.id))
                .filter(UserRoleAssignment::Column::RoleId.eq(db_role.id))
                .all(&*db)
                .await?
                .is_empty()
            {
                let values = UserRoleAssignment::ActiveModel {
                    user_id: Set(db_user.id),
                    role_id: Set(db_role.id),
                    ..Default::default()
                };
                values.insert(&*db).await.map_err(WarpgateError::from)?;
            }
        } else {
            // admin role
            let db_admin = AdminRole::Entity::find()
                .filter(AdminRole::Column::Name.eq(role_name.clone()))
                .one(&*db)
                .await?
                .ok_or_else(|| anyhow::anyhow!("admin role not found"))?;

            if UserAdminRoleAssignment::Entity::find()
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
    }

    Ok(())
}

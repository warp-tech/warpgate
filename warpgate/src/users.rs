use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use uuid::Uuid;
use warpgate_common::{
    UserPasswordCredential, UserRequireCredentialsPolicy, WarpgateError, Secret,
};
use warpgate_core::Services;
use warpgate_db_entities::{PasswordCredential, Role, User, UserRoleAssignment};

pub(crate) async fn create_user(username: &str, password: &Secret<String>, role: &Option<String>, services: &Services) -> anyhow::Result<()> {
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
                credential_policy: Set(serde_json::to_value(
                    None::<UserRequireCredentialsPolicy>,
                )?),
                rate_limit_bytes_per_second: Set(None),
            };
            values.insert(&*db).await.map_err(WarpgateError::from)?
        }
    };

    PasswordCredential::ActiveModel {
        user_id: Set(db_user.id),
        id: Set(Uuid::new_v4()),
        ..UserPasswordCredential::from_password(password).into()
    }.insert(&*db).await?;

    // Assign a role if a role is specified
    if role.is_some() {
        let db_role = Role::Entity::find()
            .filter(Role::Column::Name.eq(role.to_owned()))
            .all(&*db)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("Role not found"))?;

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
    }

    Ok(())
}
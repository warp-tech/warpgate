use sea_orm::prelude::*;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PrimaryKeyTrait, QueryFilter, Schema, Set,
};
use sea_orm_migration::prelude::*;
use uuid::Uuid;

use crate::m00007_targets_and_roles::{target, target_role_assignment};
use crate::m00008_users::user_role_assignment;
use crate::m00022_user_ldap_link::user;

pub mod admin_role {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "admin_roles")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub name: String,
        #[sea_orm(column_type = "Text")]
        pub description: String,
        pub targets_create: bool,
        pub targets_edit: bool,
        pub targets_delete: bool,
        pub users_create: bool,
        pub users_edit: bool,
        pub users_delete: bool,
        pub access_roles_create: bool,
        pub access_roles_edit: bool,
        pub access_roles_delete: bool,
        pub access_roles_assign: bool,
        pub sessions_view: bool,
        pub sessions_terminate: bool,
        pub recordings_view: bool,
        pub tickets_create: bool,
        pub tickets_delete: bool,
        pub config_edit: bool,
        pub admin_roles_manage: bool,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod user_admin_role {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "user_admin_roles")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = true)]
        pub id: i32,
        pub user_id: Uuid,
        pub admin_role_id: Uuid,
    }

    #[derive(Copy, Clone, Debug, EnumIter)]
    pub enum Relation {
        User,
        AdminRole,
    }

    impl RelationTrait for Relation {
        fn def(&self) -> RelationDef {
            match self {
                Self::User => Entity::belongs_to(user::Entity)
                    .from(Column::UserId)
                    .to(user::Column::Id)
                    .into(),
                Self::AdminRole => Entity::belongs_to(super::admin_role::Entity)
                    .from(Column::AdminRoleId)
                    .to(super::admin_role::Column::Id)
                    .into(),
            }
        }
    }

    impl ActiveModelBehavior for ActiveModel {}
}

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00032_admin_roles"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let builder = manager.get_database_backend();
        let schema = Schema::new(builder);

        manager
            .create_table(schema.create_table_from_entity(admin_role::Entity))
            .await?;
        manager
            .create_table(schema.create_table_from_entity(user_admin_role::Entity))
            .await?;

        // migrate existing warpgate:admin users to a new admin role with full permissions
        let conn = manager.get_connection();

        // find all users authorized for the web admin target without complex joins
        let admin_targets = target::Entity::find()
            .filter(target::Column::Kind.eq(target::TargetKind::WebAdmin))
            .all(conn)
            .await?;
        let mut admin_users: Vec<user::Model> = Vec::new();

        if !admin_targets.is_empty() {
            let web_target_ids: Vec<Uuid> = admin_targets.into_iter().map(|t| t.id).collect();

            let web_role_assignments = target_role_assignment::Entity::find()
                .filter(target_role_assignment::Column::TargetId.is_in(web_target_ids.clone()))
                .all(conn)
                .await?;

            let web_role_ids: Vec<Uuid> = web_role_assignments
                .into_iter()
                .map(|a| a.role_id)
                .collect();

            if !web_role_ids.is_empty() {
                // now get all users that have one of those roles
                let user_assignments = user_role_assignment::Entity::find()
                    .filter(user_role_assignment::Column::RoleId.is_in(web_role_ids.clone()))
                    .all(conn)
                    .await?;

                if !user_assignments.is_empty() {
                    let user_ids: Vec<Uuid> =
                        user_assignments.into_iter().map(|a| a.user_id).collect();
                    admin_users = user::Entity::find()
                        .filter(user::Column::Id.is_in(user_ids.clone()))
                        .all(conn)
                        .await?;
                }
            }
        }

        let builtin_admin_role_id = Uuid::new_v4();
        let values = admin_role::ActiveModel {
            id: Set(builtin_admin_role_id),
            name: Set("warpgate:admin".to_string()),
            description: Set("Built-in admin role".into()),
            targets_create: Set(true),
            targets_edit: Set(true),
            targets_delete: Set(true),
            users_create: Set(true),
            users_edit: Set(true),
            users_delete: Set(true),
            access_roles_create: Set(true),
            access_roles_edit: Set(true),
            access_roles_delete: Set(true),
            access_roles_assign: Set(true),
            sessions_view: Set(true),
            sessions_terminate: Set(true),
            recordings_view: Set(true),
            tickets_create: Set(true),
            tickets_delete: Set(true),
            config_edit: Set(true),
            admin_roles_manage: Set(true),
        };
        values.insert(conn).await?;

        for user in admin_users {
            let assign = user_admin_role::ActiveModel {
                user_id: Set(user.id),
                admin_role_id: Set(builtin_admin_role_id),
                ..Default::default()
            };
            assign.insert(conn).await?;
        }

        // drop the old web-admin target and its assignments as it's no longer used
        {
            if let Some(web_target) = target::Entity::find()
                .filter(target::Column::Kind.eq(target::TargetKind::WebAdmin))
                .one(conn)
                .await?
            {
                target_role_assignment::Entity::delete_many()
                    .filter(target_role_assignment::Column::TargetId.eq(web_target.id))
                    .exec(conn)
                    .await?;

                target::Entity::delete_by_id(web_target.id)
                    .exec(conn)
                    .await?;
            }
        }

        Ok(())
    }

    #[allow(clippy::panic)]
    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        panic!("This migration cannot be reversed");
    }
}

use sea_orm::Schema;
use sea_orm_migration::prelude::*;

mod role {
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "roles")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub name: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

mod target {
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Debug, PartialEq, Eq, Clone, EnumIter, DeriveActiveEnum)]
    #[sea_orm(rs_type = "String", db_type = "String(Some(16))")]
    pub enum TargetKind {
        #[sea_orm(string_value = "http")]
        Http,
        #[sea_orm(string_value = "mysql")]
        MySql,
        #[sea_orm(string_value = "ssh")]
        Ssh,
        #[sea_orm(string_value = "web_admin")]
        WebAdmin,
    }

    #[derive(Debug, PartialEq, Eq, Clone, EnumIter, DeriveActiveEnum)]
    #[sea_orm(rs_type = "String", db_type = "String(Some(16))")]
    pub enum SshAuthKind {
        #[sea_orm(string_value = "password")]
        Password,
        #[sea_orm(string_value = "publickey")]
        PublicKey,
    }

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "targets")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub name: String,
        pub kind: TargetKind,
        pub options: serde_json::Value,
    }

    impl Related<super::role::Entity> for Entity {
        fn to() -> RelationDef {
            super::target_role_assignment::Relation::Target.def()
        }

        fn via() -> Option<RelationDef> {
            Some(super::target_role_assignment::Relation::Role.def().rev())
        }
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

mod target_role_assignment {
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "target_roles")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: u64,
        pub target_id: Uuid,
        pub role_id: Uuid,
    }

    #[derive(Copy, Clone, Debug, EnumIter)]
    pub enum Relation {
        Target,
        Role,
    }

    impl RelationTrait for Relation {
        fn def(&self) -> RelationDef {
            match self {
                Self::Target => Entity::belongs_to(super::target::Entity)
                    .from(Column::TargetId)
                    .to(super::target::Column::Id)
                    .into(),
                Self::Role => Entity::belongs_to(super::role::Entity)
                    .from(Column::RoleId)
                    .to(super::role::Column::Id)
                    .into(),
            }
        }
    }

    impl ActiveModelBehavior for ActiveModel {}
}

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00007_targets_and_roles"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let builder = manager.get_database_backend();
        let schema = Schema::new(builder);
        manager
            .create_table(schema.create_table_from_entity(role::Entity))
            .await?;
        manager
            .create_table(schema.create_table_from_entity(target::Entity))
            .await?;
        manager
            .create_table(schema.create_table_from_entity(target_role_assignment::Entity))
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(target_role_assignment::Entity)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(target::Entity).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(role::Entity).to_owned())
            .await?;
        Ok(())
    }
}

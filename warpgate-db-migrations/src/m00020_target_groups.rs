use sea_orm::Schema;
use sea_orm_migration::prelude::*;

use crate::m00007_targets_and_roles::target;

pub mod target_group {
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Debug, PartialEq, Eq, Clone, EnumIter, DeriveActiveEnum)]
    #[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
    pub enum BootstrapThemeColor {
        #[sea_orm(string_value = "primary")]
        Primary,
        #[sea_orm(string_value = "secondary")]
        Secondary,
        #[sea_orm(string_value = "success")]
        Success,
        #[sea_orm(string_value = "danger")]
        Danger,
        #[sea_orm(string_value = "warning")]
        Warning,
        #[sea_orm(string_value = "info")]
        Info,
        #[sea_orm(string_value = "light")]
        Light,
        #[sea_orm(string_value = "dark")]
        Dark,
    }

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "target_groups")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub name: String,
        #[sea_orm(column_type = "Text")]
        pub description: String,
        pub color: Option<BootstrapThemeColor>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00020_target_groups"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create target_groups table
        let builder = manager.get_database_backend();
        let schema = Schema::new(builder);
        manager
            .create_table(schema.create_table_from_entity(target_group::Entity))
            .await?;

        // Add group_id column to targets table
        manager
            .alter_table(
                Table::alter()
                    .table(target::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("group_id"))
                            .uuid()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Note: SQLite doesn't support adding foreign key constraints to existing tables
        // The foreign key relationship will be enforced at the application level

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Remove group_id column from targets table
        manager
            .alter_table(
                Table::alter()
                    .table(target::Entity)
                    .drop_column(Alias::new("group_id"))
                    .to_owned(),
            )
            .await?;

        // Drop target_groups table
        manager
            .drop_table(Table::drop().table(target_group::Entity).to_owned())
            .await?;

        Ok(())
    }
}

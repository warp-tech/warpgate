use sea_orm_migration::prelude::*;

/// Rows a provider can own. `provider` is the owning provider, NULL when the
/// row is managed by hand. A role assignment is owned by whoever owns the
/// target or user it belongs to, so the join tables carry no column.
const TABLES: [&str; 4] = ["targets", "target_groups", "roles", "users"];

fn index_name(table: &str) -> String {
    format!("{table}_provider")
}

pub async fn add_provider_column(manager: &SchemaManager<'_>, table: &str) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(Alias::new(table))
                .add_column(ColumnDef::new(Alias::new("provider")).uuid().null())
                .to_owned(),
        )
        .await?;
    manager
        .create_index(
            Index::create()
                .name(index_name(table))
                .table(Alias::new(table))
                .col(Alias::new("provider"))
                .to_owned(),
        )
        .await
}

pub async fn drop_provider_column(manager: &SchemaManager<'_>, table: &str) -> Result<(), DbErr> {
    manager
        .drop_index(
            Index::drop()
                .name(index_name(table))
                .table(Alias::new(table))
                .to_owned(),
        )
        .await?;
    manager
        .alter_table(
            Table::alter()
                .table(Alias::new(table))
                .drop_column(Alias::new("provider"))
                .to_owned(),
        )
        .await
}

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in TABLES {
            add_provider_column(manager, table).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in TABLES {
            drop_provider_column(manager, table).await?;
        }
        Ok(())
    }
}

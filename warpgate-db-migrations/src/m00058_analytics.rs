use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;
use uuid::Uuid;

use crate::m00010_parameters::parameters;

#[derive(DeriveMigrationName)]
pub struct Migration;

async fn add_column(manager: &SchemaManager<'_>, column: ColumnDef) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(parameters::Entity)
                .add_column(column)
                .to_owned(),
        )
        .await
}

async fn drop_column(manager: &SchemaManager<'_>, name: &str) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(parameters::Entity)
                .drop_column(Alias::new(name))
                .to_owned(),
        )
        .await
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        add_column(
            manager,
            ColumnDef::new(Alias::new("analytics_consent"))
                .string()
                .not_null()
                .default("Undecided")
                .to_owned(),
        )
        .await?;
        add_column(
            manager,
            ColumnDef::new(Alias::new("analytics_normal"))
                .boolean()
                .not_null()
                .default(false)
                .to_owned(),
        )
        .await?;
        add_column(
            manager,
            ColumnDef::new(Alias::new("analytics_instance_id"))
                .string()
                .not_null()
                .default("")
                .to_owned(),
        )
        .await?;
        add_column(
            manager,
            ColumnDef::new(Alias::new("instance_created_at"))
                .timestamp_with_time_zone()
                .to_owned(),
        )
        .await?;

        let db = manager.get_connection();
        let backend = db.get_database_backend();
        let stmt = Query::update()
            .table(parameters::Entity)
            .value(
                Alias::new("analytics_instance_id"),
                Uuid::new_v4().to_string(),
            )
            .value(Alias::new("instance_created_at"), Expr::current_timestamp())
            .and_where(Expr::col(Alias::new("analytics_instance_id")).eq(""))
            .to_owned();
        db.execute(backend.build(&stmt)).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        drop_column(manager, "instance_created_at").await?;
        drop_column(manager, "analytics_instance_id").await?;
        drop_column(manager, "analytics_normal").await?;
        drop_column(manager, "analytics_consent").await?;
        Ok(())
    }
}

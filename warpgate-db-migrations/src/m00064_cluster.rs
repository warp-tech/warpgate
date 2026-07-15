use sea_orm::Schema;
use sea_orm_migration::prelude::*;

pub mod node {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "nodes")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub address: String,
        pub hostname: String,
        pub last_seen: OffsetDateTime,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let schema = Schema::new(manager.get_database_backend());
        manager
            .create_table(schema.create_table_from_entity(node::Entity))
            .await?;
        // Which node currently owns a live session; null for sessions from before
        // clustering or once the owner is gone.
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("sessions"))
                    .add_column(ColumnDef::new(Alias::new("node_id")).uuid().null())
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("sessions"))
                    .drop_column(Alias::new("node_id"))
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(node::Entity).to_owned())
            .await?;
        Ok(())
    }
}

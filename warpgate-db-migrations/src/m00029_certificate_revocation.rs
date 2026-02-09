use sea_orm::entity::prelude::*;
use sea_orm::Schema;
use sea_orm_migration::prelude::*;

pub mod certificate_revocation {
    use chrono::{DateTime, Utc};
    use sea_orm::entity::prelude::*;
    use serde::Serialize;
    use uuid::Uuid;

    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize)]
    #[sea_orm(table_name = "certificate_revocations")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub serial_number_base64: String,
        pub date_added: DateTime<Utc>,
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
        let builder = manager.get_database_backend();
        let schema = Schema::new(builder);
        manager
            .create_table(schema.create_table_from_entity(certificate_revocation::Entity))
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_certificate_revocations_serial")
                    .table(certificate_revocation::Entity)
                    .col(certificate_revocation::Column::SerialNumberBase64)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_certificate_revocations_serial")
                    .table(certificate_revocation::Entity)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(certificate_revocation::Entity)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

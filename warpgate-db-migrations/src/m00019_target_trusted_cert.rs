use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00019_target_trusted_cert"
    }
}

mod target {
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    use crate::m00017_descriptions::target::TargetKind;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "targets")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub name: String,
        #[sea_orm(column_type = "Text")]
        pub description: String,
        pub kind: TargetKind,
        pub options: serde_json::Value,
        pub trusted_tls_certificate: Option<Vec<u8>>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(target::Entity)
                    .add_column(ColumnDef::new(target::Column::TrustedTlsCertificate).blob())
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(target::Entity)
                    .drop_column(target::Column::TrustedTlsCertificate)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

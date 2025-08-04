use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, EntityTrait, IntoActiveModel};
use sea_orm_migration::prelude::*;
use tracing::info;
use uuid::Uuid;

pub mod parameters {
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "parameters")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub allow_own_credential_management: bool,
        pub rate_limit_bytes_per_second: Option<i64>,

        #[sea_orm(column_type = "Text")]
        pub ca_certificate_pem: String,
        #[sea_orm(column_type = "Text")]
        pub ca_private_key_pem: String,
    }

    impl ActiveModelBehavior for ActiveModel {}

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
}

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("ca_certificate_pem"))
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .add_column(
                        ColumnDef::new(Alias::new("ca_private_key_pem"))
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .to_owned(),
            )
            .await?;

        info!("Generating root CA certificate");
        let cert = warpgate_ca::generate_root_certificate()
            .map_err(|e| DbErr::Custom(format!("Failed to generate CA certificate: {}", e)))?;

        let db = manager.get_connection();

        let parameters = match parameters::Entity::find().one(db).await? {
            Some(model) => Ok(model),
            None => {
                parameters::ActiveModel {
                    id: Set(Uuid::new_v4()),
                    allow_own_credential_management: Set(true),
                    rate_limit_bytes_per_second: Set(None),
                    ca_certificate_pem: Set("".into()),
                    ca_private_key_pem: Set("".into()),
                }
                .insert(db)
                .await
            }
        }?;

        let mut model = parameters.into_active_model();
        model.ca_certificate_pem = Set(cert.cert.pem());
        model.ca_private_key_pem = Set(cert.key_pair.serialize_pem());
        model.update(db).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .drop_column(Alias::new("ca_certificate_pem"))
                    .drop_column(Alias::new("ca_private_key_pem"))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

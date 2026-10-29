use sea_orm::Schema;
use sea_orm_migration::prelude::*;

// Self-contained entity snapshot for this migration (per the m00009 pattern),
// so later changes to the live `OracleCredential` entity never alter history.
pub mod oracle_credential {
    use sea_orm::entity::prelude::*;
    use sea_orm::sea_query::ForeignKeyAction;
    use uuid::Uuid;

    use crate::m00008_users::user as User;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "credentials_oracle")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub user_id: Uuid,
        pub vfr_data: String,
        pub vgen_count: i32,
        pub csk_salt: String,
        pub sder_count: i32,
        pub password_key: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter)]
    pub enum Relation {
        User,
    }

    impl RelationTrait for Relation {
        fn def(&self) -> RelationDef {
            match self {
                Self::User => Entity::belongs_to(User::Entity)
                    .from(Column::UserId)
                    .to(User::Column::Id)
                    .on_delete(ForeignKeyAction::Cascade)
                    .into(),
            }
        }
    }

    impl ActiveModelBehavior for ActiveModel {}
}

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00095_oracle_credentials"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let builder = manager.get_database_backend();
        let schema = Schema::new(builder);
        manager
            .create_table(schema.create_table_from_entity(oracle_credential::Entity))
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(Alias::new("credentials_oracle"))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

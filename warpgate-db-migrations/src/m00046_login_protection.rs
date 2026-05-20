use sea_orm::Schema;
use sea_orm_migration::prelude::*;

pub mod failed_login_attempt {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "failed_login_attempts")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub username: String,
        pub remote_ip: String,
        pub protocol: String,
        pub credential_type: String,
        pub timestamp: OffsetDateTime,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod ip_block {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "ip_blocks")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        #[sea_orm(unique)]
        pub ip_address: String,
        pub block_count: i32,
        pub blocked_at: OffsetDateTime,
        pub expires_at: OffsetDateTime,
        pub reason: String,
        pub last_attempt_at: OffsetDateTime,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod user_lockout {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "user_lockouts")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        #[sea_orm(unique)]
        pub username: String,
        pub locked_at: OffsetDateTime,
        pub expires_at: Option<OffsetDateTime>,
        pub reason: String,
        pub failed_attempt_count: i32,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00046_login_protection"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let builder = manager.get_database_backend();
        let schema = Schema::new(builder);

        manager
            .create_table(schema.create_table_from_entity(failed_login_attempt::Entity))
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(failed_login_attempt::Entity)
                    .name("idx_failed_login_attempts_ip_timestamp")
                    .col(Alias::new("remote_ip"))
                    .col(Alias::new("timestamp"))
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(failed_login_attempt::Entity)
                    .name("idx_failed_login_attempts_username_timestamp")
                    .col(Alias::new("username"))
                    .col(Alias::new("timestamp"))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(schema.create_table_from_entity(ip_block::Entity))
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(ip_block::Entity)
                    .name("idx_ip_blocks_expires_at")
                    .col(Alias::new("expires_at"))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(schema.create_table_from_entity(user_lockout::Entity))
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(user_lockout::Entity)
                    .name("idx_user_lockouts_expires_at")
                    .col(Alias::new("expires_at"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .table(user_lockout::Entity)
                    .name("idx_user_lockouts_expires_at")
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .table(ip_block::Entity)
                    .name("idx_ip_blocks_expires_at")
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .table(failed_login_attempt::Entity)
                    .name("idx_failed_login_attempts_username_timestamp")
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .table(failed_login_attempt::Entity)
                    .name("idx_failed_login_attempts_ip_timestamp")
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(Table::drop().table(user_lockout::Entity).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(ip_block::Entity).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(failed_login_attempt::Entity).to_owned())
            .await?;

        Ok(())
    }
}

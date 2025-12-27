use sea_orm::Schema;
use sea_orm_migration::prelude::*;

pub mod failed_login_attempt {
    use chrono::{DateTime, Utc};
    use sea_orm::entity::prelude::*;
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
        pub timestamp: DateTime<Utc>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod ip_block {
    use chrono::{DateTime, Utc};
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "ip_blocks")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        #[sea_orm(unique)]
        pub ip_address: String,
        pub block_count: i32,
        pub blocked_at: DateTime<Utc>,
        pub expires_at: DateTime<Utc>,
        pub reason: String,
        pub last_attempt_at: DateTime<Utc>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod user_lockout {
    use chrono::{DateTime, Utc};
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "user_lockouts")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        #[sea_orm(unique)]
        pub username: String,
        pub locked_at: DateTime<Utc>,
        pub expires_at: Option<DateTime<Utc>>,
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
        "m00021_login_protection"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let builder = manager.get_database_backend();
        let schema = Schema::new(builder);

        // Create failed_login_attempts table
        manager
            .create_table(schema.create_table_from_entity(failed_login_attempt::Entity))
            .await?;

        // Create composite index for IP-based queries: "failed attempts from IP in time window"
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

        // Create composite index for user-based queries: "failed attempts for user in time window"
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

        // Create ip_blocks table
        manager
            .create_table(schema.create_table_from_entity(ip_block::Entity))
            .await?;

        // Create index for finding blocks to clean up (expired blocks)
        manager
            .create_index(
                Index::create()
                    .table(ip_block::Entity)
                    .name("idx_ip_blocks_expires_at")
                    .col(Alias::new("expires_at"))
                    .to_owned(),
            )
            .await?;

        // Create user_lockouts table
        manager
            .create_table(schema.create_table_from_entity(user_lockout::Entity))
            .await?;

        // Create index for finding lockouts to clean up (expired lockouts)
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
        // Drop indexes first
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

        // Drop tables
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

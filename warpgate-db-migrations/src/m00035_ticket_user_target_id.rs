use sea_orm::{DbBackend, Schema};
use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::ConnectionTrait;

mod ticket {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "tickets")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub secret: String,
        pub user_id: Uuid,
        #[sea_orm(column_type = "Text")]
        pub description: String,
        pub target_id: Uuid,
        pub uses_left: Option<i16>,
        pub expiry: Option<OffsetDateTime>,
        pub created: OffsetDateTime,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "super::user::Entity",
            from = "Column::UserId",
            to = "super::user::Column::Id"
        )]
        User,
        #[sea_orm(
            belongs_to = "super::target::Entity",
            from = "Column::TargetId",
            to = "super::target::Column::Id"
        )]
        Target,
    }

    impl ActiveModelBehavior for ActiveModel {}
}

mod user {
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "users")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub username: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

mod target {
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "targets")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub name: String,
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
        let db = manager.get_connection();
        let builder = manager.get_database_backend();

        match builder {
            DbBackend::Sqlite => {
                let schema = Schema::new(builder);
                let mut create_stmt = schema.create_table_from_entity(ticket::Entity);
                create_stmt.table(Alias::new("tickets_new")); // renamed
                manager.create_table(create_stmt).await?;

                // Rows with no matching user or target are silently dropped (INNER JOIN)
                db.execute_unprepared(
                    "INSERT INTO tickets_new (id, secret, user_id, description, target_id, uses_left, expiry, created)
                     SELECT o.id, o.secret,
                            u.id,
                            o.description,
                            t.id,
                            o.uses_left, o.expiry, o.created
                     FROM tickets o
                     JOIN users   u ON u.username = o.username
                     JOIN targets t ON t.name     = o.target",
                )
                .await?;

                db.execute_unprepared("PRAGMA foreign_keys=OFF").await.ok();
                manager
                    .drop_table(Table::drop().table(Alias::new("tickets")).to_owned())
                    .await?;
                db.execute_unprepared("ALTER TABLE tickets_new RENAME TO tickets")
                    .await?;
                db.execute_unprepared("PRAGMA foreign_keys=ON").await.ok();
            }
            DbBackend::MySql => {
                db.execute_unprepared(
                    "ALTER TABLE `tickets` ADD COLUMN `user_id` binary(16) NULL",
                )
                .await?;
                db.execute_unprepared(
                    "ALTER TABLE `tickets` ADD COLUMN `target_id` binary(16) NULL",
                )
                .await?;
                // Rows with no matching user or target are silently dropped (NULL left after UPDATE)
                db.execute_unprepared(
                    "UPDATE `tickets` t INNER JOIN `users` u ON u.username = t.username SET t.user_id = u.id",
                )
                .await?;
                db.execute_unprepared(
                    "UPDATE `tickets` t INNER JOIN `targets` tgt ON tgt.name = t.target SET t.target_id = tgt.id",
                )
                .await?;
                db.execute_unprepared(
                    "DELETE FROM `tickets` WHERE `user_id` IS NULL OR `target_id` IS NULL",
                )
                .await?;
                db.execute_unprepared("ALTER TABLE `tickets` DROP COLUMN `username`")
                    .await?;
                db.execute_unprepared("ALTER TABLE `tickets` DROP COLUMN `target`")
                    .await?;
                db.execute_unprepared(
                    "ALTER TABLE `tickets` MODIFY COLUMN `user_id` binary(16) NOT NULL",
                )
                .await?;
                db.execute_unprepared(
                    "ALTER TABLE `tickets` MODIFY COLUMN `target_id` binary(16) NOT NULL",
                )
                .await?;
                db.execute_unprepared(
                    "ALTER TABLE `tickets` ADD CONSTRAINT FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)",
                )
                .await?;
                db.execute_unprepared(
                    "ALTER TABLE `tickets` ADD CONSTRAINT FOREIGN KEY (`target_id`) REFERENCES `targets` (`id`)",
                )
                .await?;
            }
            DbBackend::Postgres => {
                db.execute_unprepared(
                    r#"ALTER TABLE "tickets" ADD COLUMN "user_id" uuid NULL"#,
                )
                .await?;
                db.execute_unprepared(
                    r#"ALTER TABLE "tickets" ADD COLUMN "target_id" uuid NULL"#,
                )
                .await?;
                // Rows with no matching user or target are silently dropped (NULL left after UPDATE)
                db.execute_unprepared(
                    r#"UPDATE "tickets" SET user_id = u.id FROM "users" u WHERE u.username = "tickets".username"#,
                )
                .await?;
                db.execute_unprepared(
                    r#"UPDATE "tickets" SET target_id = t.id FROM "targets" t WHERE t.name = "tickets".target"#,
                )
                .await?;
                db.execute_unprepared(
                    r#"DELETE FROM "tickets" WHERE "user_id" IS NULL OR "target_id" IS NULL"#,
                )
                .await?;
                db.execute_unprepared(r#"ALTER TABLE "tickets" DROP COLUMN "username""#)
                    .await?;
                db.execute_unprepared(r#"ALTER TABLE "tickets" DROP COLUMN "target""#)
                    .await?;
                db.execute_unprepared(
                    r#"ALTER TABLE "tickets" ALTER COLUMN "user_id" SET NOT NULL"#,
                )
                .await?;
                db.execute_unprepared(
                    r#"ALTER TABLE "tickets" ALTER COLUMN "target_id" SET NOT NULL"#,
                )
                .await?;
                db.execute_unprepared(
                    r#"ALTER TABLE "tickets" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id")"#,
                )
                .await?;
                db.execute_unprepared(
                    r#"ALTER TABLE "tickets" ADD FOREIGN KEY ("target_id") REFERENCES "targets" ("id")"#,
                )
                .await?;
            }
        }

        Ok(())
    }

    #[allow(clippy::panic)]
    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        panic!("This migration cannot be reverted");
    }
}

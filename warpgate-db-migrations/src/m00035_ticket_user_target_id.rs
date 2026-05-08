use sea_orm::{DbBackend, Schema};
use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::ConnectionTrait;
use sea_orm_migration::sea_query::ForeignKey;

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
                manager
                    .rename_table(
                        Table::rename()
                            .table(Alias::new("tickets_new"), Alias::new("tickets"))
                            .to_owned(),
                    )
                    .await?;
                db.execute_unprepared("PRAGMA foreign_keys=ON").await.ok();
            }
            DbBackend::MySql | DbBackend::Postgres => {
                // Add the new FK columns as nullable first so we can populate them
                manager
                    .alter_table(
                        Table::alter()
                            .table(Alias::new("tickets"))
                            .add_column(ColumnDef::new(Alias::new("user_id")).uuid().null())
                            .to_owned(),
                    )
                    .await?;
                manager
                    .alter_table(
                        Table::alter()
                            .table(Alias::new("tickets"))
                            .add_column(ColumnDef::new(Alias::new("target_id")).uuid().null())
                            .to_owned(),
                    )
                    .await?;

                // Rows with no matching user or target are silently dropped (NULL left after UPDATE)
                match builder {
                    DbBackend::MySql => {
                        db.execute_unprepared(
                            "UPDATE `tickets` t INNER JOIN `users` u ON u.username = t.username SET t.user_id = u.id",
                        )
                        .await?;
                        db.execute_unprepared(
                            "UPDATE `tickets` t INNER JOIN `targets` tgt ON tgt.name = t.target SET t.target_id = tgt.id",
                        )
                        .await?;
                    }
                    DbBackend::Postgres => {
                        db.execute_unprepared(
                            r#"UPDATE "tickets" SET user_id = u.id FROM "users" u WHERE u.username = "tickets".username"#,
                        )
                        .await?;
                        db.execute_unprepared(
                            r#"UPDATE "tickets" SET target_id = t.id FROM "targets" t WHERE t.name = "tickets".target"#,
                        )
                        .await?;
                    }
                    DbBackend::Sqlite => unreachable!(),
                }
                db.execute_unprepared(
                    "DELETE FROM tickets WHERE user_id IS NULL OR target_id IS NULL",
                )
                .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(Alias::new("tickets"))
                            .drop_column(Alias::new("username"))
                            .to_owned(),
                    )
                    .await?;
                manager
                    .alter_table(
                        Table::alter()
                            .table(Alias::new("tickets"))
                            .drop_column(Alias::new("target"))
                            .to_owned(),
                    )
                    .await?;

                // Make the new FK columns non-null now that data is populated
                manager
                    .alter_table(
                        Table::alter()
                            .table(Alias::new("tickets"))
                            .modify_column(ColumnDef::new(Alias::new("user_id")).uuid().not_null())
                            .to_owned(),
                    )
                    .await?;
                manager
                    .alter_table(
                        Table::alter()
                            .table(Alias::new("tickets"))
                            .modify_column(
                                ColumnDef::new(Alias::new("target_id")).uuid().not_null(),
                            )
                            .to_owned(),
                    )
                    .await?;

                manager
                    .create_foreign_key(
                        ForeignKey::create()
                            .from(Alias::new("tickets"), Alias::new("user_id"))
                            .to(Alias::new("users"), Alias::new("id"))
                            .to_owned(),
                    )
                    .await?;
                manager
                    .create_foreign_key(
                        ForeignKey::create()
                            .from(Alias::new("tickets"), Alias::new("target_id"))
                            .to(Alias::new("targets"), Alias::new("id"))
                            .to_owned(),
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

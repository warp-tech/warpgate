use sea_orm_migration::prelude::*;

/// Rows a provider can own. `provider` is the owning provider, NULL when the
/// row is managed by hand. A role assignment is owned by whoever owns the
/// target or user it belongs to, so the join tables carry no column.
const TABLES: [&str; 4] = ["targets", "target_groups", "roles", "users"];

fn index_name(table: &str) -> String {
    format!("{table}_provider")
}

pub async fn add_provider_column(manager: &SchemaManager<'_>, table: &str) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(Alias::new(table))
                .add_column(ColumnDef::new(Alias::new("provider")).uuid().null())
                .to_owned(),
        )
        .await?;
    manager
        .create_index(
            Index::create()
                .name(index_name(table))
                .table(Alias::new(table))
                .col(Alias::new("provider"))
                .to_owned(),
        )
        .await
}

pub async fn drop_provider_column(manager: &SchemaManager<'_>, table: &str) -> Result<(), DbErr> {
    manager
        .drop_index(
            Index::drop()
                .name(index_name(table))
                .table(Alias::new(table))
                .to_owned(),
        )
        .await?;
    manager
        .alter_table(
            Table::alter()
                .table(Alias::new(table))
                .drop_column(Alias::new("provider"))
                .to_owned(),
        )
        .await
}

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in TABLES {
            add_provider_column(manager, table).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in TABLES {
            drop_provider_column(manager, table).await?;
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use sea_orm::{
        ActiveModelTrait, ColumnTrait, ConnectionTrait, Database, EntityTrait, QueryFilter, Set,
    };
    use sea_orm_migration::MigratorTrait;
    use sea_orm_migration::prelude::{Alias, Query};
    use uuid::Uuid;
    use warpgate_common::ProviderId;
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
    use warpgate_db_entities::Role;

    use crate::Migrator;

    #[tokio::test]
    async fn existing_rows_become_manual() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        crate::migrate_up_to(&db, "m00095_resource_provider").await;

        let id = Uuid::new_v4();
        let backend = db.get_database_backend();
        db.execute(
            backend.build(
                Query::insert()
                    .into_table(Alias::new("roles"))
                    .columns(["id", "name", "description", "is_default"].map(Alias::new))
                    .values_panic([id.into(), "dba".into(), "".into(), false.into()]),
            ),
        )
        .await
        .unwrap();

        Migrator::up(&db, None).await.unwrap();

        let role = Role::Entity::find_by_id(id)
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(role.provider, None);

        let mut model: Role::ActiveModel = role.into();
        model.provider = Set(Some(ProviderId::GITOPS));
        model.update(&db).await.unwrap();

        let owned = Role::Entity::find()
            .filter(Role::Column::Provider.eq(ProviderId::GITOPS))
            .all(&db)
            .await
            .unwrap();
        assert_eq!(owned.len(), 1);
    }
}

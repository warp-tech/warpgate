use sea_orm::{ConnectionTrait, Order};
use sea_orm_migration::prelude::*;
use uuid::Uuid;

use crate::m00079_unique_target_and_group_names::{
    add_unique_name_index_keeping, drop_unique_name_index,
};

#[derive(DeriveMigrationName)]
pub struct Migration;

const TABLE: &str = "admin_roles";
const INDEX: &str = "admin_roles_name_unique";
const BUILTIN_ADMIN_ROLE_NAME: &str = "warpgate:admin";
const PERMISSIONS: &[&str] = &[
    "targets_create",
    "targets_edit",
    "targets_delete",
    "users_create",
    "users_edit",
    "users_delete",
    "access_roles_create",
    "access_roles_edit",
    "access_roles_delete",
    "access_roles_assign",
    "sessions_view",
    "sessions_terminate",
    "approve_sessions",
    "recordings_view",
    "tickets_create",
    "tickets_delete",
    "config_edit",
    "admin_roles_manage",
    "ticket_requests_manage",
];

/// The built-in admin role is told apart from the others only by its name: the name
/// is what protects it from deletion and what `create-user --role` finds it by. So
/// if other admin roles were given the same name, the built-in one must be the one
/// that keeps it. It is created with every permission (m00032), so of the roles
/// with its name, this picks the one granting the most.
async fn builtin_admin_role(manager: &SchemaManager<'_>) -> Result<Option<Uuid>, DbErr> {
    let db = manager.get_connection();
    let backend = db.get_database_backend();

    let select = Query::select()
        .column(Alias::new("id"))
        .columns(PERMISSIONS.iter().map(|column| Alias::new(*column)))
        .from(Alias::new(TABLE))
        .and_where(Expr::col(Alias::new("name")).eq(BUILTIN_ADMIN_ROLE_NAME))
        .order_by(Alias::new("id"), Order::Asc)
        .to_owned();

    let mut builtin: Option<(usize, Uuid)> = None;
    for row in db.query_all(backend.build(&select)).await? {
        let mut granted = 0;
        for column in PERMISSIONS {
            if row.try_get::<bool>("", column)? {
                granted += 1;
            }
        }
        if builtin.is_none_or(|(most, _)| granted > most) {
            builtin = Some((granted, row.try_get("", "id")?));
        }
    }
    Ok(builtin.map(|(_, id)| id))
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let keep: Vec<Uuid> = builtin_admin_role(manager).await?.into_iter().collect();
        add_unique_name_index_keeping(manager, TABLE, INDEX, &keep).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        drop_unique_name_index(manager, TABLE, INDEX).await
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use sea_orm::{ConnectionTrait, Database, DatabaseConnection, Statement, Value};
    use sea_orm_migration::MigratorTrait;
    use sea_orm_migration::prelude::{Alias, Query};
    use uuid::Uuid;
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};

    use super::PERMISSIONS;
    use crate::Migrator;

    async fn names(db: &DatabaseConnection) -> Vec<(String, String)> {
        db.query_all(Statement::from_string(
            db.get_database_backend(),
            "SELECT id, name FROM admin_roles ORDER BY name",
        ))
        .await
        .unwrap()
        .iter()
        .map(|row| {
            let id: Uuid = row.try_get("", "id").unwrap();
            (id.to_string(), row.try_get("", "name").unwrap())
        })
        .collect()
    }

    #[tokio::test]
    async fn duplicate_admin_role_names_are_renamed_and_then_rejected() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        let before = Migrator::migrations()
            .iter()
            .position(|migration| migration.name() == "m00096_unique_admin_role_names")
            .unwrap();
        Migrator::up(&db, Some(u32::try_from(before).unwrap()))
            .await
            .unwrap();

        // Created by m00032, with every permission and a random id.
        let [(builtin, _)]: [_; 1] = names(&db).await.try_into().unwrap();

        let backend = db.get_database_backend();
        let insert = |id: Uuid, name: &str| {
            let mut values: Vec<Value> = vec![id.into(), name.into(), "".into()];
            values.extend(PERMISSIONS.iter().map(|_| false.into()));
            backend.build(
                Query::insert()
                    .into_table(Alias::new("admin_roles"))
                    .columns(
                        ["id", "name", "description"]
                            .iter()
                            .chain(PERMISSIONS)
                            .map(|column| Alias::new(*column)),
                    )
                    .values_panic(values.into_iter().map(Into::into)),
            )
        };
        // A permission-less role under the built-in role's name, with an id that
        // sorts before any other.
        let impostor = Uuid::nil();
        db.execute(insert(impostor, "warpgate:admin"))
            .await
            .unwrap();
        for name in ["ops", "ops", "dev"] {
            db.execute(insert(Uuid::new_v4(), name)).await.unwrap();
        }

        Migrator::up(&db, None).await.unwrap();

        let names = names(&db).await;
        assert_eq!(
            names
                .iter()
                .map(|(_, name)| name.as_str())
                .collect::<Vec<_>>(),
            [
                "dev",
                "ops",
                "ops (2)",
                "warpgate:admin",
                "warpgate:admin (2)"
            ]
        );
        assert!(names.contains(&(builtin, "warpgate:admin".into())));
        assert!(names.contains(&(impostor.to_string(), "warpgate:admin (2)".into())));

        db.execute(insert(Uuid::new_v4(), "dev"))
            .await
            .expect_err("the unique index must reject a duplicate admin role name");
    }
}

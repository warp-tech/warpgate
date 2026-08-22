use sea_orm::{ConnectionTrait, DatabaseTransaction, StatementBuilder, TransactionTrait};
use sea_orm_migration::prelude::*;

/// The three role-assignment tables carried an autoincrement integer primary
/// key that nothing ever read - an assignment is only ever looked up by the
/// columns it joins. Those columns are the real key, so they become the primary
/// key here. That also enforces the uniqueness the app has always assumed but
/// the schema never guaranteed (two concurrent grants could leave duplicate
/// rows behind), and it makes the m00065 lookup indexes redundant: the primary
/// key indexes the same columns.
#[derive(DeriveMigrationName)]
pub struct Migration;

/// Name suffix for the replacement table while it is built alongside the
/// original; the two swap places once it is populated.
const TMP: &str = "_new_pk";

const USER_ROLES: &str = "user_roles";
const USER_ADMIN_ROLES: &str = "user_admin_roles";
const TARGET_ROLES: &str = "target_roles";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // sea-orm only wraps a migration in a transaction on PostgreSQL. Left to
        // itself on SQLite, the statements below land on different pooled
        // connections, and one holding an older schema snapshot rejects them -
        // so this migration keeps itself on a single connection.
        let db = manager.get_connection().begin().await?;

        exec(
            &db,
            &(Table::create()
                .table(tmp(USER_ROLES))
                .col(ColumnDef::new(Alias::new("user_id")).uuid().not_null())
                .col(ColumnDef::new(Alias::new("role_id")).uuid().not_null())
                .col(timestamp_column("granted_at"))
                .col(timestamp_column("expires_at"))
                .col(timestamp_column("revoked_at"))
                .primary_key(
                    Index::create()
                        .col(Alias::new("user_id"))
                        .col(Alias::new("role_id")),
                )
                .foreign_key(&mut foreign_key(USER_ROLES, "user_id", "users"))
                .foreign_key(&mut foreign_key(USER_ROLES, "role_id", "roles"))
                .to_owned()),
        )
        .await?;

        // Duplicate pairs were possible until now, so only one row per pair
        // survives: a live assignment in preference to a revoked one, and the
        // most recently added of those.
        exec_raw(
            &db,
            &format!(
                "INSERT INTO {USER_ROLES}{TMP} (user_id, role_id, granted_at, expires_at, revoked_at)
                 SELECT o.user_id, o.role_id, o.granted_at, o.expires_at, o.revoked_at
                 FROM {USER_ROLES} o
                 WHERE o.id = (
                     SELECT i.id FROM {USER_ROLES} i
                     WHERE i.user_id = o.user_id AND i.role_id = o.role_id
                     ORDER BY CASE WHEN i.revoked_at IS NULL THEN 0 ELSE 1 END, i.id DESC
                     LIMIT 1
                 )"
            ),
        )
        .await?;
        swap_in(&db, USER_ROLES).await?;

        exec(
            &db,
            &(Table::create()
                .table(tmp(USER_ADMIN_ROLES))
                .col(ColumnDef::new(Alias::new("user_id")).uuid().not_null())
                .col(
                    ColumnDef::new(Alias::new("admin_role_id"))
                        .uuid()
                        .not_null(),
                )
                .primary_key(
                    Index::create()
                        .col(Alias::new("user_id"))
                        .col(Alias::new("admin_role_id")),
                )
                .foreign_key(&mut foreign_key(USER_ADMIN_ROLES, "user_id", "users"))
                .foreign_key(&mut foreign_key(
                    USER_ADMIN_ROLES,
                    "admin_role_id",
                    "admin_roles",
                ))
                .to_owned()),
        )
        .await?;

        exec_raw(
            &db,
            &format!(
                "INSERT INTO {USER_ADMIN_ROLES}{TMP} (user_id, admin_role_id)
                 SELECT DISTINCT user_id, admin_role_id FROM {USER_ADMIN_ROLES}"
            ),
        )
        .await?;
        swap_in(&db, USER_ADMIN_ROLES).await?;

        exec(
            &db,
            &(Table::create()
                .table(tmp(TARGET_ROLES))
                .col(ColumnDef::new(Alias::new("target_id")).uuid().not_null())
                .col(ColumnDef::new(Alias::new("role_id")).uuid().not_null())
                .primary_key(
                    Index::create()
                        .col(Alias::new("target_id"))
                        .col(Alias::new("role_id")),
                )
                .foreign_key(&mut foreign_key(TARGET_ROLES, "target_id", "targets"))
                .foreign_key(&mut foreign_key(TARGET_ROLES, "role_id", "roles"))
                .to_owned()),
        )
        .await?;

        exec_raw(
            &db,
            &format!(
                "INSERT INTO {TARGET_ROLES}{TMP} (target_id, role_id)
                 SELECT DISTINCT target_id, role_id FROM {TARGET_ROLES}"
            ),
        )
        .await?;
        swap_in(&db, TARGET_ROLES).await?;

        db.commit().await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Restores the surrogate key and the lookup indexes it needed. The rows
        // dropped as duplicates on the way up do not come back.
        let db = manager.get_connection().begin().await?;

        exec(
            &db,
            &(Table::create()
                .table(tmp(USER_ROLES))
                .col(serial_id_column().primary_key())
                .col(ColumnDef::new(Alias::new("user_id")).uuid().not_null())
                .col(ColumnDef::new(Alias::new("role_id")).uuid().not_null())
                .col(timestamp_column("granted_at"))
                .col(timestamp_column("expires_at"))
                .col(timestamp_column("revoked_at"))
                .foreign_key(&mut foreign_key(USER_ROLES, "user_id", "users"))
                .foreign_key(&mut foreign_key(USER_ROLES, "role_id", "roles"))
                .to_owned()),
        )
        .await?;
        exec_raw(
            &db,
            &format!(
                "INSERT INTO {USER_ROLES}{TMP} (user_id, role_id, granted_at, expires_at, revoked_at)
                 SELECT user_id, role_id, granted_at, expires_at, revoked_at FROM {USER_ROLES}"
            ),
        )
        .await?;
        swap_in(&db, USER_ROLES).await?;

        exec(
            &db,
            &(Table::create()
                .table(tmp(USER_ADMIN_ROLES))
                .col(serial_id_column().primary_key())
                .col(ColumnDef::new(Alias::new("user_id")).uuid().not_null())
                .col(
                    ColumnDef::new(Alias::new("admin_role_id"))
                        .uuid()
                        .not_null(),
                )
                .foreign_key(&mut foreign_key(USER_ADMIN_ROLES, "user_id", "users"))
                .foreign_key(&mut foreign_key(
                    USER_ADMIN_ROLES,
                    "admin_role_id",
                    "admin_roles",
                ))
                .to_owned()),
        )
        .await?;
        exec_raw(
            &db,
            &format!(
                "INSERT INTO {USER_ADMIN_ROLES}{TMP} (user_id, admin_role_id)
                 SELECT user_id, admin_role_id FROM {USER_ADMIN_ROLES}"
            ),
        )
        .await?;
        swap_in(&db, USER_ADMIN_ROLES).await?;

        exec(
            &db,
            &(Table::create()
                .table(tmp(TARGET_ROLES))
                .col(serial_id_column().primary_key())
                .col(ColumnDef::new(Alias::new("target_id")).uuid().not_null())
                .col(ColumnDef::new(Alias::new("role_id")).uuid().not_null())
                .foreign_key(&mut foreign_key(TARGET_ROLES, "target_id", "targets"))
                .foreign_key(&mut foreign_key(TARGET_ROLES, "role_id", "roles"))
                .to_owned()),
        )
        .await?;
        exec_raw(
            &db,
            &format!(
                "INSERT INTO {TARGET_ROLES}{TMP} (target_id, role_id)
                 SELECT target_id, role_id FROM {TARGET_ROLES}"
            ),
        )
        .await?;
        swap_in(&db, TARGET_ROLES).await?;

        exec(
            &db,
            &(Index::create()
                .name("idx_user_roles_user_role")
                .table(Alias::new(USER_ROLES))
                .col(Alias::new("user_id"))
                .col(Alias::new("role_id"))
                .to_owned()),
        )
        .await?;
        exec(
            &db,
            &(Index::create()
                .name("idx_target_roles_target_role")
                .table(Alias::new(TARGET_ROLES))
                .col(Alias::new("target_id"))
                .col(Alias::new("role_id"))
                .to_owned()),
        )
        .await?;

        db.commit().await
    }
}

fn tmp(table: &str) -> Alias {
    Alias::new(format!("{table}{TMP}"))
}

fn serial_id_column() -> ColumnDef {
    ColumnDef::new(Alias::new("id"))
        .integer()
        .not_null()
        .auto_increment()
        .to_owned()
}

fn timestamp_column(name: &str) -> ColumnDef {
    ColumnDef::new(Alias::new(name))
        .date_time()
        .timestamp_with_time_zone()
        .null()
        .to_owned()
}

fn foreign_key(table: &str, column: &str, references: &str) -> ForeignKeyCreateStatement {
    ForeignKey::create()
        .from(tmp(table), Alias::new(column))
        .to(Alias::new(references), Alias::new("id"))
        .to_owned()
}

/// Drops the original table and moves the replacement into its place. Safe in
/// either direction: nothing in the schema points at these three tables.
async fn swap_in(db: &DatabaseTransaction, table: &str) -> Result<(), DbErr> {
    exec(db, &Table::drop().table(Alias::new(table)).to_owned()).await?;
    exec(
        db,
        &Table::rename()
            .table(tmp(table), Alias::new(table))
            .to_owned(),
    )
    .await
}

/// Runs one sea-query statement on the migration's own connection.
async fn exec<S: StatementBuilder>(db: &DatabaseTransaction, stmt: &S) -> Result<(), DbErr> {
    let statement = db.get_database_backend().build(stmt);
    db.execute(statement).await?;
    Ok(())
}

async fn exec_raw(db: &DatabaseTransaction, sql: &str) -> Result<(), DbErr> {
    db.execute_unprepared(sql).await?;
    Ok(())
}

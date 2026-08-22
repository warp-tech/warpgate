use std::collections::HashSet;

use sea_orm::{ConnectionTrait, DbBackend, Order};
use sea_orm_migration::prelude::*;
use uuid::Uuid;

#[derive(DeriveMigrationName)]
pub struct Migration;

const TABLES: &[(&str, &str)] = &[
    ("targets", "targets_name_unique"),
    ("target_groups", "target_groups_name_unique"),
];

/// Picks a free name for a duplicate row. `key` maps a name to the form the
/// backend's unique index compares.
fn deduplicated_name(taken: &HashSet<String>, name: &str, key: fn(&str) -> String) -> String {
    let mut suffix = 2;
    loop {
        let candidate = format!("{name} ({suffix})");
        if !taken.contains(&key(&candidate)) {
            return candidate;
        }
        suffix += 1;
    }
}

/// Renames rows that would collide, rather than deleting them: these rows carry the
/// access configuration for a machine, and dropping one silently revokes it.
async fn deduplicate_names(manager: &SchemaManager<'_>, table: &str) -> Result<(), DbErr> {
    let db = manager.get_connection();
    let backend = db.get_database_backend();

    let table = Alias::new(table);
    let id_col = Alias::new("id");
    let name_col = Alias::new("name");

    // Scanning in name order means a suffix we hand out is always compared against
    // the rows that could still claim it.
    let select = Query::select()
        .column(id_col.clone())
        .column(name_col.clone())
        .from(table.clone())
        .order_by(name_col.clone(), Order::Asc)
        .order_by(id_col.clone(), Order::Asc)
        .to_owned();

    // MySQL's default collation makes the unique index case-insensitive, so `prod`
    // and `PROD` would fail the index creation there while being two perfectly
    // addressable rows everywhere else.
    let key: fn(&str) -> String = if backend == DbBackend::MySql {
        |name| name.to_lowercase()
    } else {
        str::to_owned
    };

    let mut taken: HashSet<String> = HashSet::new();
    for row in db.query_all(backend.build(&select)).await? {
        let id: Uuid = row.try_get("", "id")?;
        let name: String = row.try_get("", "name")?;
        if taken.insert(key(&name)) {
            continue;
        }

        let renamed = deduplicated_name(&taken, &name, key);
        let update = Query::update()
            .table(table.clone())
            .value(name_col.clone(), renamed.clone())
            .and_where(Expr::col(id_col.clone()).eq(id))
            .to_owned();
        db.execute(backend.build(&update)).await?;
        taken.insert(key(&renamed));
    }

    Ok(())
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (table, index) in TABLES {
            deduplicate_names(manager, table).await?;

            // CREATE UNIQUE INDEX rather than ALTER COLUMN so that this works on SQLite,
            // which does not support altering column constraints.
            manager
                .create_index(
                    Index::create()
                        .name(*index)
                        .table(Alias::new(*table))
                        .col(Alias::new("name"))
                        .unique()
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (table, index) in TABLES {
            manager
                .drop_index(
                    Index::drop()
                        .name(*index)
                        .table(Alias::new(*table))
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deduplicated_name_skips_taken_names() {
        let taken: HashSet<String> = ["prod", "prod (2)"].iter().map(|s| (*s).into()).collect();
        assert_eq!(deduplicated_name(&taken, "prod", str::to_owned), "prod (3)");
        assert_eq!(deduplicated_name(&taken, "dev", str::to_owned), "dev (2)");
        assert_eq!(deduplicated_name(&taken, "PROD", str::to_owned), "PROD (2)");
        assert_eq!(
            deduplicated_name(&taken, "PROD", |name| name.to_lowercase()),
            "PROD (3)"
        );
    }
}

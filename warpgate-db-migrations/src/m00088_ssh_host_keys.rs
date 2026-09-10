use sea_orm::{ConnectionTrait, EntityTrait};
use sea_orm_migration::prelude::*;
use warpgate_common::SshHostKeyKind;
use warpgate_db_entities::Parameters::get_config_migration_values;

use crate::helpers::string_default_value;
use crate::m00010_parameters::parameters;

/// SSH host keys move out of the `ssh.keys` directory into the parameters row.
/// The columns are empty only between being added and being filled in below.
#[derive(DeriveMigrationName)]
pub struct Migration;

fn column(kind: SshHostKeyKind) -> Alias {
    Alias::new(format!("ssh_host_key_{}", kind.name()))
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        for kind in SshHostKeyKind::ALL {
            manager
                .alter_table(
                    Table::alter()
                        .table(parameters::Entity)
                        .add_column(
                            ColumnDef::new(column(kind))
                                .text()
                                .not_null()
                                .default(string_default_value(backend, "")),
                        )
                        .to_owned(),
                )
                .await?;
        }

        // Fill in the row of an existing install: its on-disk keys (published
        // by the process before migrations run), or fresh ones when it has
        // none. A fresh install has no row yet and is seeded by
        // `Parameters::Entity::get`.
        let db = manager.get_connection();
        if parameters::Entity::find().one(db).await?.is_none() {
            return Ok(());
        }
        let values = get_config_migration_values();
        let mut stmt = Query::update();
        stmt.table(parameters::Entity);
        for kind in SshHostKeyKind::ALL {
            let stored = values
                .effective_stored_ssh_host_key(kind)
                .map_err(|e| DbErr::Custom(e.to_string()))?;
            stmt.value(column(kind), stored);
        }
        db.execute(backend.build(&stmt)).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for kind in SshHostKeyKind::ALL {
            manager
                .alter_table(
                    Table::alter()
                        .table(parameters::Entity)
                        .drop_column(column(kind))
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}

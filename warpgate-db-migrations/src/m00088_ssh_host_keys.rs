use sea_orm_migration::prelude::*;
use warpgate_common::SshHostKeyKind;

use crate::helpers::string_default_value;
use crate::m00010_parameters::parameters;

/// SSH host keys move out of the `ssh.keys` directory into the parameters row.
/// The columns start out empty; `ensure_host_keys` fills them at the next
/// startup, importing the files if they are still there and generating keys
/// otherwise.
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

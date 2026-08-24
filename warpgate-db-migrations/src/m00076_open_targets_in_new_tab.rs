use sea_orm_migration::prelude::*;

use crate::m00010_parameters::parameters;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("open_targets_in_new_tab"))
                            .string_len(32)
                            .not_null()
                            // Frozen copy of `OpenTargetsInNewTabMode::DefaultOn`'s
                            // string value: a migration must not track the live
                            // enum, or a later rename would change what old
                            // installs hold vs. what fresh ones get.
                            .default("DefaultOn"),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .drop_column(Alias::new("open_targets_in_new_tab"))
                    .to_owned(),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::ActiveEnum;
    use warpgate_db_entities::Parameters::OpenTargetsInNewTabMode;

    /// Pins the frozen literal above to the live enum: if the enum's string
    /// value is ever renamed, this fails instead of silently diverging fresh
    /// installs from upgraded ones.
    #[test]
    fn frozen_default_matches_live_enum() {
        assert_eq!(OpenTargetsInNewTabMode::DefaultOn.to_value(), "DefaultOn");
    }
}

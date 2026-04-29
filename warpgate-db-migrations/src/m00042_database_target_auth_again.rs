use sea_orm_migration::prelude::*;

/// Just rerun m00037 since now some entries could be malformed again
/// due to https://github.com/warp-tech/warpgate/issues/1883
#[derive(DeriveMigrationName)]
pub struct Migration;

use super::m00037_database_target_auth::Migration as PreviousMigration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        PreviousMigration.up(manager).await
    }

    #[allow(clippy::panic, reason = "dev only")]
    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        panic!("This migration cannot be reversed");
    }
}

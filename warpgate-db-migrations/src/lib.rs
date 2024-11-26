use sea_orm::DatabaseConnection;
use sea_orm_migration::prelude::*;
use sea_orm_migration::MigrationTrait;

mod m00001_create_ticket;
mod m00002_create_session;
mod m00003_create_recording;
mod m00004_create_known_host;
mod m00005_create_log_entry;
mod m00006_add_session_protocol;
mod m00007_targets_and_roles;
mod m00008_users;
mod m00009_credential_models;
mod m00010_parameters;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m00001_create_ticket::Migration),
            Box::new(m00002_create_session::Migration),
            Box::new(m00003_create_recording::Migration),
            Box::new(m00004_create_known_host::Migration),
            Box::new(m00005_create_log_entry::Migration),
            Box::new(m00006_add_session_protocol::Migration),
            Box::new(m00007_targets_and_roles::Migration),
            Box::new(m00008_users::Migration),
            Box::new(m00009_credential_models::Migration),
            Box::new(m00010_parameters::Migration),
        ]
    }
}

pub async fn migrate_database(connection: &DatabaseConnection) -> Result<(), DbErr> {
    Migrator::up(connection, None).await
}

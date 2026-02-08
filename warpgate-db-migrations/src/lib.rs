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
mod m00011_rsa_key_algos;
mod m00012_add_openssh_public_key_label;
mod m00013_add_openssh_public_key_dates;
mod m00014_api_tokens;
mod m00015_fix_public_key_dates;
mod m00016_fix_public_key_length;
mod m00017_descriptions;
mod m00018_ticket_description;
mod m00019_rate_limits;
mod m00020_target_groups;
mod m00021_ldap_server;
mod m00022_user_ldap_link;
mod m00023_ldap_username_attribute;
mod m00024_ssh_key_attribute;
mod m00025_ldap_uuid_attribute;
mod m00026_ssh_client_auth;
mod m00027_ca;
mod m00028_certificate_credentials;
mod m00029_certificate_revocation;
mod m00030_add_recording_metadata;
mod m00031_file_transfer_permissions;
mod m00032_file_transfer_config;
mod m00033_user_role_expiry_history;
mod m00034_role_file_transfer_defaults;
mod m00035_target_role_nullable_overrides;
mod m00036_sftp_permission_mode;

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
            Box::new(m00011_rsa_key_algos::Migration),
            Box::new(m00012_add_openssh_public_key_label::Migration),
            Box::new(m00013_add_openssh_public_key_dates::Migration),
            Box::new(m00014_api_tokens::Migration),
            Box::new(m00015_fix_public_key_dates::Migration),
            Box::new(m00016_fix_public_key_length::Migration),
            Box::new(m00017_descriptions::Migration),
            Box::new(m00018_ticket_description::Migration),
            Box::new(m00019_rate_limits::Migration),
            Box::new(m00020_target_groups::Migration),
            Box::new(m00021_ldap_server::Migration),
            Box::new(m00022_user_ldap_link::Migration),
            Box::new(m00023_ldap_username_attribute::Migration),
            Box::new(m00024_ssh_key_attribute::Migration),
            Box::new(m00025_ldap_uuid_attribute::Migration),
            Box::new(m00026_ssh_client_auth::Migration),
            Box::new(m00027_ca::Migration),
            Box::new(m00028_certificate_credentials::Migration),
            Box::new(m00029_certificate_revocation::Migration),
            Box::new(m00030_add_recording_metadata::Migration),
            Box::new(m00031_file_transfer_permissions::Migration),
            Box::new(m00032_file_transfer_config::Migration),
            Box::new(m00033_user_role_expiry_history::Migration),
            Box::new(m00034_role_file_transfer_defaults::Migration),
            Box::new(m00035_target_role_nullable_overrides::Migration),
            Box::new(m00036_sftp_permission_mode::Migration),
        ]
    }
}

pub async fn migrate_database(connection: &DatabaseConnection) -> Result<(), DbErr> {
    Migrator::up(connection, None).await
}

use anyhow::{Context, Result, bail};
use sea_orm::{
    ConnectionTrait, Database, DatabaseConnection, EntityTrait, IntoActiveModel, Iterable,
    PaginatorTrait, PrimaryKeyToColumn, QueryOrder, TransactionTrait,
};
use tracing::info;
use warpgate_common::GlobalParams;
use warpgate_core::db::{connect_to_db, migrate_all};
use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};

use crate::config::load_config;

/// Tables ordered from dependencies to dependents
macro_rules! with_every_table_in_order {
    ($callback:ident) => {
        $callback![
            User,
            Role,
            Target,
            AdminRole,
            Parameters,
            Node,
            LdapServer,
            SshClientKey,
            TargetGroup,
            KnownHost,
            IpBlock,
            FailedLoginAttempt,
            UserLockout,
            HttpSession,
            LogEntry,
            CertificateRevocation,
            // Referencing the tables above
            Ticket,
            UserSession,
            TargetSession,
            Recording,
            TicketRequest,
            TargetRoleAssignment,
            UserRoleAssignment,
            UserAdminRoleAssignment,
            ApiToken,
            PasswordCredential,
            PublicKeyCredential,
            OtpCredential,
            SsoCredential,
            CertificateCredential,
        ];
    };
}

mod compile_time_check_table_list {
    // one marker per table
    mod copied {
        macro_rules! markers {
        ($($entity:ident),* $(,)?) => {
            $( #[allow(non_upper_case_globals)] pub const $entity: () = (); )*
        };
    }
        with_every_table_in_order!(markers);
    }

    // fails to compile if an entry in with_every_entity does not exist in with_every_table_in_order
    const _: () = {
        macro_rules! check {
        ($($entity:ident),* $(,)?) => {
            $( let _ = copied::$entity; )*
        };
    }
        warpgate_db_entities::with_every_entity!(check);
    };
}

const BATCH_SIZE: u64 = 500;

pub async fn command(params: &GlobalParams, target_url: &str) -> Result<()> {
    let config = load_config(params, true)?;
    let source = connect_to_db(&config, params).await?;
    let target = Database::connect(target_url)
        .await
        .context("Failed to connect to the target database")?;

    set_config_migration_values(ConfigMigrationValues::from_config(&config));

    info!("Creating the schema");
    migrate_all(&target).await?;

    ensure_target_is_empty(&target).await?;

    {
        // Migrations create some default entries in the DB
        let target_tx = target.begin().await?;
        clear_tables(&target_tx).await?;
        info!("Copying data");
        copy_rows(&source, &target_tx).await?;
        target_tx.commit().await?;
    }

    info!("Done.");
    info!(
        "You can now update `database_url` in the config file to the target database and start Warpgate."
    );

    Ok(())
}

async fn copy_rows<S: ConnectionTrait, T: ConnectionTrait>(source: &S, target: &T) -> Result<()> {
    macro_rules! copy {
        ($($entity:ident),* $(,)?) => {
            $( copy_table::<warpgate_db_entities::$entity::Entity, _, _>(source, target).await?; )*
        };
    }
    with_every_table_in_order!(copy);
    Ok(())
}

async fn clear_tables<T: ConnectionTrait>(target: &T) -> Result<()> {
    macro_rules! clear {
        ($($entity:ident),* $(,)?) => {
            $( warpgate_db_entities::$entity::Entity::delete_many().exec(target).await?; )*
        };
    }
    with_every_table_in_order!(clear);
    Ok(())
}

async fn copy_table<E, S, T>(source: &S, target: &T) -> Result<()>
where
    E: EntityTrait,
    E::Model: IntoActiveModel<E::ActiveModel> + Send + Sync,
    S: ConnectionTrait,
    T: ConnectionTrait,
{
    let table = E::default().table_name().to_owned();

    // order by PK
    let mut query = E::find();
    for key in E::PrimaryKey::iter() {
        query = query.order_by_asc(key.into_column());
    }

    let mut rows_copied = 0usize;
    let mut pages = query.paginate(source, BATCH_SIZE);
    while let Some(rows) = pages.fetch_and_next().await? {
        rows_copied += rows.len();
        E::insert_many(rows.into_iter().map(|row| row.into_active_model()))
            .exec_without_returning(target)
            .await
            .with_context(|| format!("Failed to copy into {table}"))?;
    }

    info!("{table}: {rows_copied} row(s)");

    Ok(())
}

async fn ensure_target_is_empty(target: &DatabaseConnection) -> Result<()> {
    use warpgate_db_entities::{Role, Target, User};

    let rows = User::Entity::find().count(target).await?
        + Role::Entity::find().count(target).await?
        + Target::Entity::find().count(target).await?;

    if rows > 0 {
        bail!(
            "The target database already contains data, possibly from a previous copy process - aborting"
        );
    }

    Ok(())
}

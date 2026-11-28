#![allow(non_snake_case)]

// macro list allows compile-time iteration

#[macro_export]
macro_rules! with_every_entity {
    ($callback:ident) => {
        $callback![
            AdminRole,
            ApiToken,
            CertificateCredential,
            CertificateRevocation,
            FailedLoginAttempt,
            HttpSession,
            IpBlock,
            KnownHost,
            KubernetesSession,
            LdapServer,
            LogEntry,
            Node,
            OtpCredential,
            Parameters,
            PasswordCredential,
            ProviderSync,
            PublicKeyCredential,
            Recording,
            Role,
            SecretBackend,
            SessionApprovalRequest,
            SshClientKey,
            SsoCredential,
            Target,
            TargetGroup,
            TargetRoleAssignment,
            TargetSession,
            Ticket,
            TicketRequest,
            User,
            UserAdminRoleAssignment,
            UserLockout,
            UserRoleAssignment,
            UserSession,
        ];
    };
}

macro_rules! declare_modules {
    ($($name:ident),* $(,)?) => {
        $( pub mod $name; )*
    };
}

with_every_entity!(declare_modules);

/// SQLite fails a read transaction's first write without waiting for the busy
/// timeout if another connection has written since. `BEGIN IMMEDIATE` takes
/// the write lock up front, so writers queue. Other backends ignore the mode
pub async fn begin_write<C: sea_orm::TransactionTrait>(
    db: &C,
) -> Result<C::Transaction, sea_orm::DbErr> {
    db.begin_with_options(sea_orm::TransactionOptions {
        sqlite_transaction_mode: Some(sea_orm::SqliteTransactionMode::Immediate),
        ..Default::default()
    })
    .await
}

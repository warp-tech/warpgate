//! Audit entries for resource writes. Admin edits and provider syncs log
//! the same entry

use std::future::Future;

use sea_orm::ConnectionTrait;
use serde::Serialize;
use serde_json::Value;
use tracing::warn;
use uuid::Uuid;
use warpgate_common::{
    ProviderId, RowId, User as UserConfig, UserId, UserRequireCredentialsPolicy, WarpgateError,
};
use warpgate_db_entities::ProviderSync::PlannedField;
use warpgate_db_entities::{AdminRole, KnownHost, User};
pub use warpgate_resources::ComparableValues;
use warpgate_resources::ResourceKind;

use super::OwnedEntity;
use crate::logging::AuditEvent;

#[derive(Clone, Copy, Debug)]
pub enum ChangedBy {
    Admin(UserId),
    Sync {
        id: Uuid,
        provider: ProviderId,
        /// The admin who requested the sync
        admin: Option<UserId>,
    },
}

impl ChangedBy {
    /// Sync ID with the provider's label, and the acting admin
    pub(crate) fn origin(self) -> (Option<(Uuid, String)>, Option<UserId>) {
        match self {
            Self::Admin(user) => (None, Some(user)),
            Self::Sync {
                id,
                provider,
                admin,
            } => (Some((id, provider.label())), admin),
        }
    }
}

/// Rows that no provider can manage
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowKind {
    User,
    AdminRole,
    LdapServer,
    SecretBackend,
    KnownHost,
    Parameters,
}

#[derive(Clone, Copy, Debug)]
pub enum Subject {
    Resource(ResourceKind, Uuid),
    Row(RowKind, Uuid),
}

impl Subject {
    pub fn of<E: OwnedEntity>(id: E::Id) -> Self {
        Self::Resource(E::KIND, id.uuid())
    }

    /// The kind as the log records it. The log viewer matches on these names
    pub const fn kind(self) -> &'static str {
        match self {
            Self::Resource(ResourceKind::Target, _) => "Target",
            Self::Resource(ResourceKind::TargetGroup, _) => "TargetGroup",
            Self::Resource(ResourceKind::Role, _) => "Role",
            Self::Resource(ResourceKind::SshClientKey, _) => "SshClientKey",
            Self::Row(RowKind::User, _) => "User",
            Self::Row(RowKind::AdminRole, _) => "AdminRole",
            Self::Row(RowKind::LdapServer, _) => "LdapServer",
            Self::Row(RowKind::SecretBackend, _) => "SecretBackend",
            Self::Row(RowKind::KnownHost, _) => "KnownHost",
            Self::Row(RowKind::Parameters, _) => "Parameters",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Create,
    Update,
    /// An update that also made a provider the row's owner
    Adopt,
    Delete,
}

impl Action {
    /// The action as the log records it. The log viewer matches on these names
    pub const fn name(self) -> &'static str {
        match self {
            Self::Create => "Create",
            Self::Update => "Update",
            Self::Adopt => "Adopt",
            Self::Delete => "Delete",
        }
    }
}

/// A row that the audit log can describe
pub trait Audited {
    fn subject(&self) -> Subject;

    fn name(&self) -> String;

    /// The fields that the log compares. The log prints the value of every
    /// field that isn't marked as a credential
    fn compared<C: ConnectionTrait>(
        &self,
        db: &C,
    ) -> impl Future<Output = Result<ComparableValues, WarpgateError>> + Send;
}

/// Compares a row without a spec by its serialized columns. `redacted` is
/// `row` with its credentials blanked. Fields that differ between the two are
/// logged without values. `id` and `name` are left out: the entry has both
pub fn columns<M: Serialize>(row: &M, redacted: &M) -> Result<ComparableValues, WarpgateError> {
    let columns = |row: &M| {
        let mut value = serde_json::to_value(row)?;
        if let Value::Object(columns) = &mut value {
            columns.remove("id");
            columns.remove("name");
        }
        Ok::<_, WarpgateError>(value)
    };
    Ok(ComparableValues::redacting(
        &columns(row)?,
        &columns(redacted)?,
    ))
}

/// A write that isn't in the audit log yet. The written row is reachable
/// only through `audited`, `deferred` or `skip_audit`
#[must_use]
#[derive(Debug)]
pub struct Unaudited<M>(Write<M>);

#[derive(Debug)]
enum Write<M> {
    Created(M),
    Updated {
        before: M,
        after: M,
    },
    /// An update that also made a provider the row's owner
    Adopted {
        before: M,
        after: M,
    },
    Deleted(M),
}

impl<M> Unaudited<M> {
    pub(super) const fn created(row: M) -> Self {
        Self(Write::Created(row))
    }

    pub(super) const fn updated(before: M, after: M) -> Self {
        Self(Write::Updated { before, after })
    }

    pub(super) const fn deleted(row: M) -> Self {
        Self(Write::Deleted(row))
    }

    /// An update becomes an adoption. Other writes are unchanged
    pub(super) fn adopted(self) -> Self {
        match self.0 {
            Write::Updated { before, after } => Self(Write::Adopted { before, after }),
            write => Self(write),
        }
    }

    /// The written row, without a log entry. For a write that nobody made,
    /// such as a key generated at startup
    pub fn skip_audit(self) -> M {
        match self.0 {
            Write::Created(row)
            | Write::Deleted(row)
            | Write::Updated { after: row, .. }
            | Write::Adopted { after: row, .. } => row,
        }
    }
}

impl<M: Audited> Unaudited<M> {
    pub async fn audited<C: ConnectionTrait>(self, db: &C, by: ChangedBy) -> M {
        let (row, entry) = self.deferred(db).await;
        entry.log(by);
        row
    }

    /// For a write inside a transaction. `db` is the transaction, and the
    /// caller logs the entry after the commit
    pub async fn deferred<C: ConnectionTrait>(self, db: &C) -> (M, Entry) {
        let entry = match &self.0 {
            Write::Created(row) => creation(db, row).await,
            Write::Updated { before, after } => update(db, Action::Update, before, after).await,
            Write::Adopted { before, after } => update(db, Action::Adopt, before, after).await,
            Write::Deleted(row) => deletion(row),
        };
        (self.skip_audit(), entry)
    }
}

/// The log entry of a write. Empty for an update that changed no field
#[must_use]
#[derive(Debug)]
pub struct Entry(Option<ResourceChange>);

impl Entry {
    pub fn log(&self, by: ChangedBy) {
        if let Some(change) = &self.0 {
            AuditEvent::ResourceChanged {
                change: change.clone(),
                by,
            }
            .emit();
        }
    }
}

/// Logs the fields that the new row sets
pub async fn created<A: Audited, C: ConnectionTrait>(db: &C, by: ChangedBy, row: &A) {
    creation(db, row).await.log(by);
}

/// Logs the fields that differ. Logs nothing if none does
pub async fn updated<A: Audited, C: ConnectionTrait>(db: &C, by: ChangedBy, before: &A, after: &A) {
    update(db, Action::Update, before, after).await.log(by);
}

pub fn deleted<A: Audited>(by: ChangedBy, row: &A) {
    deletion(row).log(by);
}

async fn creation<A: Audited, C: ConnectionTrait>(db: &C, row: &A) -> Entry {
    let fields = compared(db, row).await.map(|row| row.contents());
    entry(Action::Create, row, fields)
}

/// An adoption is logged even if no field changed, because the row has a new
/// owner
async fn update<A: Audited, C: ConnectionTrait>(
    db: &C,
    action: Action,
    before: &A,
    after: &A,
) -> Entry {
    let fields = changes(db, before, after).await;
    if action == Action::Update && fields.as_ref().is_some_and(Vec::is_empty) {
        return Entry(None);
    }
    entry(action, after, fields)
}

fn deletion<A: Audited>(row: &A) -> Entry {
    entry(Action::Delete, row, Some(vec![]))
}

/// `None` if a row can't be compared
async fn changes<A: Audited, C: ConnectionTrait>(
    db: &C,
    before: &A,
    after: &A,
) -> Option<Vec<PlannedField>> {
    let before = compared(db, before).await?;
    let after = compared(db, after).await?;
    let fields = before.changes_to(&after);
    Some(fields.iter().map(PlannedField::from).collect())
}

/// `None` if the row can't be compared: a credential no longer decrypts, or
/// its options are malformed. The write is then logged without fields
async fn compared<A: Audited, C: ConnectionTrait>(db: &C, row: &A) -> Option<ComparableValues> {
    let name = row.name();
    match row.compared(db).await {
        Ok(compared) => Some(compared.named(&name)),
        Err(_) => {
            // The error can quote the row, which can hold credentials
            warn!(subject = ?row.subject(), name, "Could not tell the fields of a written row");
            None
        }
    }
}

fn entry<A: Audited>(action: Action, row: &A, fields: Option<Vec<PlannedField>>) -> Entry {
    Entry(Some(ResourceChange {
        action,
        subject: row.subject(),
        name: row.name(),
        fields,
    }))
}

/// A written row as the log records it
#[derive(Clone, Debug)]
pub struct ResourceChange {
    pub(crate) action: Action,
    pub(crate) subject: Subject,
    pub(crate) name: String,
    /// The changed fields, or a new row's set fields, without credential
    /// values. `None` if the rows could not be compared
    pub(crate) fields: Option<Vec<PlannedField>>,
}

/// The compared fields of a user. Users have no spec
#[derive(Serialize)]
struct UserFields {
    description: String,
    credential_policy: UserRequireCredentialsPolicy,
    rate_limit_bytes_per_second: Option<i64>,
    allowed_ip_ranges: Option<Vec<String>>,
}

impl Audited for User::Model {
    fn subject(&self) -> Subject {
        Subject::Row(RowKind::User, self.id.uuid())
    }

    fn name(&self) -> String {
        self.username.clone()
    }

    async fn compared<C: ConnectionTrait>(
        &self,
        _db: &C,
    ) -> Result<ComparableValues, WarpgateError> {
        let user = UserConfig::try_from(self.clone())?;
        Ok(ComparableValues::plain(&UserFields {
            description: user.description,
            credential_policy: user.credential_policy.unwrap_or_default(),
            rate_limit_bytes_per_second: user.rate_limit_bytes_per_second,
            allowed_ip_ranges: user
                .allowed_ip_ranges
                .map(|ranges| ranges.iter().map(|range| range.to_string()).collect()),
        }))
    }
}

impl Audited for AdminRole::Model {
    fn subject(&self) -> Subject {
        Subject::Row(RowKind::AdminRole, self.id)
    }

    fn name(&self) -> String {
        self.name.clone()
    }

    async fn compared<C: ConnectionTrait>(
        &self,
        _db: &C,
    ) -> Result<ComparableValues, WarpgateError> {
        columns(self, self)
    }
}

impl Audited for KnownHost::Model {
    fn subject(&self) -> Subject {
        Subject::Row(RowKind::KnownHost, self.id)
    }

    fn name(&self) -> String {
        self.address()
    }

    async fn compared<C: ConnectionTrait>(
        &self,
        _db: &C,
    ) -> Result<ComparableValues, WarpgateError> {
        columns(self, self)
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use sea_orm::prelude::Expr;
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
    use serde_json::json;
    use warpgate_common::RoleId;
    use warpgate_db_entities::{Role, Target};

    use super::*;
    use crate::resources::Actor;
    use crate::resources::target_groups::{self, TargetGroupDataRequest};
    use crate::resources::targets::{self, TargetDataRequest};
    use crate::resources::tests::{db, target};

    fn web(port: u16, password: &str) -> TargetDataRequest {
        target(
            "web",
            json!({"ssh": {
                "host": "h",
                "port": port,
                "auth": {"kind": "password", "password": password},
            }}),
        )
    }

    fn paths(fields: &[PlannedField]) -> Vec<&str> {
        fields.iter().map(|field| field.path.as_str()).collect()
    }

    #[tokio::test]
    async fn a_target_is_told_by_its_fields() {
        let db = db().await;
        let prod = TargetGroupDataRequest {
            name: "prod".into(),
            description: None,
            color: None,
        };
        let prod = target_groups::create(&db, Actor::Admin, &prod)
            .await
            .unwrap()
            .skip_audit();
        let created = targets::create(&db, Actor::Admin, &web(22, "old-secret"))
            .await
            .unwrap()
            .skip_audit();

        let contents = compared(&db, &created).await.unwrap().contents();
        let port = contents
            .iter()
            .find(|field| field.path == "spec.options.ssh.port");
        assert_eq!(
            port.map(|field| (&field.from, &field.to)),
            Some((&None, &Some(json!(22))))
        );
        assert!(!serde_json::to_string(&contents).unwrap().contains("secret"));

        let (same, _) = targets::update(&db, Actor::Admin, created.id, &web(22, "old-secret"))
            .await
            .unwrap();
        let same = same.skip_audit();
        assert_eq!(changes(&db, &created, &same).await, Some(vec![]));

        let mut moved = web(2222, "new-secret");
        moved.group_id = Some(prod.id);
        let (moved, _) = targets::update(&db, Actor::Admin, created.id, &moved)
            .await
            .unwrap();
        let moved = moved.skip_audit();
        let fields = changes(&db, &created, &moved).await.unwrap();
        assert_eq!(
            paths(&fields),
            [
                "spec.group",
                "spec.options.ssh.auth.password",
                "spec.options.ssh.port"
            ]
        );
        assert!(!serde_json::to_string(&fields).unwrap().contains("secret"));
    }

    fn user(
        description: &str,
        policy: serde_json::Value,
        ranges: serde_json::Value,
    ) -> User::Model {
        User::Model {
            id: UserId(Uuid::nil()),
            username: "alice".into(),
            credential_policy: policy,
            description: description.into(),
            rate_limit_bytes_per_second: None,
            ldap_server_id: None,
            ldap_object_uuid: None,
            allowed_ip_ranges: ranges,
            provider: None,
        }
    }

    #[tokio::test]
    async fn a_user_update_is_told_by_its_changed_fields() {
        let db = db().await;
        let unset = user("", json!(null), json!(null));
        let empty = user("", json!({"ssh": []}), json!(null));
        assert_eq!(changes(&db, &unset, &empty).await, Some(vec![]));

        let edited = user(
            "ops lead",
            json!({"ssh": ["publickey"]}),
            json!(["10.0.0.0/8"]),
        );
        let fields = changes(&db, &unset, &edited).await.unwrap();
        assert_eq!(
            paths(&fields),
            [
                "spec.allowed_ip_ranges",
                "spec.credential_policy.ssh",
                "spec.description"
            ]
        );
    }

    #[tokio::test]
    async fn an_adoption_is_told_even_if_no_field_changed() {
        let db = db().await;
        let role = Role::Model {
            id: RoleId(Uuid::nil()),
            name: "dba".into(),
            description: String::new(),
            is_default: false,
            provider: None,
        };
        let update = || Unaudited::updated(role.clone(), role.clone());

        let (_, entry) = update().deferred(&db).await;
        assert!(entry.0.is_none());

        let (_, entry) = update().adopted().deferred(&db).await;
        let adoption = entry.0.unwrap();
        assert_eq!(adoption.action, Action::Adopt);
        assert_eq!(adoption.fields, Some(vec![]));
    }

    #[test]
    fn columns_hide_credentials_and_leave_out_the_name() {
        let server = |name: &str, host: &str, password: &str| {
            let row = |password: &str| json!({"id": 1, "name": name, "host": host, "bind_password": password});
            columns(&row(password), &row("")).unwrap().named(name)
        };
        let before = server("ad", "a", "old-secret");
        assert_eq!(before.changes_to(&server("ad", "a", "old-secret")), []);

        let fields: Vec<_> = before
            .changes_to(&server("ad2", "b", "new-secret"))
            .iter()
            .map(PlannedField::from)
            .collect();
        let summary: Vec<_> = fields
            .iter()
            .map(|field| (field.path.as_str(), field.credential))
            .collect();
        assert_eq!(
            summary,
            [
                ("name", false),
                ("spec.bind_password", true),
                ("spec.host", false)
            ]
        );
        assert!(!serde_json::to_string(&fields).unwrap().contains("secret"));
    }

    #[tokio::test]
    async fn a_row_that_cannot_be_read_as_a_spec_still_updates() {
        let db = db().await;
        let created = targets::create(&db, Actor::Admin, &web(22, "secret"))
            .await
            .unwrap()
            .skip_audit();
        Target::Entity::update_many()
            .col_expr(Target::Column::Options, Expr::value(json!({"ssh": 1})))
            .filter(Target::Column::Id.eq(created.id))
            .exec(&db)
            .await
            .unwrap();

        let (updated, _) = targets::update(&db, Actor::Admin, created.id, &web(22, "secret"))
            .await
            .unwrap();
        let Write::Updated { before, after } = &updated.0 else {
            panic!("an update returns both rows");
        };
        assert_eq!(changes(&db, before, after).await, None);
    }
}

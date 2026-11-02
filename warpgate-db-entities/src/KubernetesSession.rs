use sea_orm::entity::prelude::*;
use sea_orm::sea_query::{OnConflict, Query};
use sea_orm::{Condition, Set};
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::{TargetSessionId, UserSessionId, WarpgateError};

/// Cluster-wide claim on a Kubernetes correlation key: the user session that
/// serves every request of one `kubectl` command, whichever node receives it.
///
/// Denial and abandonment are not stored here. They are read from the parent
/// `user_sessions` row: ended, or deleted while provisional.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "kubernetes_sessions")]
pub struct Model {
    #[sea_orm(
        primary_key,
        auto_increment = false,
        column_type = "String(StringLen::N(255))"
    )]
    pub key: String,
    pub user_session_id: UserSessionId,
    pub created: OffsetDateTime,
    /// `None` while admission is pending.
    pub target_session_id: Option<TargetSessionId>,
}

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Relation {
    UserSession,
}

impl RelationTrait for Relation {
    fn def(&self) -> RelationDef {
        match self {
            // No FK: a deleted parent is how waiting nodes detect an abandoned claim.
            Self::UserSession => Entity::belongs_to(super::UserSession::Entity)
                .from(Column::UserSessionId)
                .to(super::UserSession::Column::Id)
                .into(),
        }
    }
}

impl Related<super::UserSession::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::UserSession.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

/// Ids, not names, so a rename doesn't split a live session.
pub fn key(user_id: Uuid, target_id: Uuid, ip: Option<&str>, ticket_id: Option<Uuid>) -> String {
    format!(
        "{user_id}|{target_id}|{}|{}",
        ip.unwrap_or_default(),
        ticket_id.map(|id| id.to_string()).unwrap_or_default(),
    )
}

pub async fn find_with_parent(
    db: &DatabaseConnection,
    key: &str,
) -> Result<Option<(Model, Option<super::UserSession::Model>)>, WarpgateError> {
    Ok(Entity::find_by_id(key)
        .find_also_related(super::UserSession::Entity)
        .one(db)
        .await?)
}

pub enum Claim {
    Won,
    Lost(Model),
}

/// `replacing` is a stale claim the caller has inspected. Its deletion is
/// scoped to that session id so a concurrent fresh claim survives.
pub async fn claim(
    db: &DatabaseConnection,
    key: &str,
    user_session_id: UserSessionId,
    created: OffsetDateTime,
    replacing: Option<UserSessionId>,
) -> Result<Claim, WarpgateError> {
    if let Some(stale) = replacing {
        release(db, key, stale).await?;
    }

    insert_unless_claimed(ActiveModel {
        key: Set(key.to_owned()),
        user_session_id: Set(user_session_id),
        created: Set(created),
        target_session_id: Set(None),
    })
    .do_nothing()
    .exec_without_returning(db)
    .await?;

    let row = Entity::find_by_id(key).one(db).await?.ok_or_else(|| {
        WarpgateError::InconsistentState("Kubernetes session claim not found".into())
    })?;
    if row.user_session_id == user_session_id {
        Ok(Claim::Won)
    } else {
        Ok(Claim::Lost(row))
    }
}

/// `OnConflict::do_nothing()` renders invalid `ON DUPLICATE KEY IGNORE` on
/// MySQL. A self-assignment is the portable no-op.
fn insert_unless_claimed(model: ActiveModel) -> sea_orm::Insert<ActiveModel> {
    Entity::insert(model).on_conflict(
        OnConflict::column(Column::Key)
            .update_column(Column::Key)
            .to_owned(),
    )
}

/// No-op if the claim has been replaced since.
pub async fn admit(
    db: &DatabaseConnection,
    key: &str,
    user_session_id: UserSessionId,
    target_session_id: TargetSessionId,
) -> Result<(), WarpgateError> {
    Entity::update_many()
        .col_expr(Column::TargetSessionId, Expr::value(target_session_id))
        .filter(Column::Key.eq(key))
        .filter(Column::UserSessionId.eq(user_session_id))
        .exec(db)
        .await?;
    Ok(())
}

async fn release(
    db: &DatabaseConnection,
    key: &str,
    user_session_id: UserSessionId,
) -> Result<(), WarpgateError> {
    Entity::delete_many()
        .filter(Column::Key.eq(key))
        .filter(Column::UserSessionId.eq(user_session_id))
        .exec(db)
        .await?;
    Ok(())
}

pub async fn sweep(db: &DatabaseConnection, cutoff: OffsetDateTime) -> Result<u64, WarpgateError> {
    Ok(Entity::delete_many()
        .filter(
            Condition::any().add(Column::Created.lt(cutoff)).add(
                Column::UserSessionId.not_in_subquery(
                    Query::select()
                        .column(super::UserSession::Column::Id)
                        .from(super::UserSession::Entity)
                        .and_where(Expr::col(super::UserSession::Column::Ended).is_null())
                        .to_owned(),
                ),
            ),
        )
        .exec(db)
        .await?
        .rows_affected)
}

#[cfg(test)]
mod tests {
    use sea_orm::{DbBackend, QueryTrait};

    use super::*;

    #[test]
    fn the_claim_conflict_clause_renders_valid_sql_on_every_backend() {
        let model = ActiveModel {
            key: Set("k".into()),
            user_session_id: Set(UserSessionId(Uuid::new_v4())),
            created: Set(OffsetDateTime::now_utc()),
            target_session_id: Set(None),
        };

        for backend in [DbBackend::MySql, DbBackend::Postgres, DbBackend::Sqlite] {
            let sql = insert_unless_claimed(model.clone())
                .build(backend)
                .to_string();
            assert!(
                !sql.contains("ON DUPLICATE KEY IGNORE"),
                "{backend:?} rendered sea-query's invalid MySQL construct: {sql}",
            );
            let has_valid_conflict_action =
                sql.contains("ON DUPLICATE KEY UPDATE") || sql.contains("ON CONFLICT");
            assert!(has_valid_conflict_action, "{backend:?}: {sql}");
        }
    }

    #[test]
    fn keys_separate_tickets_and_unknown_ips() {
        let (user, target, ticket) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let plain = key(user, target, Some("10.0.0.1"), None);
        assert_ne!(plain, key(user, target, Some("10.0.0.1"), Some(ticket)));
        assert_ne!(plain, key(user, target, None, None));
        assert_eq!(plain, key(user, target, Some("10.0.0.1"), None));
    }
}

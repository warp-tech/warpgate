use sea_orm::entity::prelude::*;
use sea_orm::sea_query::Expr;
use sea_orm::{DatabaseTransaction, QuerySelect, TransactionTrait};
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::{NodeId, UserSessionId, WarpgateError};

use crate::{HttpSession, TargetSession};

/// A top level session object, one per protocol login.
/// This is what WarpgateServerHandle corresponds to
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "user_sessions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: UserSessionId,
    pub username: Option<String>,
    pub user_id: Option<Uuid>,
    pub remote_address: String,
    pub started: OffsetDateTime,
    pub ended: Option<OffsetDateTime>,
    pub protocol: String,
    pub node_id: Option<NodeId>,
    /// The node where this session's `AuthState` exists in runtime,
    /// all login requests are cluster-forwarded until login is completed
    pub auth_state_node_id: Option<NodeId>,
}

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Relation {
    TargetSessions,
}

impl RelationTrait for Relation {
    fn def(&self) -> RelationDef {
        match self {
            Self::TargetSessions => Entity::has_many(super::TargetSession::Entity)
                .from(Column::Id)
                .to(super::TargetSession::Column::UserSessionId)
                .into(),
        }
    }
}

impl Related<super::TargetSession::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::TargetSessions.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

/// Audit events produced by a committed user-session termination.
#[must_use]
pub struct EndedTargetSessions {
    children: Vec<TargetSession::Model>,
    user_id: Option<Uuid>,
    username: Option<String>,
}

impl EndedTargetSessions {
    const fn none() -> Self {
        Self {
            children: vec![],
            user_id: None,
            username: None,
        }
    }

    pub fn emit(self) {
        let (Some(user_id), Some(username)) = (self.user_id, self.username) else {
            return;
        };
        for child in &self.children {
            TargetSession::emit_ended(child, user_id, &username);
        }
    }
}

/// Locks a user-session row until `transaction` completes.
///
/// The no-op update is deliberate: PostgreSQL/MySQL take a row lock, while
/// SQLite takes the transaction's write lock. A plain `FOR UPDATE` would be a
/// no-op on SQLite and would not serialize session backing and target changes.
pub async fn lock_for_update(
    transaction: &DatabaseTransaction,
    id: UserSessionId,
) -> Result<Option<Model>, WarpgateError> {
    Entity::update_many()
        .col_expr(Column::Started, Expr::col(Column::Started).into())
        .filter(Column::Id.eq(id))
        .exec(transaction)
        .await?;
    Ok(Entity::find_by_id(id).one(transaction).await?)
}

/// Ends a locked user session and all of its target sessions in one
/// transaction. The returned audit events must only be emitted after commit.
pub async fn mark_ended_in_transaction(
    transaction: &DatabaseTransaction,
    id: UserSessionId,
) -> Result<EndedTargetSessions, WarpgateError> {
    let Some(parent) = lock_for_update(transaction, id).await? else {
        return Ok(EndedTargetSessions::none());
    };
    if parent.ended.is_some() {
        return Ok(EndedTargetSessions::none());
    }

    Entity::update_many()
        .col_expr(Column::Ended, Expr::value(OffsetDateTime::now_utc()))
        .filter(Column::Id.eq(id))
        .filter(Column::Ended.is_null())
        .exec(transaction)
        .await?;

    let children = TargetSession::Entity::find()
        .filter(TargetSession::Column::UserSessionId.eq(id))
        .filter(TargetSession::Column::Ended.is_null())
        .all(transaction)
        .await?;
    TargetSession::Entity::update_many()
        .col_expr(
            TargetSession::Column::Ended,
            Expr::value(OffsetDateTime::now_utc()),
        )
        .filter(TargetSession::Column::UserSessionId.eq(id))
        .filter(TargetSession::Column::Ended.is_null())
        .exec(transaction)
        .await?;

    Ok(EndedTargetSessions {
        children,
        user_id: parent.user_id,
        username: parent.username,
    })
}

pub async fn mark_ended_including_target_sessions(
    db: &DatabaseConnection,
    id: UserSessionId,
) -> Result<(), WarpgateError> {
    let transaction = db.begin().await?;
    let ended = mark_ended_in_transaction(&transaction, id).await?;
    transaction.commit().await?;
    ended.emit();
    Ok(())
}

/// The definite way to close a session
pub async fn revoke(db: &DatabaseConnection, id: UserSessionId) -> Result<(), WarpgateError> {
    let transaction = db.begin().await?;
    let ended = mark_ended_in_transaction(&transaction, id).await?;
    HttpSession::Entity::delete_many()
        .filter(HttpSession::Column::UserSessionId.eq(id))
        .exec(&transaction)
        .await?;
    transaction.commit().await?;
    ended.emit();
    Ok(())
}

pub async fn revoke_all(db: &DatabaseConnection) -> Result<(), WarpgateError> {
    let open: Vec<Uuid> = Entity::find()
        .filter(Column::Ended.is_null())
        .select_only()
        .column(Column::Id)
        .into_tuple()
        .all(db)
        .await?;
    for id in open {
        revoke(db, UserSessionId(id)).await?;
    }
    Ok(())
}


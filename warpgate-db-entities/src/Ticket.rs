use sea_orm::entity::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::helpers::hash::hash_secret;
use warpgate_common::{Secret, WarpgateError};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "tickets")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub secret_hash: String,
    pub user_id: Uuid,
    #[sea_orm(column_type = "Text")]
    pub description: String,
    pub target_id: Uuid,
    pub uses_left: Option<i16>,
    pub self_service: bool,
    pub expiry: Option<OffsetDateTime>,
    pub created: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::TargetSession::Entity")]
    TargetSessions,
    #[sea_orm(
        belongs_to = "super::User::Entity",
        from = "Column::UserId",
        to = "super::User::Column::Id"
    )]
    User,
    #[sea_orm(
        belongs_to = "super::Target::Entity",
        from = "Column::TargetId",
        to = "super::Target::Column::Id"
    )]
    Target,
}

impl Related<super::User::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}

impl Related<super::Target::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Target.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

/// Atomic use spend
///
/// WarpgateError::InvalidTicket = no uses left
pub async fn spend_use(db: &DatabaseConnection, ticket_id: Uuid) -> Result<(), WarpgateError> {
    let ticket = Entity::find_by_id(ticket_id).one(db).await?;
    let Some(ticket) = ticket else {
        return Err(WarpgateError::InvalidTicket(ticket_id));
    };
    if ticket.uses_left.is_none() {
        return Ok(());
    }
    let spent = Entity::update_many()
        .col_expr(Column::UsesLeft, Expr::col(Column::UsesLeft).sub(1))
        .filter(Column::Id.eq(ticket_id))
        .filter(Column::UsesLeft.gt(0))
        .exec(db)
        .await?;
    if spent.rows_affected == 0 {
        return Err(WarpgateError::InvalidTicket(ticket_id));
    }
    Ok(())
}

pub async fn refund_use(db: &DatabaseConnection, ticket_id: Uuid) -> Result<(), WarpgateError> {
    Entity::update_many()
        .col_expr(Column::UsesLeft, Expr::col(Column::UsesLeft).add(1))
        .filter(Column::Id.eq(ticket_id))
        .filter(Column::UsesLeft.is_not_null())
        .exec(db)
        .await?;
    Ok(())
}

pub async fn for_secret(
    db: &DatabaseConnection,
    secret: &Secret<String>,
) -> Result<Option<Uuid>, WarpgateError> {
    Ok(Entity::find()
        .filter(Column::SecretHash.eq(hash_secret(secret.expose_secret())))
        .one(db)
        .await?
        .map(|ticket| ticket.id))
}

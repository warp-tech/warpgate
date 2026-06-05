use poem_openapi::Object;
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "user_roles")]
#[oai(rename = "UserRoleAssignment")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i32,
    pub user_id: Uuid,
    pub role_id: Uuid,
    /// When this role assignment was granted
    pub granted_at: Option<OffsetDateTime>,
    /// When this role assignment expires (null = never)
    pub expires_at: Option<OffsetDateTime>,
    /// When this role assignment was revoked (null = not revoked)
    pub revoked_at: Option<OffsetDateTime>,
}

impl Model {
    pub fn expired(&self) -> bool {
        self.expires_at
            .is_some_and(|expires_at| expires_at <= OffsetDateTime::now_utc())
    }
    pub fn active(&self) -> bool {
        self.revoked_at.is_none() && !self.expired()
    }
}

impl Entity {
    pub fn find_active() -> Select<Self> {
        Self::find().filter(
            Column::ExpiresAt
                .is_null()
                .or(Column::ExpiresAt.gt(OffsetDateTime::now_utc()))
                .and(Column::RevokedAt.is_null()),
        )
    }

    pub async fn idempotent_grant(
        db: &DatabaseConnection,
        user_id: Uuid,
        role_id: Uuid,
        expires_at: Option<OffsetDateTime>,
    ) -> Result<Model, DbErr> {
        let existing = Self::find()
            .filter(Column::UserId.eq(user_id))
            .filter(Column::RoleId.eq(role_id))
            .one(db)
            .await?;

        let now = OffsetDateTime::now_utc();

        Ok(if let Some(existing) = existing {
            if existing.active() {
                return Ok(existing);
            }
            // Re-activate a revoked/expired assignment
            let mut model: ActiveModel = existing.into();
            model.granted_at = Set(Some(now));
            model.expires_at = Set(expires_at);
            model.revoked_at = Set(None);
            model.update(db).await?
        } else {
            let values = ActiveModel {
                user_id: Set(user_id),
                role_id: Set(role_id),
                granted_at: Set(Some(now)),
                expires_at: Set(expires_at),
                revoked_at: Set(None),
                ..Default::default()
            };
            values.insert(db).await?
        })
    }
}

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Relation {
    User,
    Role,
}

impl RelationTrait for Relation {
    fn def(&self) -> RelationDef {
        match self {
            Self::User => Entity::belongs_to(super::User::Entity)
                .from(Column::UserId)
                .to(super::User::Column::Id)
                .into(),
            Self::Role => Entity::belongs_to(super::Role::Entity)
                .from(Column::RoleId)
                .to(super::Role::Column::Id)
                .into(),
        }
    }
}

impl ActiveModelBehavior for ActiveModel {}

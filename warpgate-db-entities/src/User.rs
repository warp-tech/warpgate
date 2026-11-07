use std::str::FromStr;

use ipnet::IpNet;
use poem_openapi::Object;
use sea_orm::entity::prelude::*;
use sea_orm::sea_query::{Func, IntoCondition};
use sea_orm::{ActiveValue, Set};
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::{User, UserDetails, WarpgateError};

use crate::{
    CertificateCredential, OtpCredential, PasswordCredential, PublicKeyCredential, Role,
    SsoCredential,
};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "users")]
#[oai(rename = "User")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    #[sea_orm(unique)]
    pub username: String,
    pub credential_policy: serde_json::Value,
    #[sea_orm(column_type = "Text")]
    pub description: String,
    pub rate_limit_bytes_per_second: Option<i64>,
    pub ldap_server_id: Option<Uuid>,
    #[sea_orm(column_type = "Text", nullable)]
    pub ldap_object_uuid: Option<Uuid>,
    #[sea_orm(column_type = "Text", nullable)]
    pub allowed_ip_ranges: serde_json::Value,
    /// A disabled account can't log in anywhere (SCIM `active`).
    pub enabled: bool,
    /// The identity provider's own id for this user (SCIM `externalId`).
    pub scim_external_id: Option<String>,
    /// The SCIM attributes Warpgate has no column for (name, emails, …), kept
    /// verbatim so the provisioning client reads back what it wrote.
    #[sea_orm(column_type = "Text", nullable)]
    pub scim_attributes: Option<String>,
    /// Stamped by `before_save`; `None` only for rows older than the column.
    pub created_at: Option<OffsetDateTime>,
    pub updated_at: Option<OffsetDateTime>,
}

impl Related<super::Role::Entity> for Entity {
    fn to() -> RelationDef {
        super::UserRoleAssignment::Relation::Role.def()
    }

    fn via() -> Option<RelationDef> {
        Some(
            super::UserRoleAssignment::Relation::User
                .def()
                .rev()
                .on_condition(|_user, assignment| {
                    super::UserRoleAssignment::Entity::active_condition(assignment)
                }),
        )
    }
}

impl Related<super::AdminRole::Entity> for Entity {
    fn to() -> RelationDef {
        super::UserAdminRoleAssignment::Relation::AdminRole.def()
    }

    fn via() -> Option<RelationDef> {
        Some(super::UserAdminRoleAssignment::Relation::User.def().rev())
    }
}

impl Related<super::OtpCredential::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::OtpCredentials.def()
    }
}

impl Related<super::PasswordCredential::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PasswordCredentials.def()
    }
}

impl Related<super::PublicKeyCredential::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PublicKeyCredentials.def()
    }
}

impl Related<super::CertificateCredential::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::CertificateCredentials.def()
    }
}

impl Related<super::SsoCredential::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::SsoCredentials.def()
    }
}

impl Related<super::ApiToken::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ApiTokens.def()
    }
}

#[derive(Copy, Clone, Debug, EnumIter)]
#[allow(clippy::enum_variant_names)]
pub enum Relation {
    OtpCredentials,
    PasswordCredentials,
    PublicKeyCredentials,
    CertificateCredentials,
    SsoCredentials,
    ApiTokens,
    AdminRoles,
}

impl RelationTrait for Relation {
    fn def(&self) -> RelationDef {
        match self {
            Self::OtpCredentials => Entity::has_many(super::OtpCredential::Entity)
                .from(Column::Id)
                .to(super::OtpCredential::Column::UserId)
                .into(),
            Self::PasswordCredentials => Entity::has_many(super::PasswordCredential::Entity)
                .from(Column::Id)
                .to(super::PasswordCredential::Column::UserId)
                .into(),
            Self::PublicKeyCredentials => Entity::has_many(super::PublicKeyCredential::Entity)
                .from(Column::Id)
                .to(super::PublicKeyCredential::Column::UserId)
                .into(),
            Self::CertificateCredentials => Entity::has_many(super::CertificateCredential::Entity)
                .from(Column::Id)
                .to(super::CertificateCredential::Column::UserId)
                .into(),
            Self::SsoCredentials => Entity::has_many(super::SsoCredential::Entity)
                .from(Column::Id)
                .to(super::SsoCredential::Column::UserId)
                .into(),
            Self::ApiTokens => Entity::has_many(super::ApiToken::Entity)
                .from(Column::Id)
                .to(super::ApiToken::Column::UserId)
                .into(),
            Self::AdminRoles => Entity::has_many(super::UserAdminRoleAssignment::Entity)
                .from(Column::Id)
                .to(super::UserAdminRoleAssignment::Column::UserId)
                .into(),
        }
    }
}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {
    /// Stamps the timestamps here rather than at each writer, so no caller can
    /// forget. An explicitly `Set` value (a database copy) is kept.
    async fn before_save<C>(mut self, _db: &C, insert: bool) -> Result<Self, DbErr>
    where
        C: ConnectionTrait,
    {
        stamp_timestamps(&mut self.created_at, &mut self.updated_at, insert);
        Ok(self)
    }
}

/// Shared by the user and role entities.
pub fn stamp_timestamps(
    created_at: &mut ActiveValue<Option<OffsetDateTime>>,
    updated_at: &mut ActiveValue<Option<OffsetDateTime>>,
    insert: bool,
) {
    let now = OffsetDateTime::now_utc();
    if insert && !matches!(created_at, ActiveValue::Set(Some(_))) {
        *created_at = Set(Some(now));
    }
    if !matches!(updated_at, ActiveValue::Set(Some(_))) {
        *updated_at = Set(Some(now));
    }
}

impl Entity {
    pub fn username_eq_ci(username: &str) -> impl IntoCondition {
        Expr::expr(Func::lower(Expr::col(Column::Username))).eq(username.to_lowercase())
    }
}

/// Parse a user's allowed source ranges.
///
/// The column is read on every login (through `list_users`), so one entry that does not parse
/// fails authentication for everyone. Every writer has to validate through this before storing.
pub fn parse_allowed_ip_ranges(ranges: Vec<String>) -> Result<Vec<IpNet>, WarpgateError> {
    ranges
        .into_iter()
        .map(|x| IpNet::from_str(&x).map_err(|_| WarpgateError::InvalidNetworkAddress(x)))
        .collect()
}

impl TryFrom<Model> for User {
    type Error = WarpgateError;

    fn try_from(model: Model) -> Result<Self, WarpgateError> {
        let allowed_ip_ranges = if model.allowed_ip_ranges.is_null() {
            None
        } else {
            let ranges: Vec<String> = serde_json::from_value(model.allowed_ip_ranges)?;
            Some(parse_allowed_ip_ranges(ranges)?)
        };

        Ok(Self {
            id: model.id,
            username: model.username,
            credential_policy: serde_json::from_value(model.credential_policy)?,
            description: model.description,
            rate_limit_bytes_per_second: model.rate_limit_bytes_per_second,
            ldap_server_id: model.ldap_server_id,
            allowed_ip_ranges: allowed_ip_ranges
                .map(|ranges| ranges.into_iter().map(Into::into).collect()),
            enabled: model.enabled,
            scim_external_id: model.scim_external_id,
            created_at: model.created_at,
            updated_at: model.updated_at,
        })
    }
}

impl Model {
    pub async fn load_details(self, db: &DatabaseConnection) -> Result<UserDetails, WarpgateError> {
        let roles: Vec<String> = self
            .find_related(Role::Entity)
            .all(db)
            .await?
            .into_iter()
            .map(Into::<warpgate_common::Role>::into)
            .map(|x| x.name)
            .collect();

        let mut credentials = vec![];
        credentials.extend(
            self.find_related(OtpCredential::Entity)
                .all(db)
                .await?
                .into_iter()
                .map(Into::into),
        );
        credentials.extend(
            self.find_related(PasswordCredential::Entity)
                .all(db)
                .await?
                .into_iter()
                .map(Into::into),
        );
        credentials.extend(
            self.find_related(SsoCredential::Entity)
                .all(db)
                .await?
                .into_iter()
                .map(Into::into),
        );
        credentials.extend(
            self.find_related(PublicKeyCredential::Entity)
                .all(db)
                .await?
                .into_iter()
                .map(Into::into),
        );
        credentials.extend(
            self.find_related(CertificateCredential::Entity)
                .all(db)
                .await?
                .into_iter()
                .map(Into::into),
        );

        Ok(warpgate_common::UserDetails {
            inner: self.try_into()?,
            roles,
            credentials,
        })
    }

    pub async fn require_otp_in_policy(self, db: &DatabaseConnection) -> Result<(), WarpgateError> {
        let details = self.load_details(db).await?;
        let credential_policy = details
            .inner
            .credential_policy
            .unwrap_or_default()
            .upgrade_to_otp(&details.credentials);
        ActiveModel {
            id: Set(details.inner.id),
            credential_policy: Set(serde_json::to_value(Some(credential_policy))?),
            ..Default::default()
        }
        .update(db)
        .await?;
        Ok(())
    }
}

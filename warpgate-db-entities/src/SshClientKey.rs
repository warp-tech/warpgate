use sea_orm::entity::prelude::*;
use sea_orm::{ColumnTrait, QueryFilter, QueryOrder};
use uuid::Uuid;

/// An SSH private key Warpgate uses to authenticate against targets.
/// The secret key is intentionally not serializable — API responses use
/// their own DTO exposing only the public part.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "ssh_client_keys")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub label: String,
    /// PKCS#8 PEM
    #[sea_orm(column_type = "Text")]
    pub secret_key: String,
    /// OpenSSH `<algo> <base64>` form, used for display and de-duplication
    #[sea_orm(column_type = "Text")]
    pub public_key: String,
    pub is_default: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Entity {
    /// All keys with the default ones first, then by label — used for display.
    pub fn find_ordered() -> Select<Self> {
        Self::find()
            .order_by_desc(Column::IsDefault)
            .order_by_asc(Column::Label)
    }

    /// The default-flagged keys, ordered by label — offered to a target that
    /// authenticates without a specific key selected.
    pub fn find_default() -> Select<Self> {
        Self::find()
            .filter(Column::IsDefault.eq(true))
            .order_by_asc(Column::Label)
    }
}

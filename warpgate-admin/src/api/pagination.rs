use poem_openapi::Object;
use poem_openapi::types::{ParseFromJSON, ToJSON};
use sea_orm::{DatabaseConnection, DbErr, EntityTrait, PaginatorTrait, QueryTrait, Select};

/// Page size when the client doesn't ask for one, and the most it may ask for.
pub const DEFAULT_PAGE_SIZE: u64 = 100;
pub const MAX_PAGE_SIZE: u64 = 500;

#[derive(Object)]
pub struct PaginatedResponse<T: ParseFromJSON + ToJSON + Send + Sync> {
    items: Vec<T>,
    offset: u64,
    total: u64,
}

impl<T: ParseFromJSON + ToJSON + Send + Sync> PaginatedResponse<T> {
    pub const fn from_parts(items: Vec<T>, offset: u64, total: u64) -> Self {
        Self {
            items,
            offset,
            total,
        }
    }
}

/// Number of rows `select` matches, for [`PaginatedResponse::total`]. Its
/// ordering is dropped first, as sorting every matching row only to count them
/// is wasted work with a large number of rows. It doesn't depend on the page
/// query, so callers run the two concurrently.
pub async fn count_unordered<E>(
    mut select: Select<E>,
    db: &DatabaseConnection,
) -> Result<u64, DbErr>
where
    E: EntityTrait,
    E::Model: Sync,
{
    select.query().clear_order_by();
    select.count(db).await
}

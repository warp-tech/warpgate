use poem_openapi::Object;
use poem_openapi::types::{ParseFromJSON, ToJSON};

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

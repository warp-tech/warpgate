use poem_openapi::types::{ParseFromJSON, ToJSON};
use poem_openapi::Object;
use sea_orm::{ConnectionTrait, EntityTrait, FromQueryResult, PaginatorTrait, QuerySelect, Select};
use warpgate_common::WarpgateError;

#[derive(Object)]
pub struct PaginatedResponse<T: ParseFromJSON + ToJSON + Send + Sync> {
    items: Vec<T>,
    offset: u64,
    total: u64,
}

pub struct PaginationParams {
    pub offset: Option<u64>,
    pub limit: Option<u64>,
}

impl<T: ParseFromJSON + ToJSON + Send + Sync> PaginatedResponse<T> {
    pub async fn new<E, M, C, P>(
        query: Select<E>,
        params: PaginationParams,
        db: &'_ C,
        postprocess: P,
    ) -> Result<PaginatedResponse<T>, WarpgateError>
    where
        E: EntityTrait<Model = M>,
        C: ConnectionTrait,
        M: FromQueryResult + Sized + Send + Sync + 'static,
        P: FnMut(E::Model) -> T,
    {
        let offset = params.offset.unwrap_or(0);
        let limit = params.limit.unwrap_or(100);

        let paginator = query.clone().paginate(db, limit);

        let total = paginator.num_items().await?;

        let query = query.offset(offset).limit(limit);

        let items = query.all(db).await?;

        let items = items.into_iter().map(postprocess).collect::<Vec<_>>();
        Ok(PaginatedResponse {
            items,
            offset,
            total,
        })
    }
}

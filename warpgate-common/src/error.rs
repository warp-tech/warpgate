use std::error::Error;

use poem::error::ResponseError;
use uuid::Uuid;

#[derive(thiserror::Error, Debug)]
pub enum WarpgateError {
    #[error("database error: {0}")]
    DatabaseError(#[from] sea_orm::DbErr),
    #[error("ticket not found: {0}")]
    InvalidTicket(Uuid),
    #[error(transparent)]
    Other(Box<dyn Error + Send + Sync>),
}

impl ResponseError for WarpgateError {
    fn status(&self) -> poem::http::StatusCode {
        poem::http::StatusCode::INTERNAL_SERVER_ERROR
    }
}

impl WarpgateError {
    pub fn other<E: Error + Send + Sync + 'static>(err: E) -> Self {
        Self::Other(Box::new(err))
    }
}

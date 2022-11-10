use std::sync::Arc;

use poem::web::Data;
use poem::Request;
use poem_openapi::param::Path;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, ModelTrait, QueryFilter};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::api::tokens_list::get_user;

pub struct Api;

#[derive(ApiResponse)]
enum DeleteTokenResponse {
    #[oai(status = 204)]
    Deleted,

    #[oai(status = 404)]
    NotFound,
}

#[OpenApi]
impl Api {
    #[oai(path = "/tokens/:id", method = "delete", operation_id = "delete_token")]
    async fn api_delete_token(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        req: &Request,
        id: Path<Uuid>,
    ) -> poem::Result<DeleteTokenResponse> {
        use warpgate_db_entities::Token;
        let db = db.lock().await;

        let user = get_user(&*db, req).await?;
        let token = Token::Entity::find()
            .filter(Token::Column::UserId.eq(user.id))
            .filter(Token::Column::Id.eq(id.0))
            .one(&*db)
            .await
            .map_err(poem::error::InternalServerError)?;

        match token {
            Some(token) => {
                token
                    .delete(&*db)
                    .await
                    .map_err(poem::error::InternalServerError)?;
                Ok(DeleteTokenResponse::Deleted)
            }
            None => Ok(DeleteTokenResponse::NotFound),
        }
    }
}

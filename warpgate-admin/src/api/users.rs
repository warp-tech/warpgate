use std::sync::Arc;

use poem::web::Data;
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, ModelTrait, QueryFilter,
    QueryOrder, Set,
};
use tokio::sync::Mutex;
use uuid::Uuid;
use warpgate_common::{
    Role as RoleConfig, User as UserConfig, UserAuthCredential, UserRequireCredentialsPolicy,
    WarpgateError,
};
use warpgate_db_entities::{Role, User, UserRoleAssignment};

#[derive(Object)]
struct UserDataRequest {
    username: String,
    credentials: Vec<UserAuthCredential>,
    credential_policy: Option<UserRequireCredentialsPolicy>,
}

#[derive(ApiResponse)]
enum GetUsersResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<UserConfig>>),
}
#[derive(ApiResponse)]
enum CreateUserResponse {
    #[oai(status = 201)]
    Created(Json<UserConfig>),

    #[oai(status = 400)]
    BadRequest(Json<String>),
}

pub struct ListApi;

#[OpenApi]
impl ListApi {
    #[oai(path = "/users", method = "get", operation_id = "get_users")]
    async fn api_get_all_users(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
    ) -> poem::Result<GetUsersResponse> {
        let db = db.lock().await;

        let users = User::Entity::find()
            .order_by_asc(User::Column::Username)
            .all(&*db)
            .await
            .map_err(WarpgateError::from)?;

        let users: Result<Vec<UserConfig>, _> = users.into_iter().map(|t| t.try_into()).collect();
        let users = users.map_err(WarpgateError::from)?;

        Ok(GetUsersResponse::Ok(Json(users)))
    }

    #[oai(path = "/users", method = "post", operation_id = "create_user")]
    async fn api_create_user(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        body: Json<UserDataRequest>,
    ) -> poem::Result<CreateUserResponse> {
        if body.username.is_empty() {
            return Ok(CreateUserResponse::BadRequest(Json("name".into())));
        }

        let db = db.lock().await;

        let values = User::ActiveModel {
            id: Set(Uuid::new_v4()),
            username: Set(body.username.clone()),
            credentials: Set(
                serde_json::to_value(body.credentials.clone()).map_err(WarpgateError::from)?
            ),
            credential_policy: Set(serde_json::to_value(body.credential_policy.clone())
                .map_err(WarpgateError::from)?),
        };

        let user = values.insert(&*db).await.map_err(WarpgateError::from)?;

        Ok(CreateUserResponse::Created(Json(
            user.try_into().map_err(WarpgateError::from)?,
        )))
    }
}

#[derive(ApiResponse)]
enum GetUserResponse {
    #[oai(status = 200)]
    Ok(Json<UserConfig>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum UpdateUserResponse {
    #[oai(status = 200)]
    Ok(Json<UserConfig>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DeleteUserResponse {
    #[oai(status = 204)]
    Deleted,

    #[oai(status = 404)]
    NotFound,
}

pub struct DetailApi;

#[OpenApi]
impl DetailApi {
    #[oai(path = "/users/:id", method = "get", operation_id = "get_user")]
    async fn api_get_user(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
    ) -> poem::Result<GetUserResponse> {
        let db = db.lock().await;

        let Some(user) = User::Entity::find_by_id(id.0)
            .one(&*db)
            .await
            .map_err(poem::error::InternalServerError)? else {
                return Ok(GetUserResponse::NotFound);
            };

        Ok(GetUserResponse::Ok(Json(
            user.try_into().map_err(poem::error::InternalServerError)?,
        )))
    }

    #[oai(path = "/users/:id", method = "put", operation_id = "update_user")]
    async fn api_update_user(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        body: Json<UserDataRequest>,
        id: Path<Uuid>,
    ) -> poem::Result<UpdateUserResponse> {
        let db = db.lock().await;

        let Some(user) = User::Entity::find_by_id(id.0)
            .one(&*db)
            .await
            .map_err(poem::error::InternalServerError)? else {
            return Ok(UpdateUserResponse::NotFound);
        };

        let mut model: User::ActiveModel = user.into();
        model.username = Set(body.username.clone());
        model.credentials =
            Set(serde_json::to_value(body.credentials.clone()).map_err(WarpgateError::from)?);
        model.credential_policy =
            Set(serde_json::to_value(body.credential_policy.clone())
                .map_err(WarpgateError::from)?);
        let user = model
            .update(&*db)
            .await
            .map_err(poem::error::InternalServerError)?;

        Ok(UpdateUserResponse::Ok(Json(
            user.try_into().map_err(WarpgateError::from)?,
        )))
    }

    #[oai(path = "/users/:id", method = "delete", operation_id = "delete_user")]
    async fn api_delete_user(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
    ) -> poem::Result<DeleteUserResponse> {
        let db = db.lock().await;

        let Some(user) = User::Entity::find_by_id(id.0)
            .one(&*db)
            .await
            .map_err(poem::error::InternalServerError)? else {
                return Ok(DeleteUserResponse::NotFound);
            };

        user.delete(&*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        Ok(DeleteUserResponse::Deleted)
    }
}

#[derive(ApiResponse)]
enum GetUserRolesResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<RoleConfig>>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum AddUserRoleResponse {
    #[oai(status = 201)]
    Created,
    #[oai(status = 409)]
    AlreadyExists,
}

#[derive(ApiResponse)]
enum DeleteUserRoleResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 404)]
    NotFound,
}

pub struct RolesApi;

#[OpenApi]
impl RolesApi {
    #[oai(
        path = "/users/:id/roles",
        method = "get",
        operation_id = "get_user_roles"
    )]
    async fn api_get_user_roles(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
    ) -> poem::Result<GetUserRolesResponse> {
        let db = db.lock().await;

        let Some((_, roles)) = User::Entity::find_by_id(*id)
            .find_with_related(Role::Entity)
            .all(&*db)
            .await
            .map(|x| x.into_iter().next())
            .map_err(WarpgateError::from)? else {
            return Ok(GetUserRolesResponse::NotFound)
        };

        Ok(GetUserRolesResponse::Ok(Json(
            roles.into_iter().map(|x| x.into()).collect(),
        )))
    }

    #[oai(
        path = "/users/:id/roles/:role_id",
        method = "post",
        operation_id = "add_user_role"
    )]
    async fn api_add_user_role(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
    ) -> poem::Result<AddUserRoleResponse> {
        let db = db.lock().await;

        if !UserRoleAssignment::Entity::find()
            .filter(UserRoleAssignment::Column::UserId.eq(id.0.clone()))
            .filter(UserRoleAssignment::Column::RoleId.eq(role_id.0.clone()))
            .all(&*db)
            .await
            .map_err(WarpgateError::from)?
            .is_empty()
        {
            return Ok(AddUserRoleResponse::AlreadyExists);
        }

        let values = UserRoleAssignment::ActiveModel {
            user_id: Set(id.0),
            role_id: Set(role_id.0),
            ..Default::default()
        };

        values.insert(&*db).await.map_err(WarpgateError::from)?;

        Ok(AddUserRoleResponse::Created)
    }

    #[oai(
        path = "/users/:id/roles/:role_id",
        method = "delete",
        operation_id = "delete_user_role"
    )]
    async fn api_delete_user_role(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
    ) -> poem::Result<DeleteUserRoleResponse> {
        let db = db.lock().await;

        let Some(_user) = User::Entity::find_by_id(id.0)
            .one(&*db)
            .await
            .map_err(poem::error::InternalServerError)? else {
                return Ok(DeleteUserRoleResponse::NotFound);
            };

        let Some(_role) = Role::Entity::find_by_id(role_id.0)
            .one(&*db)
            .await
            .map_err(poem::error::InternalServerError)? else {
                return Ok(DeleteUserRoleResponse::NotFound);
            };

        let Some(model) = UserRoleAssignment::Entity::find()
            .filter(UserRoleAssignment::Column::UserId.eq(id.0))
            .filter(UserRoleAssignment::Column::RoleId.eq(role_id.0))
            .one(&*db)
            .await
            .map_err(WarpgateError::from)? else {
                return Ok(DeleteUserRoleResponse::NotFound);
            };

        model.delete(&*db).await.map_err(WarpgateError::from)?;

        Ok(DeleteUserRoleResponse::Deleted)
    }
}

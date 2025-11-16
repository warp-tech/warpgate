use std::sync::Arc;

use poem::web::Data;
use poem_openapi::param::{Path, Query};
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, ModelTrait, QueryFilter,
    QueryOrder, Set,
};
use tokio::sync::Mutex;
use uuid::Uuid;
use warpgate_common::{Secret, WarpgateError};
use warpgate_tls::TlsMode;
use warpgate_db_entities::LdapServer;

use super::AnySecurityScheme;

#[derive(Object)]
struct LdapServerResponse {
    id: Uuid,
    name: String,
    host: String,
    port: i32,
    bind_dn: String,
    user_filter: String,
    base_dns: Vec<String>,
    tls_mode: TlsMode,
    tls_verify: bool,
    enabled: bool,
    auto_link_sso_users: bool,
    description: String,
}

impl From<LdapServer::Model> for LdapServerResponse {
    fn from(model: LdapServer::Model) -> Self {
        let base_dns: Vec<String> = serde_json::from_value(model.base_dns).unwrap_or_default();
        Self {
            id: model.id,
            name: model.name,
            host: model.host,
            port: model.port,
            bind_dn: model.bind_dn,
            user_filter: model.user_filter,
            base_dns,
            tls_mode: TlsMode::from(model.tls_mode.as_str()),
            tls_verify: model.tls_verify,
            enabled: model.enabled,
            auto_link_sso_users: model.auto_link_sso_users,
            description: model.description,
        }
    }
}

#[derive(Object)]
struct CreateLdapServerRequest {
    name: String,
    host: String,
    #[oai(default = "default_port")]
    port: i32,
    bind_dn: String,
    bind_password: Secret<String>,
    #[oai(default = "default_user_filter")]
    user_filter: String,
    #[oai(default = "default_tls_mode")]
    tls_mode: TlsMode,
    #[oai(default = "default_tls_verify")]
    tls_verify: bool,
    #[oai(default = "default_enabled")]
    enabled: bool,
    #[oai(default = "default_auto_link_sso_users")]
    auto_link_sso_users: bool,
    description: Option<String>,
}

fn default_port() -> i32 {
    389
}

fn default_user_filter() -> String {
    "(objectClass=person)".to_string()
}

fn default_tls_mode() -> TlsMode {
    TlsMode::Preferred
}

fn default_tls_verify() -> bool {
    true
}

fn default_enabled() -> bool {
    true
}

fn default_auto_link_sso_users() -> bool {
    false
}

#[derive(Object)]
struct UpdateLdapServerRequest {
    name: String,
    host: String,
    port: i32,
    bind_dn: String,
    bind_password: Option<Secret<String>>,
    user_filter: String,
    tls_mode: TlsMode,
    tls_verify: bool,
    enabled: bool,
    auto_link_sso_users: bool,
    description: Option<String>,
}

#[derive(Object)]
struct TestLdapServerRequest {
    host: String,
    port: i32,
    bind_dn: String,
    bind_password: Secret<String>,
    tls_mode: TlsMode,
    tls_verify: bool,
}

#[derive(Object)]
struct TestLdapServerResponse {
    success: bool,
    message: String,
    base_dns: Option<Vec<String>>,
}

#[derive(Object)]
struct LdapUserResponse {
    username: String,
    email: Option<String>,
    display_name: Option<String>,
    dn: String,
}

impl From<warpgate_ldap::LdapUser> for LdapUserResponse {
    fn from(user: warpgate_ldap::LdapUser) -> Self {
        Self {
            username: user.username,
            email: user.email,
            display_name: user.display_name,
            dn: user.dn,
        }
    }
}

#[derive(ApiResponse)]
enum GetLdapServersResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<LdapServerResponse>>),
}

#[derive(ApiResponse)]
enum CreateLdapServerResponse {
    #[oai(status = 201)]
    Created(Json<LdapServerResponse>),

    #[oai(status = 409)]
    Conflict(Json<String>),

    #[oai(status = 400)]
    BadRequest(Json<String>),
}

#[derive(ApiResponse)]
#[allow(dead_code)]
enum TestLdapServerConnectionResponse {
    #[oai(status = 200)]
    Ok(Json<TestLdapServerResponse>),

    #[oai(status = 400)]
    BadRequest(Json<String>),
}

pub struct ListApi;

#[OpenApi]
impl ListApi {
    #[oai(path = "/ldap-servers", method = "get", operation_id = "get_ldap_servers")]
    async fn api_get_all_ldap_servers(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        search: Query<Option<String>>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetLdapServersResponse, WarpgateError> {
        let db = db.lock().await;

        let mut query = LdapServer::Entity::find().order_by_asc(LdapServer::Column::Name);

        if let Some(ref search) = *search {
            let search_pattern = format!("%{search}%");
            query = query.filter(LdapServer::Column::Name.like(search_pattern));
        }

        let servers = query.all(&*db).await.map_err(WarpgateError::from)?;

        Ok(GetLdapServersResponse::Ok(Json(
            servers.into_iter().map(Into::into).collect(),
        )))
    }

    #[oai(path = "/ldap-servers", method = "post", operation_id = "create_ldap_server")]
    async fn api_create_ldap_server(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        body: Json<CreateLdapServerRequest>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<CreateLdapServerResponse, WarpgateError> {
        if body.name.is_empty() {
            return Ok(CreateLdapServerResponse::BadRequest(Json(
                "Name cannot be empty".into(),
            )));
        }

        let db = db.lock().await;

        // Check if name already exists
        let existing = LdapServer::Entity::find()
            .filter(LdapServer::Column::Name.eq(&body.name))
            .one(&*db)
            .await?;

        if existing.is_some() {
            return Ok(CreateLdapServerResponse::Conflict(Json(
                "Name already exists".into(),
            )));
        }

        // Create LDAP config for discovery
        let ldap_config = warpgate_ldap::LdapConfig {
            host: body.host.clone(),
            port: body.port as u16,
            bind_dn: body.bind_dn.clone(),
            bind_password: body.bind_password.expose_secret().clone(),
            tls_mode: body.tls_mode,
            tls_verify: body.tls_verify,
            base_dns: vec![],
            user_filter: body.user_filter.clone(),
        };

        // Discover base DNs
        let base_dns = warpgate_ldap::discover_base_dns(&ldap_config).await?;

        let base_dns_json = serde_json::to_value(&base_dns)?;

        let values = LdapServer::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(body.name.clone()),
            host: Set(body.host.clone()),
            port: Set(body.port),
            bind_dn: Set(body.bind_dn.clone()),
            bind_password: Set(body.bind_password.expose_secret().clone()),
            user_filter: Set(body.user_filter.clone()),
            base_dns: Set(base_dns_json),
            tls_mode: Set(String::from(body.tls_mode)),
            tls_verify: Set(body.tls_verify),
            enabled: Set(body.enabled),
            auto_link_sso_users: Set(body.auto_link_sso_users),
            description: Set(body.description.clone().unwrap_or_default()),
        };

        let server = values.insert(&*db).await.map_err(WarpgateError::from)?;

        Ok(CreateLdapServerResponse::Created(Json(server.into())))
    }

    #[oai(
        path = "/ldap-servers/test",
        method = "post",
        operation_id = "test_ldap_server_connection"
    )]
    async fn api_test_ldap_server(
        &self,
        body: Json<TestLdapServerRequest>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<TestLdapServerConnectionResponse, WarpgateError> {
        let ldap_config = warpgate_ldap::LdapConfig {
            host: body.host.clone(),
            port: body.port as u16,
            bind_dn: body.bind_dn.clone(),
            bind_password: body.bind_password.expose_secret().clone(),
            tls_mode: body.tls_mode,
            tls_verify: body.tls_verify,
            base_dns: vec![],
            user_filter: String::new(),
        };

        match warpgate_ldap::test_connection(&ldap_config).await {
            Ok(_) => {
                // Try to discover base DNs
                let base_dns = warpgate_ldap::discover_base_dns(&ldap_config).await.ok();

                Ok(TestLdapServerConnectionResponse::Ok(Json(
                    TestLdapServerResponse {
                        success: true,
                        message: "Connection successful".to_string(),
                        base_dns,
                    },
                )))
            }
            Err(e) => Ok(TestLdapServerConnectionResponse::Ok(Json(
                TestLdapServerResponse {
                    success: false,
                    message: format!("Connection failed: {}", e),
                    base_dns: None,
                },
            ))),
        }
    }
}

#[derive(ApiResponse)]
enum GetLdapServerResponse {
    #[oai(status = 200)]
    Ok(Json<LdapServerResponse>),

    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
#[allow(dead_code)]
enum UpdateLdapServerResponse {
    #[oai(status = 200)]
    Ok(Json<LdapServerResponse>),

    #[oai(status = 404)]
    NotFound,

    #[oai(status = 400)]
    BadRequest(Json<String>),
}

#[derive(ApiResponse)]
enum DeleteLdapServerResponse {
    #[oai(status = 204)]
    Deleted,

    #[oai(status = 404)]
    NotFound,
}

pub struct DetailApi;

#[OpenApi]
impl DetailApi {
    #[oai(
        path = "/ldap-servers/:id",
        method = "get",
        operation_id = "get_ldap_server"
    )]
    async fn api_get_ldap_server(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetLdapServerResponse, WarpgateError> {
        let db = db.lock().await;

        let Some(server) = LdapServer::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(GetLdapServerResponse::NotFound);
        };

        Ok(GetLdapServerResponse::Ok(Json(server.into())))
    }

    #[oai(
        path = "/ldap-servers/:id",
        method = "put",
        operation_id = "update_ldap_server"
    )]
    async fn api_update_ldap_server(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        body: Json<UpdateLdapServerRequest>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<UpdateLdapServerResponse, WarpgateError> {
        let db = db.lock().await;

        let Some(server) = LdapServer::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(UpdateLdapServerResponse::NotFound);
        };

        let mut model: LdapServer::ActiveModel = server.into();

        // Update fields
        model.name = Set(body.name.clone());
        model.host = Set(body.host.clone());
        model.port = Set(body.port);
        model.bind_dn = Set(body.bind_dn.clone());
        if let Some(password) = &body.bind_password {
            model.bind_password = Set(password.expose_secret().clone());
        }
        model.user_filter = Set(body.user_filter.clone());
        model.tls_mode = Set(String::from(body.tls_mode.clone()));
        model.tls_verify = Set(body.tls_verify);
        model.enabled = Set(body.enabled);
        model.auto_link_sso_users = Set(body.auto_link_sso_users);
        model.description = Set(body.description.clone().unwrap_or_default());

        // Re-discover base DNs if connection details changed
        let ldap_config = warpgate_ldap::LdapConfig {
            host: body.host.clone(),
            port: body.port as u16,
            bind_dn: body.bind_dn.clone(),
            bind_password: body.bind_password.as_ref().map(|p| p.expose_secret().clone())
                .unwrap_or_else(|| model.bind_password.clone().unwrap()),
            tls_mode: body.tls_mode,
            tls_verify: body.tls_verify,
            base_dns: vec![],
            user_filter: body.user_filter.clone(),
        };

        if let Ok(base_dns) = warpgate_ldap::discover_base_dns(&ldap_config).await {
            model.base_dns = Set(serde_json::to_value(&base_dns)?);
        }

        let server = model.update(&*db).await?;

        Ok(UpdateLdapServerResponse::Ok(Json(server.into())))
    }

    #[oai(
        path = "/ldap-servers/:id",
        method = "delete",
        operation_id = "delete_ldap_server"
    )]
    async fn api_delete_ldap_server(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<DeleteLdapServerResponse, WarpgateError> {
        let db = db.lock().await;

        let Some(server) = LdapServer::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(DeleteLdapServerResponse::NotFound);
        };

        server
            .delete(&*db)
            .await
            .map_err(WarpgateError::from)?;

        Ok(DeleteLdapServerResponse::Deleted)
    }
}

#[derive(ApiResponse)]
enum GetLdapUsersResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<LdapUserResponse>>),

    #[oai(status = 404)]
    NotFound,

    #[oai(status = 400)]
    BadRequest(Json<String>),
}

pub struct QueryApi;

#[OpenApi]
impl QueryApi {
    #[oai(
        path = "/ldap-servers/:id/users",
        method = "get",
        operation_id = "get_ldap_users"
    )]
    async fn api_get_ldap_users(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetLdapUsersResponse, WarpgateError> {
        let db = db.lock().await;

        let Some(server) = LdapServer::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(GetLdapUsersResponse::NotFound);
        };

        let ldap_config = warpgate_ldap::LdapConfig::try_from(&server)?;

        match warpgate_ldap::list_users(&ldap_config).await {
            Ok(users) => Ok(GetLdapUsersResponse::Ok(Json(
                users.into_iter().map(Into::into).collect(),
            ))),
            Err(e) => Ok(GetLdapUsersResponse::BadRequest(Json(format!(
                "Failed to query users: {}",
                e
            )))),
        }
    }
}

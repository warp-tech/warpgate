use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use poem::web::Data;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use russh::keys::{Algorithm, PublicKey};
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, Set};
use tokio::sync::Mutex;
use uuid::Uuid;
use warpgate_common::WarpgateError;
use warpgate_db_entities::KnownHost;

use super::AnySecurityScheme;

pub struct Api;

#[derive(ApiResponse)]
enum GetSSHKnownHostsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<KnownHost::Model>>),
}

#[derive(ApiResponse)]
enum AddSshKnownHostResponse {
    #[oai(status = 200)]
    Ok(Json<KnownHost::Model>),
}

#[derive(Object)]
struct AddSshKnownHostRequest {
    host: String,
    port: i32,
    key_type: String,
    key_base64: String,
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/ssh/known-hosts",
        method = "post",
        operation_id = "add_ssh_known_host"
    )]
    async fn add_ssh_known_host(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        body: Json<AddSshKnownHostRequest>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<AddSshKnownHostResponse, WarpgateError> {
        use warpgate_db_entities::KnownHost;

        // Validate
        Algorithm::from_str(&body.key_type).context("parsing key type")?;
        PublicKey::from_openssh(&format!("{} {}", body.key_type, body.key_base64))
            .context("parsing key")?;

        let db = db.lock().await;
        let model = KnownHost::ActiveModel {
            id: Set(Uuid::new_v4()),
            host: Set(body.host.clone()),
            port: Set(body.port),
            key_type: Set(body.key_type.clone()),
            key_base64: Set(body.key_base64.clone()),
        }
        .insert(&*db)
        .await?;
        Ok(AddSshKnownHostResponse::Ok(Json(model)))
    }

    #[oai(
        path = "/ssh/known-hosts",
        method = "get",
        operation_id = "get_ssh_known_hosts"
    )]
    async fn get_ssh_known_hosts(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetSSHKnownHostsResponse, WarpgateError> {
        use warpgate_db_entities::KnownHost;

        let db = db.lock().await;
        let hosts = KnownHost::Entity::find().all(&*db).await?;
        Ok(GetSSHKnownHostsResponse::Ok(Json(hosts)))
    }
}

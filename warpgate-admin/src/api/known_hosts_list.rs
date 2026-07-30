use std::str::FromStr;

use anyhow::Context;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use russh::keys::{Algorithm, PublicKey};
use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use uuid::Uuid;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_db_entities::KnownHost;

use super::AdminContext;

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
        admin: AdminContext,
        body: Json<AddSshKnownHostRequest>,
    ) -> Result<AddSshKnownHostResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;

        // Validate
        Algorithm::from_str(&body.key_type).context("parsing key type")?;
        PublicKey::from_openssh(&format!("{} {}", body.key_type, body.key_base64))
            .context("parsing key")?;

        let db = &admin.services().db;
        let model = KnownHost::ActiveModel {
            id: Set(Uuid::new_v4()),
            host: Set(body.host.clone()),
            port: Set(body.port),
            key_type: Set(body.key_type.clone()),
            key_base64: Set(body.key_base64.clone()),
        }
        .insert(db)
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
        admin: AdminContext,
    ) -> Result<GetSSHKnownHostsResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;

        let db = &admin.services().db;
        let hosts = KnownHost::Entity::find().all(db).await?;
        Ok(GetSSHKnownHostsResponse::Ok(Json(hosts)))
    }
}

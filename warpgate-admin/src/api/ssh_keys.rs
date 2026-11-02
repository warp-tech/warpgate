use std::str::FromStr;

use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Enum, Object, OpenApi};
use russh::keys::{Algorithm, HashAlg, PrivateKey};
use sea_orm::EntityTrait;
use serde::Serialize;
use uuid::Uuid;
use warpgate_common::helpers::rng::get_crypto_rng;
use warpgate_common::{AdminPermission, ProviderId, SecretRef, WarpgateError};
use warpgate_common_http::errors::bad_request;
use warpgate_core::resources::ssh_client_keys::{self, KeyMaterial, SshClientKeyDataRequest};
use warpgate_core::resources::{Actor, ResourceError};
use warpgate_db_entities::SshClientKey;

use super::AdminContext;

pub struct Api;

#[derive(Serialize, Object)]
struct SSHClientKey {
    pub id: Uuid,
    pub label: String,
    pub kind: String,
    pub public_key: String,
    pub is_default: bool,
    pub secret_backend: Option<String>,
    /// The provider that manages the key, if any; such a key is read-only here
    pub provider: Option<ProviderId>,
}

impl From<SshClientKey::Model> for SSHClientKey {
    fn from(model: SshClientKey::Model) -> Self {
        let kind = model
            .public_key
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .into();
        let backend = model.secret_key.as_reference().map(|r| r.backend.clone());
        Self {
            id: model.id,
            label: model.label,
            kind,
            public_key: model.public_key,
            is_default: model.is_default,
            secret_backend: backend,
            provider: model.provider,
        }
    }
}

#[derive(Enum)]
enum SSHClientKeyKind {
    Ed25519,
    Rsa,
}

impl From<SSHClientKeyKind> for Algorithm {
    fn from(kind: SSHClientKeyKind) -> Self {
        match kind {
            SSHClientKeyKind::Ed25519 => Self::Ed25519,
            SSHClientKeyKind::Rsa => Self::Rsa {
                hash: Some(HashAlg::Sha512),
            },
        }
    }
}

#[derive(ApiResponse)]
enum GetSSHOwnKeysResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<SSHClientKey>>),
}

#[derive(Object)]
struct ImportSshClientKeyRequest {
    label: String,
    /// Private key in OpenSSH or PKCS#8 PEM format, without a passphrase
    secret_key: String,
    is_default: bool,
}

#[derive(Object)]
struct GenerateSSHClientKeyRequest {
    label: String,
    kind: SSHClientKeyKind,
}

#[derive(Object)]
struct ImportSshClientKeyReferenceRequest {
    #[oai(validator(max_length = 255))]
    label: String,
    /// A `secret://backend/mount/path#field` reference; the field must resolve to
    /// a private key in OpenSSH or PKCS#8 PEM format.
    #[oai(validator(max_length = 1024))]
    reference: String,
    is_default: bool,
}

#[derive(ApiResponse)]
enum CreateSSHClientKeyResponse {
    #[oai(status = 201)]
    Created(Json<SSHClientKey>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 409)]
    Conflict(Json<String>),
}

#[derive(Object)]
struct UpdateSSHClientKeyRequest {
    label: String,
    is_default: bool,
}

#[derive(ApiResponse)]
enum UpdateSSHClientKeyResponse {
    #[oai(status = 200)]
    Ok(Json<SSHClientKey>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 409)]
    Conflict(Json<String>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum ReleaseSSHClientKeyResponse {
    #[oai(status = 200)]
    Ok(Json<SSHClientKey>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DeleteSSHClientKeyResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 409)]
    Conflict(Json<String>),
    #[oai(status = 404)]
    NotFound,
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/ssh/own-keys",
        method = "get",
        operation_id = "get_ssh_own_keys"
    )]
    async fn api_ssh_get_own_keys(
        &self,
        admin: AdminContext,
    ) -> Result<GetSSHOwnKeysResponse, WarpgateError> {
        let keys = SshClientKey::Entity::find_ordered()
            .all(&admin.services().db)
            .await?
            .into_iter()
            .map(Into::into)
            .collect();
        Ok(GetSSHOwnKeysResponse::Ok(Json(keys)))
    }

    #[oai(
        path = "/ssh/own-keys",
        method = "post",
        operation_id = "import_ssh_own_key"
    )]
    async fn api_import_client_key(
        &self,
        admin: AdminContext,
        body: Json<ImportSshClientKeyRequest>,
    ) -> Result<CreateSSHClientKeyResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;

        let key = match russh::keys::decode_secret_key(&body.secret_key, None) {
            Ok(key) => key,
            Err(e) => {
                return Ok(CreateSSHClientKeyResponse::BadRequest(bad_request(
                    format!("Could not parse the private key: {e}"),
                )));
            }
        };

        store_new_key(&admin, &body.label, &key, body.is_default).await
    }

    #[oai(
        path = "/ssh/own-keys/generate",
        method = "post",
        operation_id = "generate_ssh_own_key"
    )]
    async fn api_generate_client_key(
        &self,
        admin: AdminContext,
        body: Json<GenerateSSHClientKeyRequest>,
    ) -> Result<CreateSSHClientKeyResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;

        let Json(GenerateSSHClientKeyRequest { label, kind }) = body;
        let key = PrivateKey::random(&mut get_crypto_rng(), kind.into())
            .map_err(russh::keys::Error::from)?;

        store_new_key(&admin, &label, &key, false).await
    }

    #[oai(
        path = "/ssh/own-keys/reference",
        method = "post",
        operation_id = "import_ssh_own_key_reference"
    )]
    async fn api_import_client_key_reference(
        &self,
        admin: AdminContext,
        body: Json<ImportSshClientKeyReferenceRequest>,
    ) -> Result<CreateSSHClientKeyResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;

        let reference = SecretRef::from_str(&body.reference)?;
        let services = admin.services();
        let material = match KeyMaterial::reference(&reference, &*services.secret_backends).await {
            Ok(material) => material,
            Err(e) => {
                return Ok(CreateSSHClientKeyResponse::BadRequest(Json(format!(
                    "Could not resolve the referenced key: {e}"
                ))));
            }
        };
        let data = SshClientKeyDataRequest {
            label: body.label.clone(),
            is_default: body.is_default,
        };
        created(ssh_client_keys::create(&services.db, Actor::Admin, &data, material).await)
    }

    #[oai(
        path = "/ssh/own-keys/:id",
        method = "put",
        operation_id = "update_ssh_own_key"
    )]
    async fn api_update_client_key(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        body: Json<UpdateSSHClientKeyRequest>,
    ) -> Result<UpdateSSHClientKeyResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;

        let data = SshClientKeyDataRequest {
            label: body.label.clone(),
            is_default: body.is_default,
        };
        match ssh_client_keys::update(&admin.services().db, Actor::Admin, id.0, &data, None).await {
            Ok(model) => Ok(UpdateSSHClientKeyResponse::Ok(Json(model.into()))),
            Err(ResourceError::EmptyName) => Ok(UpdateSSHClientKeyResponse::BadRequest(
                bad_request("The label is empty"),
            )),
            Err(err @ (ResourceError::NameTaken | ResourceError::OwnedBy(_))) => {
                Ok(UpdateSSHClientKeyResponse::Conflict(Json(err.to_string())))
            }
            Err(ResourceError::NotFound) => Ok(UpdateSSHClientKeyResponse::NotFound),
            Err(err) => Err(err.into()),
        }
    }

    /// Hands a managed key back to manual editing
    #[oai(
        path = "/ssh/own-keys/:id/release",
        method = "post",
        operation_id = "release_ssh_own_key"
    )]
    async fn api_release_client_key(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<ReleaseSSHClientKeyResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;

        let db = &admin.services().db;
        ssh_client_keys::release(db, id.0).await?;
        Ok(match SshClientKey::Entity::find_by_id(id.0).one(db).await? {
            Some(key) => ReleaseSSHClientKeyResponse::Ok(Json(key.into())),
            None => ReleaseSSHClientKeyResponse::NotFound,
        })
    }

    #[oai(
        path = "/ssh/own-keys/:id",
        method = "delete",
        operation_id = "delete_ssh_own_key"
    )]
    async fn api_delete_client_key(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<DeleteSSHClientKeyResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;

        match ssh_client_keys::delete(&admin.services().db, Actor::Admin, id.0).await {
            Ok(()) => Ok(DeleteSSHClientKeyResponse::Deleted),
            Err(err @ ResourceError::LastClientKey) => Ok(DeleteSSHClientKeyResponse::BadRequest(
                bad_request(err.to_string()),
            )),
            Err(err @ ResourceError::OwnedBy(_)) => {
                Ok(DeleteSSHClientKeyResponse::Conflict(Json(err.to_string())))
            }
            Err(ResourceError::NotFound) => Ok(DeleteSSHClientKeyResponse::NotFound),
            Err(err) => Err(err.into()),
        }
    }
}

/// Stores a fresh key (imported or generated)
async fn store_new_key(
    admin: &AdminContext,
    label: &str,
    key: &PrivateKey,
    is_default: bool,
) -> Result<CreateSSHClientKeyResponse, WarpgateError> {
    let data = SshClientKeyDataRequest {
        label: label.into(),
        is_default,
    };
    let material = KeyMaterial::inline(key)?;
    created(ssh_client_keys::create(&admin.services().db, Actor::Admin, &data, material).await)
}

fn created(
    result: Result<SshClientKey::Model, ResourceError>,
) -> Result<CreateSSHClientKeyResponse, WarpgateError> {
    match result {
        Ok(model) => Ok(CreateSSHClientKeyResponse::Created(Json(model.into()))),
        Err(ResourceError::KeyTaken) => Ok(CreateSSHClientKeyResponse::Conflict(Json(
            "This key is already imported".into(),
        ))),
        Err(err @ ResourceError::NameTaken) => {
            Ok(CreateSSHClientKeyResponse::Conflict(Json(err.to_string())))
        }
        Err(ResourceError::EmptyName) => Ok(CreateSSHClientKeyResponse::BadRequest(bad_request(
            "The label is empty",
        ))),
        Err(err) => Err(err.into()),
    }
}

use std::str::FromStr;

use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Enum, Object, OpenApi};
use russh::keys::{Algorithm, HashAlg, PrivateKey};
use sea_orm::{ActiveModelTrait, EntityTrait, ModelTrait, PaginatorTrait, Set, Unchanged};
use serde::Serialize;
use uuid::Uuid;
use warpgate_common::helpers::rng::get_crypto_rng;
use warpgate_common::secrets::is_secret_reference;
use warpgate_common::{AdminPermission, SecretRef, WarpgateError};
use warpgate_db_entities::SshClientKey;

use super::AdminContext;

pub struct Api;

#[derive(Serialize, Object)]
struct SSHClientKey {
    pub id: Uuid,
    pub label: String,
    pub kind: String,
    pub public_key: String,
    /// The base64 body without the algorithm prefix — kept for the
    /// backwards-compatible `own-keys` consumers.
    pub public_key_base64: String,
    pub is_default: bool,
    /// The secret backend this key's material is read from, e.g. `"vault-prod"` —
    /// `None` when the key material is stored directly in Warpgate's database.
    pub backend: Option<String>,
}

impl From<SshClientKey::Model> for SSHClientKey {
    fn from(model: SshClientKey::Model) -> Self {
        let mut parts = model.public_key.split_whitespace();
        let kind = parts.next().unwrap_or_default().into();
        let public_key_base64 = parts.next().unwrap_or_default().into();
        let backend = is_secret_reference(&model.secret_key)
            .then(|| SecretRef::from_str(&model.secret_key).ok())
            .flatten()
            .map(|r| r.backend);
        Self {
            id: model.id,
            label: model.label,
            kind,
            public_key_base64,
            public_key: model.public_key,
            is_default: model.is_default,
            backend,
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
struct ImportSSHClientKeyRequest {
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
struct ImportSSHClientKeyReferenceRequest {
    label: String,
    /// A `vault://backend/path#field` or `openbao://backend/path#field` reference;
    /// the field must resolve to a private key in OpenSSH or PKCS#8 PEM format.
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
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DeleteSSHClientKeyResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 400)]
    BadRequest(Json<String>),
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
        body: Json<ImportSSHClientKeyRequest>,
    ) -> Result<CreateSSHClientKeyResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;

        let key = match russh::keys::decode_secret_key(&body.secret_key, None) {
            Ok(key) => key,
            Err(e) => {
                return Ok(CreateSSHClientKeyResponse::BadRequest(Json(format!(
                    "Could not parse the private key: {e}"
                ))));
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
        body: Json<ImportSSHClientKeyReferenceRequest>,
    ) -> Result<CreateSSHClientKeyResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;

        let reference = match SecretRef::from_str(&body.reference) {
            Ok(r) => r,
            Err(e) => {
                return Ok(CreateSSHClientKeyResponse::BadRequest(Json(format!(
                    "Invalid secret reference: {e}"
                ))));
            }
        };

        let model = warpgate_protocol_ssh::import_client_key_reference(
            &admin.services().db,
            &body.label,
            &reference,
            &*admin.services().secret_backend,
            body.is_default,
        )
        .await;

        match model {
            Ok(Some(model)) => Ok(CreateSSHClientKeyResponse::Created(Json(model.into()))),
            Ok(None) => Ok(CreateSSHClientKeyResponse::Conflict(Json(
                "This key is already imported".into(),
            ))),
            Err(e) => Ok(CreateSSHClientKeyResponse::BadRequest(Json(format!(
                "Could not resolve the referenced key: {e}"
            )))),
        }
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

        let db = &admin.services().db;
        let Some(key) = SshClientKey::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(UpdateSSHClientKeyResponse::NotFound);
        };

        let model = SshClientKey::ActiveModel {
            id: Unchanged(key.id),
            label: Set(body.label.clone()),
            is_default: Set(body.is_default),
            ..Default::default()
        }
        .update(db)
        .await?;

        Ok(UpdateSSHClientKeyResponse::Ok(Json(model.into())))
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

        let db = &admin.services().db;
        let Some(key) = SshClientKey::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(DeleteSSHClientKeyResponse::NotFound);
        };

        if SshClientKey::Entity::find().count(db).await? <= 1 {
            return Ok(DeleteSSHClientKeyResponse::BadRequest(Json(
                "At least one SSH client key must remain".into(),
            )));
        }

        key.delete(db).await?;
        Ok(DeleteSSHClientKeyResponse::Deleted)
    }
}

/// Stores a fresh key (imported or generated) as a non-default key — the admin
/// flags it default afterwards. A duplicate public key yields a 409.
async fn store_new_key(
    admin: &AdminContext,
    label: &str,
    key: &PrivateKey,
    is_default: bool,
) -> Result<CreateSSHClientKeyResponse, WarpgateError> {
    match warpgate_protocol_ssh::import_client_key(&admin.services().db, label, key, is_default)
        .await?
    {
        Some(model) => Ok(CreateSSHClientKeyResponse::Created(Json(model.into()))),
        None => Ok(CreateSSHClientKeyResponse::Conflict(Json(
            "This key is already imported".into(),
        ))),
    }
}

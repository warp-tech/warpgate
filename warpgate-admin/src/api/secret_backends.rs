use std::collections::HashMap;
use std::mem;
use std::str::FromStr;

use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, ModelTrait, QueryOrder, Set};
use uuid::Uuid;
use warpgate_common::encryption::idempotent_maybe_encrypt_secret;
use warpgate_common::secrets::validate_backend_name;
use warpgate_common::{
    AdminPermission, BackendType, SecretError, SecretRef, SecretResolver as _, StoredSecret,
    TargetOptions, VaultAuthConfig, WarpgateError,
};
use warpgate_db_entities::{Parameters, SecretBackend, SshClientKey, Target};

use super::AdminContext;
use crate::api::common::is_unique_violation;

#[derive(Object)]
pub struct SecretBackendResponse {
    pub id: Uuid,
    pub name: String,
    pub backend_type: BackendType,
    pub address: String,
    pub namespace: Option<String>,
    pub auth: VaultAuthConfig,
    pub tls_skip_verify: bool,
    pub allowed_paths: Vec<String>,
}

impl From<SecretBackend::Model> for SecretBackendResponse {
    fn from(model: SecretBackend::Model) -> Self {
        Self {
            allowed_paths: model.allowed_paths(),
            auth: model.auth.redacted(),
            id: model.id,
            name: model.name,
            backend_type: model.backend_type,
            address: model.address,
            namespace: model.namespace,
            tls_skip_verify: model.tls_skip_verify,
        }
    }
}

/// Shared by create and update.
#[derive(Object)]
pub struct SecretBackendRequest {
    #[oai(validator(min_length = 1, max_length = 64, pattern = r"^[A-Za-z0-9._-]+$"))]
    pub name: String,
    pub backend_type: BackendType,
    #[oai(validator(min_length = 1, max_length = 2048))]
    pub address: String,
    #[oai(validator(min_length = 1, max_length = 255))]
    pub namespace: Option<String>,
    pub auth: VaultAuthConfig,
    #[oai(default)]
    pub tls_skip_verify: bool,
    /// KV path prefixes (`mount/path`), matched on whole segments
    #[oai(default, validator(max_items = 256, max_length = 1024))]
    pub allowed_paths: Vec<String>,
}

#[derive(Object)]
pub struct CheckHealthResponse {
    /// `null` when the backend is reachable and accepts the stored credentials
    pub error: Option<String>,
}

#[derive(Object)]
pub struct TestResolveRequest {
    #[oai(validator(max_length = 1024))]
    pub reference: String,
}

#[derive(Object)]
pub struct SecretReferenceUsageTarget {
    pub id: Uuid,
    pub name: String,
}

#[derive(Object)]
pub struct SecretReferenceUsage {
    pub reference: String,
    pub backend: String,
    pub targets: Vec<SecretReferenceUsageTarget>,
}

#[derive(ApiResponse)]
enum GetSecretBackendsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<SecretBackendResponse>>),
}

#[derive(ApiResponse)]
enum GetSecretBackendResponse {
    #[oai(status = 200)]
    Ok(Json<SecretBackendResponse>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum CreateSecretBackendResponse {
    #[oai(status = 201)]
    Created(Json<SecretBackendResponse>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 409)]
    Conflict(Json<String>),
}

#[derive(ApiResponse)]
enum UpdateSecretBackendResponse {
    #[oai(status = 200)]
    Ok(Json<SecretBackendResponse>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 404)]
    NotFound,
    #[oai(status = 409)]
    Conflict(Json<String>),
}

#[derive(ApiResponse)]
enum DeleteSecretBackendResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 404)]
    NotFound,
    #[oai(status = 409)]
    Conflict(Json<String>),
}

#[derive(ApiResponse)]
enum CheckHealthApiResponse {
    #[oai(status = 200)]
    Ok(Json<CheckHealthResponse>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum TestResolveApiResponse {
    /// The reference resolved; the value itself is never returned
    #[oai(status = 204)]
    Resolved,
    #[oai(status = 400)]
    BadRequest(Json<String>),
    /// The path is outside the backend's allowed prefixes
    #[oai(status = 403)]
    Forbidden(Json<String>),
    /// No such backend, secret or field
    #[oai(status = 404)]
    NotFound(Json<String>),
    /// The backend could not be reached or refused the request
    #[oai(status = 502)]
    BadGateway(Json<String>),
}

impl From<SecretError> for TestResolveApiResponse {
    fn from(error: SecretError) -> Self {
        let message = Json(error.to_string());
        match error {
            SecretError::InvalidRef(_) | SecretError::InvalidBackendName(_) => {
                Self::BadRequest(message)
            }
            SecretError::PathNotAllowed { .. } => Self::Forbidden(message),
            SecretError::BackendNotConfigured { .. } | SecretError::NotFound { .. } => {
                Self::NotFound(message)
            }
            SecretError::Backend(_) => Self::BadGateway(message),
        }
    }
}

#[derive(ApiResponse)]
enum GetSecretReferenceUsageResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<SecretReferenceUsage>>),
}

const NAME_TAKEN: &str = "A secret backend with this name already exists";

/// Copies a request onto a row. A secret omitted from the request keeps the
/// one stored for the same method; there is nothing to keep for another method.
fn apply_request(
    model: &mut SecretBackend::ActiveModel,
    body: &SecretBackendRequest,
    existing: Option<&SecretBackend::Model>,
) -> Result<(), String> {
    validate_backend_name(&body.name).map_err(|e| e.to_string())?;
    if body.allowed_paths.iter().any(|p| p.contains('\n')) {
        return Err("An allowed path cannot contain a line break".into());
    }

    // A blank secret is the redacted value responses carry, so it keeps the
    // one stored for the same method.
    let stored = existing
        .map(|m| &m.auth)
        .filter(|auth| mem::discriminant(*auth) == mem::discriminant(&body.auth))
        .and_then(VaultAuthConfig::secret);
    let mut auth = body.auth.clone();
    if let Some(secret) = auth.secret_mut() {
        let given = secret.stored_value();
        *secret = if given.is_empty() {
            stored.cloned().ok_or_else(|| {
                "The login secret is required for this authentication method".to_owned()
            })?
        } else {
            StoredSecret::from(idempotent_maybe_encrypt_secret(given).map_err(|e| e.to_string())?)
        };
    }

    model.name = Set(body.name.clone());
    model.backend_type = Set(body.backend_type);
    model.address = Set(body.address.clone());
    model.namespace = Set(body.namespace.clone());
    model.auth = Set(auth);
    model.tls_skip_verify = Set(body.tls_skip_verify);
    model.allowed_paths = Set(body.allowed_paths.join("\n"));
    Ok(())
}

/// What still names the backend: a backend can't be removed or renamed from
/// under a reference, because the reference would only fail at connect time.
async fn references_to(db: &DatabaseConnection, name: &str) -> Result<Vec<String>, WarpgateError> {
    let mut found = Vec::new();
    for target in Target::Entity::find().all(db).await? {
        if let Ok(options) = serde_json::from_value::<TargetOptions>(target.options)
            && options
                .secret_references()
                .iter()
                .any(|r| r.backend == name)
        {
            found.push(format!("target '{}'", target.name));
        }
    }
    for key in SshClientKey::Entity::find().all(db).await? {
        if key
            .secret_key
            .as_reference()
            .is_some_and(|r| r.backend == name)
        {
            found.push(format!("SSH client key '{}'", key.label));
        }
    }
    if let Some(reference) = Parameters::Entity::get(db).await?.ssh_host_key_secret_ref
        && reference.backend == name
    {
        found.push("the SSH host key setting".into());
    }
    Ok(found)
}

fn in_use(found: &[String]) -> String {
    format!("This secret backend is used by {}", found.join(", "))
}

pub struct Api;

#[OpenApi]
impl Api {
    #[oai(
        path = "/secret-backends",
        method = "get",
        operation_id = "get_secret_backends"
    )]
    async fn api_get_secret_backends(
        &self,
        admin: AdminContext,
    ) -> Result<GetSecretBackendsResponse, WarpgateError> {
        let backends = SecretBackend::Entity::find()
            .order_by_asc(SecretBackend::Column::Name)
            .all(&admin.services().db)
            .await?
            .into_iter()
            .map(Into::into)
            .collect();
        Ok(GetSecretBackendsResponse::Ok(Json(backends)))
    }

    #[oai(
        path = "/secret-backends",
        method = "post",
        operation_id = "create_secret_backend"
    )]
    async fn api_create_secret_backend(
        &self,
        admin: AdminContext,
        body: Json<SecretBackendRequest>,
    ) -> Result<CreateSecretBackendResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;
        let db = &admin.services().db;

        let mut model = SecretBackend::ActiveModel {
            id: Set(Uuid::new_v4()),
            ..Default::default()
        };
        if let Err(error) = apply_request(&mut model, &body, None) {
            return Ok(CreateSecretBackendResponse::BadRequest(Json(error)));
        }
        match model.insert(db).await {
            Ok(model) => Ok(CreateSecretBackendResponse::Created(Json(model.into()))),
            Err(e) if is_unique_violation(&e) => Ok(CreateSecretBackendResponse::Conflict(Json(
                NAME_TAKEN.into(),
            ))),
            Err(e) => Err(e.into()),
        }
    }

    #[oai(
        path = "/secret-backends/:id",
        method = "get",
        operation_id = "get_secret_backend"
    )]
    async fn api_get_secret_backend(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<GetSecretBackendResponse, WarpgateError> {
        match SecretBackend::Entity::find_by_id(id.0)
            .one(&admin.services().db)
            .await?
        {
            Some(model) => Ok(GetSecretBackendResponse::Ok(Json(model.into()))),
            None => Ok(GetSecretBackendResponse::NotFound),
        }
    }

    #[oai(
        path = "/secret-backends/:id",
        method = "put",
        operation_id = "update_secret_backend"
    )]
    async fn api_update_secret_backend(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        body: Json<SecretBackendRequest>,
    ) -> Result<UpdateSecretBackendResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;
        let db = &admin.services().db;

        let Some(existing) = SecretBackend::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(UpdateSecretBackendResponse::NotFound);
        };
        if existing.name != body.name {
            let found = references_to(db, &existing.name).await?;
            if !found.is_empty() {
                return Ok(UpdateSecretBackendResponse::Conflict(Json(in_use(&found))));
            }
        }

        let mut model: SecretBackend::ActiveModel = existing.clone().into();
        if let Err(error) = apply_request(&mut model, &body, Some(&existing)) {
            return Ok(UpdateSecretBackendResponse::BadRequest(Json(error)));
        }
        match model.update(db).await {
            Ok(model) => Ok(UpdateSecretBackendResponse::Ok(Json(model.into()))),
            Err(e) if is_unique_violation(&e) => Ok(UpdateSecretBackendResponse::Conflict(Json(
                NAME_TAKEN.into(),
            ))),
            Err(e) => Err(e.into()),
        }
    }

    #[oai(
        path = "/secret-backends/:id",
        method = "delete",
        operation_id = "delete_secret_backend"
    )]
    async fn api_delete_secret_backend(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<DeleteSecretBackendResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;
        let db = &admin.services().db;

        let Some(model) = SecretBackend::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(DeleteSecretBackendResponse::NotFound);
        };
        let found = references_to(db, &model.name).await?;
        if !found.is_empty() {
            return Ok(DeleteSecretBackendResponse::Conflict(Json(in_use(&found))));
        }
        model.delete(db).await?;
        Ok(DeleteSecretBackendResponse::Deleted)
    }

    #[oai(
        path = "/secret-backends/:id/health",
        method = "post",
        operation_id = "check_secret_backend_health"
    )]
    async fn api_check_backend_health(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<CheckHealthApiResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;
        let services = admin.services();

        let Some(model) = SecretBackend::Entity::find_by_id(id.0)
            .one(&services.db)
            .await?
        else {
            return Ok(CheckHealthApiResponse::NotFound);
        };

        let error = services
            .secret_backends
            .health_of(&model.name)
            .await
            .err()
            .map(|e| e.to_string());
        Ok(CheckHealthApiResponse::Ok(Json(CheckHealthResponse {
            error,
        })))
    }

    #[oai(
        path = "/secret-backends/resolve-test",
        method = "post",
        operation_id = "test_secret_resolve"
    )]
    async fn api_test_secret_resolve(
        &self,
        admin: AdminContext,
        body: Json<TestResolveRequest>,
    ) -> Result<TestResolveApiResponse, WarpgateError> {
        // The permission it takes to make Warpgate use a reference.
        admin.require(AdminPermission::TargetsEdit)?;

        let secret_ref = match SecretRef::from_str(&body.reference) {
            Ok(r) => r,
            Err(e) => return Ok(e.into()),
        };
        Ok(
            match admin.services().secret_backends.resolve(&secret_ref).await {
                Ok(_) => TestResolveApiResponse::Resolved,
                Err(e) => e.into(),
            },
        )
    }

    #[oai(
        path = "/secret-backends/usage",
        method = "get",
        operation_id = "get_secret_reference_usage"
    )]
    async fn api_get_secret_reference_usage(
        &self,
        admin: AdminContext,
    ) -> Result<GetSecretReferenceUsageResponse, WarpgateError> {
        let targets = Target::Entity::find().all(&admin.services().db).await?;

        let mut usage: HashMap<String, SecretReferenceUsage> = HashMap::new();
        for target in targets {
            // Skip targets whose options can't be parsed rather than failing the whole report.
            let Ok(options) = serde_json::from_value::<TargetOptions>(target.options) else {
                continue;
            };
            for reference in options.secret_references() {
                let key = reference.to_string();
                let entry = usage
                    .entry(key.clone())
                    .or_insert_with(|| SecretReferenceUsage {
                        reference: key,
                        backend: reference.backend.clone(),
                        targets: Vec::new(),
                    });
                // A target may reference the same secret from more than one field; list it once.
                if !entry.targets.iter().any(|t| t.id == target.id) {
                    entry.targets.push(SecretReferenceUsageTarget {
                        id: target.id,
                        name: target.name.clone(),
                    });
                }
            }
        }

        let mut usage: Vec<SecretReferenceUsage> = usage.into_values().collect();
        usage.sort_by(|a, b| a.reference.cmp(&b.reference));
        Ok(GetSecretReferenceUsageResponse::Ok(Json(usage)))
    }
}

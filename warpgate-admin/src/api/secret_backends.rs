use std::collections::HashMap;
use std::fmt::Display;
use std::mem;
use std::str::FromStr;

use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi, Union};
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, ModelTrait, QueryOrder, Set};
use uuid::Uuid;
use warpgate_common::encryption::idempotent_maybe_encrypt_secret;
use warpgate_common::secrets::validate_backend_name;
use warpgate_common::{
    AdminPermission, BackendType, SecretError, SecretRef, SecretResolver as _, StoredSecret,
    TargetSecrets, VaultAuthConfig, WarpgateError,
};
use warpgate_db_entities::{SecretBackend, SshClientKey, Target};

use super::AdminContext;
use crate::api::common::is_unique_violation;

#[derive(Object)]
#[oai(rename = "SecretBackend")]
pub struct SecretBackendModel {
    pub id: Uuid,
    pub name: String,
    pub backend_type: BackendType,
    pub address: String,
    pub namespace: Option<String>,
    pub auth: VaultAuthConfig,
    pub tls_skip_verify: bool,
    pub allowed_paths: Vec<String>,
}

impl From<SecretBackend::Model> for SecretBackendModel {
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
#[derive(Object)]
#[oai(rename = "SecretBackendSummary")]
pub struct SecretBackendSummary {
    pub id: Uuid,
    pub name: String,
    pub backend_type: BackendType,
}

impl From<SecretBackend::Model> for SecretBackendSummary {
    fn from(model: SecretBackend::Model) -> Self {
        Self {
            id: model.id,
            name: model.name,
            backend_type: model.backend_type,
        }
    }
}

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
pub struct SecretReferenceUsageSshClientKey {
    pub id: Uuid,
    pub label: String,
}

#[derive(Union)]
#[oai(discriminator_name = "kind", one_of)]
pub enum SecretReferenceUsageInstance {
    Target(SecretReferenceUsageTarget),
    SshClientKey(SecretReferenceUsageSshClientKey),
}

impl Display for SecretReferenceUsageInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Target(target) => write!(f, "target '{}'", target.name),
            Self::SshClientKey(key) => write!(f, "SSH client key '{}'", key.label),
        }
    }
}

#[derive(Object)]
pub struct SecretReferenceUsage {
    pub reference: String,
    pub backend: String,
    pub usages: Vec<SecretReferenceUsageInstance>,
}

#[derive(ApiResponse)]
enum GetSecretBackendsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<SecretBackendModel>>),
}

#[derive(ApiResponse)]
enum GetSecretBackendsSummaryResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<SecretBackendSummary>>),
}

#[derive(ApiResponse)]
enum GetSecretBackendResponse {
    #[oai(status = 200)]
    Ok(Json<SecretBackendModel>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum CreateSecretBackendResponse {
    #[oai(status = 201)]
    Created(Json<SecretBackendModel>),
    #[oai(status = 409)]
    Conflict(Json<String>),
}

#[derive(ApiResponse)]
enum UpdateSecretBackendResponse {
    #[oai(status = 200)]
    Ok(Json<SecretBackendModel>),
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
    #[oai(status = 404)]
    NotFound,
}

const NAME_TAKEN: &str = "A secret backend with this name already exists";

fn update_active_model(
    model: &mut SecretBackend::ActiveModel,
    body: &SecretBackendRequest,
    existing: Option<&SecretBackend::Model>,
) -> Result<(), WarpgateError> {
    validate_backend_name(&body.name)?;

    // existing entry that can be used to restore the full auth field
    let stored = existing
        .map(|m| &m.auth)
        // only if the auth type hasn't changed
        .filter(|auth| mem::discriminant(*auth) == mem::discriminant(&body.auth))
        .and_then(VaultAuthConfig::secret);

    let mut auth = body.auth.clone();
    if let Some(provided_secret) = auth.secret_mut() {
        let provided_value = provided_secret.stored_value();
        *provided_secret = if provided_value.is_empty() {
            stored.cloned().ok_or_else(|| {
                WarpgateError::InvalidRequest(
                    "The login secret is required for this authentication method".into(),
                )
            })?
        } else {
            StoredSecret::from(idempotent_maybe_encrypt_secret(provided_value)?)
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

async fn existing_references_to_backend(
    db: &DatabaseConnection,
    backend_name: &str,
) -> Result<HashMap<SecretRef, Vec<SecretReferenceUsageInstance>>, WarpgateError> {
    let mut found: HashMap<SecretRef, Vec<SecretReferenceUsageInstance>> = HashMap::new();

    for target in Target::Entity::find().all(db).await? {
        if let Ok(target) = warpgate_common::Target::try_from(target) {
            for secret in target
                .options
                .secrets()
                .into_iter()
                .filter_map(|s| s.as_reference())
            {
                if secret.backend == backend_name {
                    found.entry(secret.clone()).or_default().push(
                        SecretReferenceUsageInstance::Target(SecretReferenceUsageTarget {
                            id: target.id,
                            name: target.name.clone(),
                        }),
                    );
                }
            }
        }
    }
    for key in SshClientKey::Entity::find().all(db).await? {
        if let Some(reference) = key.secret_key.as_reference()
            && reference.backend == backend_name
        {
            found.entry(reference.clone()).or_default().push(
                SecretReferenceUsageInstance::SshClientKey(SecretReferenceUsageSshClientKey {
                    id: key.id,
                    label: key.label,
                }),
            );
        }
    }
    Ok(found)
}

fn in_use_err_msg(found: &HashMap<SecretRef, Vec<SecretReferenceUsageInstance>>) -> String {
    format!(
        "This secret backend is used by {}",
        found
            .values()
            .flatten()
            .map(|x| format!("{x}"))
            .collect::<Vec<_>>()
            .join(", ")
    )
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
        admin.require(AdminPermission::ConfigEdit)?;

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
        path = "/secret-backends/summary",
        method = "get",
        operation_id = "get_secret_backends_summary"
    )]
    async fn api_get_secret_backends_summary(
        &self,
        admin: AdminContext,
    ) -> Result<GetSecretBackendsSummaryResponse, WarpgateError> {
        let backends = SecretBackend::Entity::find()
            .order_by_asc(SecretBackend::Column::Name)
            .all(&admin.services().db)
            .await?
            .into_iter()
            .map(Into::into)
            .collect();
        Ok(GetSecretBackendsSummaryResponse::Ok(Json(backends)))
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
        update_active_model(&mut model, &body, None)?;
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
        Path(id): Path<Uuid>,
    ) -> Result<GetSecretBackendResponse, WarpgateError> {
        let Some(backend) = SecretBackend::Entity::find_by_id(id)
            .one(&admin.services().db)
            .await?
        else {
            return Ok(GetSecretBackendResponse::NotFound);
        };
        Ok(GetSecretBackendResponse::Ok(Json(backend.into())))
    }

    #[oai(
        path = "/secret-backends/:id",
        method = "put",
        operation_id = "update_secret_backend"
    )]
    async fn api_update_secret_backend(
        &self,
        admin: AdminContext,
        Path(id): Path<Uuid>,
        body: Json<SecretBackendRequest>,
    ) -> Result<UpdateSecretBackendResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;
        let db = &admin.services().db;

        let Some(existing) = SecretBackend::Entity::find_by_id(id).one(db).await? else {
            return Ok(UpdateSecretBackendResponse::NotFound);
        };
        if existing.name != body.name {
            let found = existing_references_to_backend(db, &existing.name).await?;
            if !found.is_empty() {
                return Ok(UpdateSecretBackendResponse::Conflict(Json(in_use_err_msg(
                    &found,
                ))));
            }
        }

        let mut model: SecretBackend::ActiveModel = existing.clone().into();
        update_active_model(&mut model, &body, Some(&existing))?;
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
        Path(id): Path<Uuid>,
    ) -> Result<DeleteSecretBackendResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;
        let db = &admin.services().db;

        let Some(model) = SecretBackend::Entity::find_by_id(id).one(db).await? else {
            return Ok(DeleteSecretBackendResponse::NotFound);
        };
        let found = existing_references_to_backend(db, &model.name).await?;
        if !found.is_empty() {
            return Ok(DeleteSecretBackendResponse::Conflict(Json(in_use_err_msg(
                &found,
            ))));
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
        Path(id): Path<Uuid>,
    ) -> Result<CheckHealthApiResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;
        let services = admin.services();

        let Some(model) = SecretBackend::Entity::find_by_id(id)
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
        // Currently Target.svelte and Parameters.svelte are the only views where it's used
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
        path = "/secret-backends/:id/usage",
        method = "get",
        operation_id = "get_secret_reference_usage"
    )]
    async fn api_get_secret_reference_usage(
        &self,
        Path(id): Path<Uuid>,
        admin: AdminContext,
    ) -> Result<GetSecretReferenceUsageResponse, WarpgateError> {
        // Currently Target.svelte and Parameters.svelte are the only views where it's used
        admin.require(AdminPermission::TargetsEdit)?;
        let services = admin.services();

        let Some(model) = SecretBackend::Entity::find_by_id(id)
            .one(&services.db)
            .await?
        else {
            return Ok(GetSecretReferenceUsageResponse::NotFound);
        };

        let mut usage: Vec<SecretReferenceUsage> =
            existing_references_to_backend(&services.db, &model.name)
                .await?
                .into_iter()
                .map(|(reference, usages)| SecretReferenceUsage {
                    backend: model.name.clone(),
                    reference: reference.to_string(),
                    usages,
                })
                .collect();

        usage.sort_by(|a, b| a.reference.cmp(&b.reference));
        Ok(GetSecretReferenceUsageResponse::Ok(Json(usage)))
    }
}

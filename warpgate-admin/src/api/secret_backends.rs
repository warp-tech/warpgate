use std::collections::HashMap;
use std::str::FromStr;

use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Enum, Object, OpenApi};
use sea_orm::ActiveValue::NotSet;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, ModelTrait, QueryOrder, Set};
use uuid::Uuid;
use warpgate_common::encryption::idempotent_maybe_encrypt_secret;
use warpgate_common::secrets::validate_backend_name;
use warpgate_common::{
    AdminPermission, BackendType, Secret, SecretError, SecretRef, SecretResolver as _,
    TargetOptions, VaultAuthMethod, WarpgateError,
};
use warpgate_db_entities::{Parameters, SecretBackend, SshClientKey, Target};

use super::AdminContext;
use crate::api::common::is_unique_violation;

#[derive(Debug, Enum)]
#[oai(rename_all = "lowercase")]
pub enum HealthStatus {
    Ok,
    Error,
}

#[derive(Object)]
pub struct SecretBackendResponse {
    pub id: Uuid,
    pub name: String,
    pub backend_type: BackendType,
    pub address: String,
    pub namespace: Option<String>,
    pub auth_method: VaultAuthMethod,
    /// Empty means the method's default mount
    pub auth_mount: String,
    pub app_role_id: Option<String>,
    pub kubernetes_role: Option<String>,
    pub tls_skip_verify: bool,
    pub allowed_paths: Vec<String>,
}

impl TryFrom<SecretBackend::Model> for SecretBackendResponse {
    type Error = WarpgateError;

    fn try_from(model: SecretBackend::Model) -> Result<Self, WarpgateError> {
        Ok(Self {
            backend_type: model.backend_type()?,
            auth_method: model.auth_method()?,
            allowed_paths: model.allowed_paths(),
            id: model.id,
            name: model.name,
            address: model.address,
            namespace: model.namespace,
            auth_mount: model.auth_mount,
            app_role_id: model.app_role_id,
            kubernetes_role: model.kubernetes_role,
            tls_skip_verify: model.tls_skip_verify,
        })
    }
}

/// Shared by create and update. The secret fields are write-only: mandatory
/// when the row holds none for the chosen method, kept when omitted otherwise.
#[derive(Object)]
pub struct SecretBackendRequest {
    #[oai(validator(min_length = 1, max_length = 64, pattern = r"^[A-Za-z0-9._-]+$"))]
    pub name: String,
    pub backend_type: BackendType,
    #[oai(validator(min_length = 1, max_length = 2048))]
    pub address: String,
    #[oai(validator(max_length = 255))]
    pub namespace: Option<String>,
    pub auth_method: VaultAuthMethod,
    #[oai(validator(max_length = 255))]
    pub auth_mount: Option<String>,
    pub token: Option<Secret<String>>,
    #[oai(validator(max_length = 255))]
    pub app_role_id: Option<String>,
    pub app_role_secret_id: Option<Secret<String>>,
    #[oai(validator(max_length = 255))]
    pub kubernetes_role: Option<String>,
    #[oai(default)]
    pub tls_skip_verify: bool,
    /// KV path prefixes (`mount/path`), matched on whole segments
    #[oai(default, validator(max_items = 256, max_length = 1024))]
    pub allowed_paths: Vec<String>,
}

#[derive(Object)]
pub struct CheckHealthResponse {
    pub health: HealthStatus,
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
    pub target_count: u32,
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
            SecretError::Unresolved(_) | SecretError::Backend(_) => Self::BadGateway(message),
        }
    }
}

#[derive(ApiResponse)]
enum GetSecretReferenceUsageResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<SecretReferenceUsage>>),
}

const NAME_TAKEN: &str = "A secret backend with this name already exists";

/// Copies a request onto a row. A secret is mandatory when the row has none
/// stored for the chosen method; omitting it otherwise keeps the stored value.
fn apply_request(
    model: &mut SecretBackend::ActiveModel,
    body: &SecretBackendRequest,
    existing: Option<&SecretBackend::Model>,
) -> Result<(), String> {
    validate_backend_name(&body.name).map_err(|e| e.to_string())?;
    if body.allowed_paths.iter().any(|p| p.contains('\n')) {
        return Err("An allowed path cannot contain a line break".into());
    }

    let stored = |column: fn(&SecretBackend::Model) -> &Option<String>| {
        existing.is_some_and(|m| m.auth_method == body.auth_method.as_str() && column(m).is_some())
    };
    let secret = |what: &str, value: &Option<Secret<String>>, keep: bool| -> Result<_, String> {
        match value {
            Some(s) => Ok(Set(Some(
                idempotent_maybe_encrypt_secret(s.expose_secret()).map_err(|e| e.to_string())?,
            ))),
            None if keep => Ok(NotSet),
            None => Err(format!("{what} is required for this authentication method")),
        }
    };
    let required = |what: &str, present: bool| -> Result<(), String> {
        if present {
            Ok(())
        } else {
            Err(format!("{what} is required for this authentication method"))
        }
    };

    let mut token = Set(None);
    let mut app_role_id = Set(None);
    let mut app_role_secret_id = Set(None);
    let mut kubernetes_role = Set(None);
    match body.auth_method {
        VaultAuthMethod::Token => {
            token = secret("A token", &body.token, stored(|m| &m.token))?;
        }
        VaultAuthMethod::AppRole => {
            required("The AppRole role ID", body.app_role_id.is_some())?;
            app_role_id = Set(body.app_role_id.clone());
            app_role_secret_id = secret(
                "The AppRole secret ID",
                &body.app_role_secret_id,
                stored(|m| &m.app_role_secret_id),
            )?;
        }
        VaultAuthMethod::Kubernetes => {
            required("The Kubernetes role", body.kubernetes_role.is_some())?;
            kubernetes_role = Set(body.kubernetes_role.clone());
        }
    }

    model.name = Set(body.name.clone());
    model.backend_type = Set(body.backend_type.as_str().to_owned());
    model.address = Set(body.address.clone());
    model.namespace = Set(body.namespace.clone().filter(|ns| !ns.is_empty()));
    model.auth_method = Set(body.auth_method.as_str().to_owned());
    model.auth_mount = Set(body.auth_mount.clone().unwrap_or_default());
    model.token = token;
    model.app_role_id = app_role_id;
    model.app_role_secret_id = app_role_secret_id;
    model.kubernetes_role = kubernetes_role;
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
        && reference
            .parse::<SecretRef>()
            .is_ok_and(|r| r.backend == name)
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
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()?;
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
            Ok(model) => Ok(CreateSecretBackendResponse::Created(Json(
                model.try_into()?,
            ))),
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
            Some(model) => Ok(GetSecretBackendResponse::Ok(Json(model.try_into()?))),
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
            Ok(model) => Ok(UpdateSecretBackendResponse::Ok(Json(model.try_into()?))),
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

        let (health, error) = match services.secret_backends.health_of(&model.name).await {
            Ok(()) => (HealthStatus::Ok, None),
            Err(e) => (HealthStatus::Error, Some(e.to_string())),
        };
        Ok(CheckHealthApiResponse::Ok(Json(CheckHealthResponse {
            health,
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
                        target_count: 0,
                        targets: Vec::new(),
                    });
                // A target may reference the same secret from more than one field; count it once.
                if !entry.targets.iter().any(|t| t.id == target.id) {
                    entry.targets.push(SecretReferenceUsageTarget {
                        id: target.id,
                        name: target.name.clone(),
                    });
                    entry.target_count += 1;
                }
            }
        }

        let mut usage: Vec<SecretReferenceUsage> = usage.into_values().collect();
        usage.sort_by(|a, b| a.reference.cmp(&b.reference));
        Ok(GetSecretReferenceUsageResponse::Ok(Json(usage)))
    }
}

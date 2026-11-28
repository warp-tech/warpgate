use std::collections::HashMap;
use std::fmt::Display;
use std::str::FromStr;

use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi, Union};
use sea_orm::{
    ActiveModelTrait, ConnectionTrait, DatabaseConnection, EntityTrait, ModelTrait, QueryOrder, Set,
};
use serde::Serialize;
use uuid::Uuid;
use warpgate_common::secrets::validate_backend_name;
use warpgate_common::{
    AdminPermission, BackendType, SecretError, SecretRef, SecretResolver as _, StoredSecret,
    StoredSecrets, VaultAuthConfig, WarpgateError,
};
use warpgate_core::resources::audit::{self, Audited, ComparableValues, RowKind, Subject};
use warpgate_db_entities::{SecretBackend, SshClientKey, Target};

use super::AdminContext;
use crate::api::common::is_unique_violation;

#[derive(Serialize, Object)]
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

/// The audit log compares the fields of `SecretBackendModel`, with the stored
/// `auth` secret as a credential
struct Audit<'a>(&'a SecretBackend::Model);

impl Audited for Audit<'_> {
    fn subject(&self) -> Subject {
        Subject::Row(RowKind::SecretBackend, self.0.id)
    }

    fn name(&self) -> String {
        self.0.name.clone()
    }

    async fn compared<C: ConnectionTrait>(
        &self,
        _db: &C,
    ) -> Result<ComparableValues, WarpgateError> {
        let redacted = SecretBackendModel::from(self.0.clone());
        let stored = SecretBackendModel {
            auth: self.0.auth.clone(),
            ..self.0.clone().into()
        };
        audit::columns(&stored, &redacted)
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
    /// Path prefixes the backend may be used for, matched on whole segments:
    /// `mount/path` for KV secrets, `mount/sign/role` for SSH certificate
    /// signing. Empty allows any.
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
    pub id: warpgate_common::TargetId,
    pub name: String,
}

#[derive(Object)]
pub struct SecretReferenceUsageSshClientKey {
    pub id: warpgate_common::SshClientKeyId,
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
            SecretError::InvalidRef(_)
            | SecretError::InvalidBackendName(_)
            | SecretError::InvalidSshSigningRequest(_) => Self::BadRequest(message),
            SecretError::PathNotAllowed { .. } => Self::Forbidden(message),
            SecretError::BackendNotConfigured { .. } | SecretError::NotFound { .. } => {
                Self::NotFound(message)
            }
            SecretError::Backend(_) | SecretError::SshSigning { .. } => Self::BadGateway(message),
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

    // A blank login secret keeps the stored one. A caller must not be able to
    // redirect it to another server or to an unverified connection
    let stored = existing.and_then(|existing| existing.auth.secret());
    let same_destination = existing.is_some_and(|existing| {
        // Every field is listed so that a new one does not compile until it
        // is either compared or ignored here
        let SecretBackend::Model {
            address,
            namespace,
            auth,
            tls_skip_verify,
            id: _,
            name: _,
            backend_type: _,
            allowed_paths: _,
        } = existing;
        *address == body.address
            && *namespace == body.namespace
            && auth.redacted() == body.auth.redacted()
            && (*tls_skip_verify || !body.tls_skip_verify)
    });

    let mut auth = body.auth.clone();
    if let Some(provided_secret) = auth.secret_mut() {
        let provided_value = provided_secret.stored_value();
        *provided_secret = if !provided_value.is_empty() {
            StoredSecret::encrypted(provided_value.to_owned())?
        } else if let Some(stored) = stored.filter(|_| same_destination) {
            stored.clone()
        } else {
            return Err(WarpgateError::InvalidRequest(
                if stored.is_some() {
                    "The login secret is required when changing the address, namespace or authentication settings, or disabling TLS verification"
                } else {
                    "The login secret is required for this authentication method"
                }
                .into(),
            ));
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
            for secret in target.options.secret_references() {
                if secret.backend == backend_name {
                    found
                        .entry(secret)
                        .or_default()
                        .push(SecretReferenceUsageInstance::Target(
                            SecretReferenceUsageTarget {
                                id: target.id,
                                name: target.name.clone(),
                            },
                        ));
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
            Ok(model) => {
                audit::created(db, admin.changed_by(), &Audit(&model)).await;
                Ok(CreateSecretBackendResponse::Created(Json(model.into())))
            }
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
        admin.require(AdminPermission::ConfigEdit)?;

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
            Ok(model) => {
                audit::updated(db, admin.changed_by(), &Audit(&existing), &Audit(&model)).await;
                Ok(UpdateSecretBackendResponse::Ok(Json(model.into())))
            }
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
        model.clone().delete(db).await?;
        audit::deleted(admin.changed_by(), &Audit(&model));
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

#[cfg(test)]
mod tests {
    use sea_orm::ActiveValue;
    use uuid::Uuid;
    use warpgate_common::secrets::{
        BackendType, VaultAppRoleAuth, VaultAuthConfig, VaultTokenAuth,
    };
    use warpgate_db_entities::SecretBackend;

    use super::{SecretBackendRequest, update_active_model};

    fn stored() -> SecretBackend::Model {
        SecretBackend::Model {
            id: Uuid::nil(),
            name: "vault".into(),
            backend_type: BackendType::Vault,
            address: "https://vault.example".into(),
            namespace: None,
            auth: token("stored-token"),
            tls_skip_verify: false,
            allowed_paths: String::new(),
        }
    }

    fn token(token: &str) -> VaultAuthConfig {
        VaultAuthConfig::Token(VaultTokenAuth {
            token: token.to_owned().into(),
        })
    }

    /// Updates `stored` with a blank token and `edit` applied. Returns the
    /// saved token, or `None` if the update is refused
    fn update(
        stored: &SecretBackend::Model,
        edit: impl FnOnce(&mut SecretBackendRequest),
    ) -> Option<String> {
        let mut body = SecretBackendRequest {
            name: stored.name.clone(),
            backend_type: stored.backend_type,
            address: stored.address.clone(),
            namespace: stored.namespace.clone(),
            auth: token(""),
            tls_skip_verify: stored.tls_skip_verify,
            allowed_paths: vec![],
        };
        edit(&mut body);
        let mut model = SecretBackend::ActiveModel::default();
        update_active_model(&mut model, &body, Some(stored)).ok()?;
        let ActiveValue::Set(auth) = model.auth else {
            return None;
        };
        auth.secret().map(|s| s.stored_value().to_owned())
    }

    #[test]
    fn a_blank_login_secret_keeps_the_stored_one() {
        let kept = Some("stored-token".to_owned());
        assert_eq!(update(&stored(), |_| {}), kept);
        assert_eq!(update(&stored(), |b| b.name = "renamed".into()), kept);
        assert_eq!(
            update(&stored(), |b| b.allowed_paths = vec!["kv/a".into()]),
            kept
        );

        let unverified = SecretBackend::Model {
            tls_skip_verify: true,
            ..stored()
        };
        assert_eq!(update(&unverified, |b| b.tls_skip_verify = false), kept);
    }

    #[test]
    fn a_stored_login_secret_does_not_follow_a_change_of_destination() {
        assert_eq!(
            update(&stored(), |b| b.address =
                "https://elsewhere.example".into()),
            None
        );
        assert_eq!(
            update(&stored(), |b| b.namespace = Some("other".into())),
            None
        );
        assert_eq!(update(&stored(), |b| b.tls_skip_verify = true), None);
    }

    #[test]
    fn a_stored_login_secret_does_not_follow_a_change_of_auth_settings() {
        let approle = |mount: Option<&str>, secret_id: &str| {
            VaultAuthConfig::AppRole(VaultAppRoleAuth {
                role_id: "role".into(),
                secret_id: secret_id.to_owned().into(),
                mount: mount.map(Into::into),
            })
        };
        let stored = SecretBackend::Model {
            auth: approle(None, "stored-secret-id"),
            ..stored()
        };
        assert_eq!(
            update(&stored, |b| b.auth = approle(None, "")),
            Some("stored-secret-id".into())
        );
        assert_eq!(
            update(&stored, |b| b.auth = approle(Some("other"), "")),
            None
        );
        assert_eq!(update(&stored, |_| {}), None);
    }
}

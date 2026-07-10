use std::collections::HashMap;
use std::str::FromStr;

use poem::web::Data;
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Enum, Object, OpenApi};
use sea_orm::EntityTrait;
use uuid::Uuid;
use warpgate_common::{BackendType, SecretRef, TargetOptions, WarpgateError};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_db_entities::Target;
use tracing::debug;

use super::AnySecurityScheme;
use crate::api::common::require_admin_permission;

#[derive(Debug, Enum)]
#[oai(rename_all = "lowercase")]
pub enum SecretBackendType {
    Vault,
    Openbao,
}

#[derive(Debug, Enum)]
#[oai(rename_all = "lowercase")]
pub enum HealthStatus {
    Ok,
    Error,
    Unknown,
}

#[derive(Debug, Object)]
pub struct SecretBackendStatus {
    pub name: String,
    #[oai(rename = "backendType")]
    pub backend_type: SecretBackendType,
    pub address: String,
    pub namespace: Option<String>,
    pub health: HealthStatus,
    pub health_error: Option<String>,
}

#[derive(Object)]
pub struct CheckHealthResponse {
    pub health: HealthStatus,
    pub error: Option<String>,
}

#[derive(Object)]
pub struct TestResolveRequest {
    pub reference: String,
}

#[derive(Object)]
pub struct TestResolveResponse {
    pub ok: bool,
    pub error: Option<String>,
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
    Ok(Json<Vec<SecretBackendStatus>>),
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
    #[oai(status = 200)]
    Ok(Json<TestResolveResponse>),
    #[oai(status = 400)]
    BadRequest,
}

#[derive(ApiResponse)]
enum GetSecretReferenceUsageResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<SecretReferenceUsage>>),
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
        ctx: Data<&AuthenticatedRequestContext>,
        _sec: AnySecurityScheme,
    ) -> Result<GetSecretBackendsResponse, WarpgateError> {
        require_admin_permission(&ctx, None).await?;

        let backend_configs = {
            let config = ctx.services().config.lock().await;
            config.store.secrets.backends.clone()
        };

        let secret_backend = ctx.services().secret_backend.clone();

        let statuses = futures::future::join_all(backend_configs.into_iter().map(|bc| {
            let secret_backend = secret_backend.clone();
            async move {
                let (health, health_error) = match secret_backend.health_for(&bc.name).await {
                    Ok(()) => (HealthStatus::Ok, None),
                    Err(e) => (HealthStatus::Error, Some(e.to_string())),
                };
                SecretBackendStatus {
                    backend_type: match bc.backend_type {
                        BackendType::Vault => SecretBackendType::Vault,
                        BackendType::OpenBao => SecretBackendType::Openbao,
                    },
                    address: bc.address,
                    namespace: bc.namespace,
                    name: bc.name,
                    health,
                    health_error,
                }
            }
        }))
        .await;

        Ok(GetSecretBackendsResponse::Ok(Json(statuses)))
    }

    #[oai(
        path = "/secret-backends/resolve-test",
        method = "post",
        operation_id = "test_secret_resolve"
    )]
    async fn api_test_secret_resolve(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        _sec: AnySecurityScheme,
        body: Json<TestResolveRequest>,
    ) -> Result<TestResolveApiResponse, WarpgateError> {
        require_admin_permission(&ctx, None).await?;
        debug!("Testing secret resolve for reference: {}", body.reference);

        let secret_ref = match SecretRef::from_str(&body.reference) {
            Ok(r) => r,
            Err(_) => return Ok(TestResolveApiResponse::BadRequest),
        };

        debug!("Parsed secret reference: {:?}", secret_ref);

        let backend = ctx.services().secret_backend.clone();
        let (ok, error) = match backend.resolve(&secret_ref).await {
            Ok(_) => (true, None),
            Err(e) => (false, Some(e.to_string())),
        };

        debug!(ok = ok, error = ?error, "Secret resolve test result for reference: {}", body.reference);

        Ok(TestResolveApiResponse::Ok(Json(TestResolveResponse {
            ok,
            error,
        })))
    }

    #[oai(
        path = "/secret-backends/usage",
        method = "get",
        operation_id = "get_secret_reference_usage"
    )]
    async fn api_get_secret_reference_usage(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        _sec: AnySecurityScheme,
    ) -> Result<GetSecretReferenceUsageResponse, WarpgateError> {
        require_admin_permission(&ctx, None).await?;

        let targets = {
            let db = ctx.services().db.lock().await;
            Target::Entity::find().all(&*db).await?
        };

        let mut usage: HashMap<String, SecretReferenceUsage> = HashMap::new();
        for target in targets {
            // Skip targets whose options can't be parsed rather than failing the whole report.
            let Ok(options) = serde_json::from_value::<TargetOptions>(target.options) else {
                continue;
            };
            for reference in options.secret_references() {
                let key = reference.to_string();
                let entry = usage.entry(key.clone()).or_insert_with(|| SecretReferenceUsage {
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

    #[oai(
        path = "/secret-backends/:name/health",
        method = "post",
        operation_id = "check_secret_backend_health"
    )]
    async fn api_check_backend_health(
        &self,
        name: Path<String>,
        ctx: Data<&AuthenticatedRequestContext>,
        _sec: AnySecurityScheme,
    ) -> Result<CheckHealthApiResponse, WarpgateError> {
        require_admin_permission(&ctx, None).await?;

        let exists = {
            let config = ctx.services().config.lock().await;
            config.store.secrets.backends.iter().any(|b| b.name == *name)
        };

        if !exists {
            return Ok(CheckHealthApiResponse::NotFound);
        }

        let secret_backend = ctx.services().secret_backend.clone();
        let (health, error) = match secret_backend.health_for(&name).await {
            Ok(()) => (HealthStatus::Ok, None),
            Err(e) => (HealthStatus::Error, Some(e.to_string())),
        };

        Ok(CheckHealthApiResponse::Ok(Json(CheckHealthResponse {
            health,
            error,
        })))
    }
}

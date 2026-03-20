use std::sync::Arc;

use anyhow::anyhow;
use chrono::Utc;
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder};
use tokio::sync::Mutex;
use tracing::*;
use uuid::Uuid;
use warpgate_common::helpers::hash::generate_ticket_secret;
use warpgate_common::{Secret, WarpgateError};
use warpgate_db_entities::TicketRequest::TicketRequestStatus;
use warpgate_db_entities::{Parameters, Target, Ticket, TicketRequest};

use crate::{ConfigProvider, ConfigProviderEnum};

pub struct TicketRequestResult {
    pub request: TicketRequest::Model,
    pub secret: Option<Secret<String>>,
}

pub struct CreateTicketRequestParams {
    pub user_id: Uuid,
    pub username: String,
    pub target_name: String,
    pub duration_seconds: Option<i64>,
    pub uses: Option<i16>,
    pub description: String,
}

/// Validation error for ticket request operations.
/// These are expected user errors (not server bugs), so they should map to HTTP 400.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct TicketRequestValidationError(pub String);

fn validation_err(msg: impl Into<String>) -> TicketRequestValidationError {
    TicketRequestValidationError(msg.into())
}

pub async fn create_ticket_request(
    db: &Arc<Mutex<sea_orm::DatabaseConnection>>,
    config_provider: &Arc<Mutex<ConfigProviderEnum>>,
    params: CreateTicketRequestParams,
) -> Result<TicketRequestResult, TicketRequestValidationError> {
    let db_conn = db.lock().await;

    let policy = Parameters::Entity::get(&db_conn)
        .await
        .map_err(|e| validation_err(e.to_string()))?;

    if !policy.ticket_self_service_enabled {
        return Err(validation_err("Self-service tickets are not enabled"));
    }

    // Validate target exists and get per-target settings
    let target = Target::Entity::find()
        .filter(Target::Column::Name.eq(&params.target_name))
        .one(&*db_conn)
        .await
        .map_err(|e| validation_err(e.to_string()))?;

    let Some(target) = target else {
        return Err(validation_err("Target not found"));
    };

    // Validate description requirement
    if policy.ticket_require_description && params.description.trim().is_empty() {
        return Err(validation_err("A description is required for ticket requests"));
    }

    // Validate description length
    if params.description.len() > 2000 {
        return Err(validation_err("Description must be 2000 characters or fewer"));
    }

    // Validate duration
    if let Some(duration) = params.duration_seconds {
        if duration <= 0 {
            return Err(validation_err("Duration must be a positive number"));
        }
        if duration < 60 {
            return Err(validation_err("Minimum ticket duration is 60 seconds"));
        }
        // Per-target limit takes priority, then global limit
        let max_duration = target
            .ticket_max_duration_seconds
            .or(policy.ticket_max_duration_seconds);
        if let Some(max_duration) = max_duration {
            if duration > max_duration {
                return Err(validation_err(format!(
                    "Requested duration exceeds maximum of {} seconds",
                    max_duration
                )));
            }
        }
    }

    // Validate uses
    if let Some(requested_uses) = params.uses {
        if requested_uses <= 0 {
            return Err(validation_err("Number of uses must be a positive number"));
        }
        if let Some(max_uses) = policy.ticket_max_uses {
            if requested_uses > max_uses {
                return Err(validation_err(format!(
                    "Requested uses exceeds maximum of {}",
                    max_uses
                )));
            }
        }
    }

    // Check if user has existing role-based access
    // Drop db lock before acquiring config_provider lock to avoid deadlock
    let has_access = {
        drop(db_conn);
        let mut cp = config_provider.lock().await;
        cp.authorize_target(&params.username, &params.target_name)
            .await
            .map_err(|e| validation_err(e.to_string()))?
    };

    // Re-acquire db lock
    let db_conn = db.lock().await;

    // Determine if this should be auto-approved
    let auto_approve = has_access && policy.ticket_auto_approve_existing_access;

    if auto_approve {
        let (ticket_id, secret) = insert_self_service_ticket(
            &*db_conn,
            &params.username,
            &params.target_name,
            params.duration_seconds,
            params.uses,
            &params.description,
        )
        .await
        .map_err(|e| validation_err(e.to_string()))?;

        let request_id = Uuid::new_v4();
        let request = TicketRequest::ActiveModel {
            id: Set(request_id),
            user_id: Set(params.user_id),
            username: Set(params.username.clone()),
            target_name: Set(params.target_name.clone()),
            requested_duration_seconds: Set(params.duration_seconds),
            requested_uses: Set(params.uses),
            description: Set(params.description),
            status: Set(TicketRequestStatus::Approved),
            resolved_by_username: Set(Some("system".to_string())),
            ticket_id: Set(Some(ticket_id)),
            created: Set(Utc::now()),
            resolved_at: Set(Some(Utc::now())),
            deny_reason: Set(None),
        };
        let request_model = request
            .insert(&*db_conn)
            .await
            .map_err(|e| validation_err(e.to_string()))?;

        info!(
            "Auto-approved ticket request {} for user {} to target {}",
            request_id, params.username, params.target_name
        );

        Ok(TicketRequestResult {
            request: request_model,
            secret: Some(secret),
        })
    } else {
        let request_id = Uuid::new_v4();
        let request = TicketRequest::ActiveModel {
            id: Set(request_id),
            user_id: Set(params.user_id),
            username: Set(params.username.clone()),
            target_name: Set(params.target_name.clone()),
            requested_duration_seconds: Set(params.duration_seconds),
            requested_uses: Set(params.uses),
            description: Set(params.description),
            status: Set(TicketRequestStatus::Pending),
            resolved_by_username: Set(None),
            ticket_id: Set(None),
            created: Set(Utc::now()),
            resolved_at: Set(None),
            deny_reason: Set(None),
        };
        let request_model = request
            .insert(&*db_conn)
            .await
            .map_err(|e| validation_err(e.to_string()))?;

        info!(
            "Created pending ticket request {} for user {} to target {}",
            request_id, params.username, params.target_name
        );

        Ok(TicketRequestResult {
            request: request_model,
            secret: None,
        })
    }
}

/// Shared helper to create a self-service ticket in the database.
/// Used by both auto-approve and admin-approve flows.
async fn insert_self_service_ticket(
    db_conn: &sea_orm::DatabaseConnection,
    username: &str,
    target_name: &str,
    duration_seconds: Option<i64>,
    uses: Option<i16>,
    description: &str,
) -> Result<(Uuid, Secret<String>), WarpgateError> {
    let secret = generate_ticket_secret();
    let ticket_id = Uuid::new_v4();
    let expiry = duration_seconds.and_then(|d| {
        chrono::Duration::try_seconds(d).map(|dur| Utc::now() + dur)
    });

    let ticket = Ticket::ActiveModel {
        id: Set(ticket_id),
        secret: Set(secret.expose_secret().to_string()),
        username: Set(username.to_string()),
        target: Set(target_name.to_string()),
        created: Set(Utc::now()),
        expiry: Set(expiry),
        uses_left: Set(uses),
        description: Set(description.to_string()),
        self_service: Set(true),
    };
    ticket.insert(db_conn).await?;

    Ok((ticket_id, secret))
}

pub async fn approve_ticket_request(
    db: &Arc<Mutex<sea_orm::DatabaseConnection>>,
    request_id: Uuid,
    admin_username: &str,
) -> Result<Option<(TicketRequest::Model, Secret<String>)>, WarpgateError> {
    let db_conn = db.lock().await;

    let Some(request) = TicketRequest::Entity::find_by_id(request_id)
        .filter(TicketRequest::Column::Status.eq(TicketRequestStatus::Pending))
        .one(&*db_conn)
        .await?
    else {
        return Ok(None);
    };

    // Verify user still exists
    let user_exists = warpgate_db_entities::User::Entity::find()
        .filter(warpgate_db_entities::User::Column::Username.eq(&request.username))
        .count(&*db_conn)
        .await?
        > 0;

    if !user_exists {
        return Err(WarpgateError::UserNotFound(request.username.clone()));
    }

    // Verify target still exists
    let target_exists = Target::Entity::find()
        .filter(Target::Column::Name.eq(&request.target_name))
        .count(&*db_conn)
        .await?
        > 0;

    if !target_exists {
        return Err(WarpgateError::from(anyhow!("Target no longer exists")));
    }

    let (ticket_id, secret) = insert_self_service_ticket(
        &*db_conn,
        &request.username,
        &request.target_name,
        request.requested_duration_seconds,
        request.requested_uses,
        &request.description,
    )
    .await?;

    let mut active: TicketRequest::ActiveModel = request.into();
    active.status = Set(TicketRequestStatus::Approved);
    active.resolved_by_username = Set(Some(admin_username.to_string()));
    active.ticket_id = Set(Some(ticket_id));
    active.resolved_at = Set(Some(Utc::now()));
    let updated = active.update(&*db_conn).await?;

    info!(
        "Admin {} approved ticket request {}",
        admin_username, request_id
    );

    Ok(Some((updated, secret)))
}

pub async fn deny_ticket_request(
    db: &Arc<Mutex<sea_orm::DatabaseConnection>>,
    request_id: Uuid,
    admin_username: &str,
    reason: Option<String>,
) -> Result<Option<TicketRequest::Model>, WarpgateError> {
    let db_conn = db.lock().await;

    let Some(request) = TicketRequest::Entity::find_by_id(request_id)
        .filter(TicketRequest::Column::Status.eq(TicketRequestStatus::Pending))
        .one(&*db_conn)
        .await?
    else {
        return Ok(None);
    };

    let mut active: TicketRequest::ActiveModel = request.into();
    active.status = Set(TicketRequestStatus::Denied);
    active.resolved_by_username = Set(Some(admin_username.to_string()));
    active.resolved_at = Set(Some(Utc::now()));
    active.deny_reason = Set(reason);
    let updated = active.update(&*db_conn).await?;

    info!(
        "Admin {} denied ticket request {}",
        admin_username, request_id
    );

    Ok(Some(updated))
}

pub async fn list_ticket_requests(
    db: &Arc<Mutex<sea_orm::DatabaseConnection>>,
    status_filter: Option<TicketRequestStatus>,
) -> Result<Vec<TicketRequest::Model>, WarpgateError> {
    let db_conn = db.lock().await;
    let mut query = TicketRequest::Entity::find().order_by_desc(TicketRequest::Column::Created);

    if let Some(status) = status_filter {
        query = query.filter(TicketRequest::Column::Status.eq(status));
    }

    Ok(query.all(&*db_conn).await?)
}


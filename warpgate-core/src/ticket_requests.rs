use std::sync::Arc;

use anyhow::anyhow;
use sea_orm::ActiveValue::Set;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
};
use time::{Duration, OffsetDateTime};
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
    pub description: String,
}

#[derive(Debug)]
pub enum CreateTicketRequestError {
    InvalidInput(String),
    Internal(WarpgateError),
}

impl From<sea_orm::DbErr> for CreateTicketRequestError {
    fn from(e: sea_orm::DbErr) -> Self {
        Self::Internal(e.into())
    }
}

impl From<WarpgateError> for CreateTicketRequestError {
    fn from(e: WarpgateError) -> Self {
        Self::Internal(e)
    }
}

pub async fn create_ticket_request(
    db: &Arc<Mutex<sea_orm::DatabaseConnection>>,
    config_provider: &Arc<Mutex<ConfigProviderEnum>>,
    params: CreateTicketRequestParams,
) -> Result<TicketRequestResult, CreateTicketRequestError> {
    let db_conn = db.lock().await;

    let policy = Parameters::Entity::get(&db_conn).await?;

    if !policy.ticket_self_service_enabled {
        return Err(CreateTicketRequestError::InvalidInput(
            "Self-service tickets are not enabled".into(),
        ));
    }

    let target = Target::Entity::find()
        .filter(Target::Column::Name.eq(&params.target_name))
        .one(&*db_conn)
        .await?;

    let Some(target) = target else {
        return Err(CreateTicketRequestError::InvalidInput(
            "Target not found".into(),
        ));
    };

    let has_access = {
        // Must drop db_conn before locking config_provider to avoid deadlock
        drop(db_conn);
        let mut cp = config_provider.lock().await;
        cp.authorize_target(&params.username, &params.target_name)
            .await?
    };

    // Return generic "not found" to avoid revealing target existence to unauthorized users
    if !policy.ticket_request_show_all_targets && !has_access {
        return Err(CreateTicketRequestError::InvalidInput(
            "Target not found".into(),
        ));
    }

    if target.ticket_requests_disabled {
        return Err(CreateTicketRequestError::InvalidInput(
            "Ticket requests are not allowed for this target".into(),
        ));
    }

    if policy.ticket_require_description && params.description.trim().is_empty() {
        return Err(CreateTicketRequestError::InvalidInput(
            "A description is required for ticket requests".into(),
        ));
    }

    if params.description.chars().count() > 2000 {
        return Err(CreateTicketRequestError::InvalidInput(
            "Description must be 2000 characters or fewer".into(),
        ));
    }

    let max_duration = target
        .ticket_max_duration_seconds
        .or(policy.ticket_max_duration_seconds);
    let effective_duration = match params.duration_seconds {
        Some(duration) => {
            if duration <= 0 {
                return Err(CreateTicketRequestError::InvalidInput(
                    "Duration must be a positive number".into(),
                ));
            }
            if duration < 60 {
                return Err(CreateTicketRequestError::InvalidInput(
                    "Minimum ticket duration is 60 seconds".into(),
                ));
            }
            if let Some(max_duration) = max_duration {
                if duration > max_duration {
                    return Err(CreateTicketRequestError::InvalidInput(format!(
                        "Requested duration exceeds maximum of {} seconds",
                        max_duration
                    )));
                }
            }
            Some(duration)
        }
        None => max_duration,
    };

    // Uses are always admin-controlled (target-level or global policy), not user-specified
    let effective_uses = target.ticket_max_uses.or(policy.ticket_max_uses);

    let db_conn = db.lock().await;

    let existing_pending = TicketRequest::Entity::find()
        .filter(TicketRequest::Column::UserId.eq(params.user_id))
        .filter(TicketRequest::Column::TargetId.eq(target.id))
        .filter(TicketRequest::Column::Status.eq(TicketRequestStatus::Pending))
        .count(&*db_conn)
        .await?;

    if existing_pending > 0 {
        return Err(CreateTicketRequestError::InvalidInput(
            "You already have a pending request for this target".into(),
        ));
    }

    let auto_approve =
        has_access && policy.ticket_auto_approve_existing_access && !target.ticket_require_approval;

    if auto_approve {
        let (ticket_id, secret) = insert_self_service_ticket(
            &*db_conn,
            params.user_id,
            target.id,
            effective_duration,
            effective_uses,
            &params.description,
            true,
        )
        .await?;

        let request_id = Uuid::new_v4();
        let request = TicketRequest::ActiveModel {
            id: Set(request_id),
            user_id: Set(params.user_id),
            target_id: Set(target.id),
            requested_duration_seconds: Set(effective_duration),
            description: Set(params.description),
            status: Set(TicketRequestStatus::Approved),
            resolved_by_user_id: Set(None),
            ticket_id: Set(Some(ticket_id)),
            created: Set(OffsetDateTime::now_utc()),
            resolved_at: Set(Some(OffsetDateTime::now_utc())),
            deny_reason: Set(None),
        };
        let request_model = request.insert(&*db_conn).await?;

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
            target_id: Set(target.id),
            requested_duration_seconds: Set(effective_duration),
            description: Set(params.description),
            status: Set(TicketRequestStatus::Pending),
            resolved_by_user_id: Set(None),
            ticket_id: Set(None),
            created: Set(OffsetDateTime::now_utc()),
            resolved_at: Set(None),
            deny_reason: Set(None),
        };
        let request_model = request.insert(&*db_conn).await?;

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

async fn insert_self_service_ticket(
    db_conn: &sea_orm::DatabaseConnection,
    user_id: Uuid,
    target_id: Uuid,
    duration_seconds: Option<i64>,
    uses: Option<i16>,
    description: &str,
    self_service: bool,
) -> Result<(Uuid, Secret<String>), WarpgateError> {
    let secret = generate_ticket_secret();
    let ticket_id = Uuid::new_v4();
    let expiry = duration_seconds.map(|d| OffsetDateTime::now_utc() + Duration::seconds(d));

    let ticket = Ticket::ActiveModel {
        id: Set(ticket_id),
        secret: Set(secret.expose_secret().to_string()),
        user_id: Set(user_id),
        target_id: Set(target_id),
        created: Set(OffsetDateTime::now_utc()),
        expiry: Set(expiry),
        uses_left: Set(uses),
        description: Set(description.to_string()),
        self_service: Set(self_service),
    };
    ticket.insert(db_conn).await?;

    Ok((ticket_id, secret))
}

pub async fn approve_ticket_request(
    db: &Arc<Mutex<sea_orm::DatabaseConnection>>,
    request_id: Uuid,
    admin_user_id: Uuid,
) -> Result<Option<TicketRequest::Model>, WarpgateError> {
    let db_conn = db.lock().await;

    let Some(request) = TicketRequest::Entity::find_by_id(request_id)
        .filter(TicketRequest::Column::Status.eq(TicketRequestStatus::Pending))
        .one(&*db_conn)
        .await?
    else {
        return Ok(None);
    };

    let user_exists = warpgate_db_entities::User::Entity::find_by_id(request.user_id)
        .count(&*db_conn)
        .await?
        > 0;

    if !user_exists {
        return Err(WarpgateError::UserNotFound(request.user_id.to_string()));
    }

    let target_exists = Target::Entity::find_by_id(request.target_id)
        .count(&*db_conn)
        .await?
        > 0;

    if !target_exists {
        return Err(WarpgateError::from(anyhow!("Target no longer exists")));
    }

    let mut active: TicketRequest::ActiveModel = request.into();
    active.status = Set(TicketRequestStatus::Approved);
    active.resolved_by_user_id = Set(Some(admin_user_id));
    active.resolved_at = Set(Some(OffsetDateTime::now_utc()));
    let updated = active.update(&*db_conn).await?;

    info!(
        "Admin {} approved ticket request {}",
        admin_user_id, request_id
    );

    Ok(Some(updated))
}

#[derive(Debug)]
pub enum ActivateTicketRequestError {
    NotFound,
    AlreadyActivated,
    TargetGone,
    Internal(WarpgateError),
}

impl From<sea_orm::DbErr> for ActivateTicketRequestError {
    fn from(e: sea_orm::DbErr) -> Self {
        Self::Internal(e.into())
    }
}

impl From<WarpgateError> for ActivateTicketRequestError {
    fn from(e: WarpgateError) -> Self {
        Self::Internal(e)
    }
}

pub async fn activate_ticket_request(
    db: &Arc<Mutex<sea_orm::DatabaseConnection>>,
    request_id: Uuid,
    user_id: Uuid,
) -> Result<(TicketRequest::Model, Secret<String>), ActivateTicketRequestError> {
    let db_conn = db.lock().await;

    let Some(request) = TicketRequest::Entity::find_by_id(request_id)
        .filter(TicketRequest::Column::UserId.eq(user_id))
        .filter(TicketRequest::Column::Status.eq(TicketRequestStatus::Approved))
        .one(&*db_conn)
        .await?
    else {
        return Err(ActivateTicketRequestError::NotFound);
    };

    // Ticket is only created on activation, not on approval — this prevents
    // the duration clock from starting before the user is ready to connect
    if request.ticket_id.is_some() {
        return Err(ActivateTicketRequestError::AlreadyActivated);
    }

    let target = Target::Entity::find_by_id(request.target_id)
        .one(&*db_conn)
        .await?;

    let Some(target) = target else {
        return Err(ActivateTicketRequestError::TargetGone);
    };

    let policy = Parameters::Entity::get(&db_conn).await?;
    // Re-cap duration against current policy at activation time, in case
    // max duration was lowered between approval and activation
    let max_duration = target
        .ticket_max_duration_seconds
        .or(policy.ticket_max_duration_seconds);
    let effective_duration = match (request.requested_duration_seconds, max_duration) {
        (Some(d), Some(max)) => Some(d.min(max)),
        (Some(d), None) => Some(d),
        (None, max) => max,
    };

    let max_uses = target.ticket_max_uses.or(policy.ticket_max_uses);

    let (ticket_id, secret) = insert_self_service_ticket(
        &*db_conn,
        request.user_id,
        request.target_id,
        effective_duration,
        max_uses,
        &request.description,
        false,
    )
    .await?;

    let mut active: TicketRequest::ActiveModel = request.into();
    active.ticket_id = Set(Some(ticket_id));
    let updated = active.update(&*db_conn).await?;

    info!(
        "User activated approved ticket request {}, ticket {} created",
        request_id, ticket_id
    );

    Ok((updated, secret))
}

pub async fn deny_ticket_request(
    db: &Arc<Mutex<sea_orm::DatabaseConnection>>,
    request_id: Uuid,
    admin_user_id: Uuid,
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

    let reason = reason.map(|r| {
        if r.chars().count() > 2000 {
            r.chars().take(2000).collect::<String>()
        } else {
            r
        }
    });

    let mut active: TicketRequest::ActiveModel = request.into();
    active.status = Set(TicketRequestStatus::Denied);
    active.resolved_by_user_id = Set(Some(admin_user_id));
    active.resolved_at = Set(Some(OffsetDateTime::now_utc()));
    active.deny_reason = Set(reason);
    let updated = active.update(&*db_conn).await?;

    info!(
        "Admin {} denied ticket request {}",
        admin_user_id, request_id
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

use std::collections::{HashMap, HashSet};

use poem_openapi::Object;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::WarpgateError;
use warpgate_db_entities::TicketRequest::TicketRequestStatus;
use warpgate_db_entities::{Target, TicketRequest, User};

/// ticket request with resolved username and target name
#[derive(Debug, Clone, Serialize, Object)]
#[oai(rename = "TicketRequest")]
pub struct TicketRequestDetails {
    pub id: Uuid,
    pub user_id: Uuid,
    /// Empty if the user has been deleted
    pub username: Option<String>,
    pub target_id: Uuid,
    /// Empty if the target has been deleted
    pub target_name: Option<String>,
    pub requested_duration_seconds: Option<i64>,
    pub description: String,
    pub status: TicketRequestStatus,
    pub resolved_by_user_id: Option<Uuid>,
    pub resolved_by_username: Option<String>,
    pub ticket_id: Option<Uuid>,
    pub created: OffsetDateTime,
    pub resolved_at: Option<OffsetDateTime>,
    pub deny_reason: Option<String>,
}

pub async fn batch_resolve_ticket_request_names(
    db: &DatabaseConnection,
    requests: Vec<TicketRequest::Model>,
) -> Result<Vec<TicketRequestDetails>, WarpgateError> {
    if requests.is_empty() {
        return Ok(vec![]);
    }

    let user_ids: HashSet<Uuid> = requests
        .iter()
        .flat_map(|r| [Some(r.user_id), r.resolved_by_user_id])
        .flatten()
        .collect();
    let target_ids: HashSet<Uuid> = requests.iter().map(|r| r.target_id).collect();

    let usernames: HashMap<Uuid, String> = User::Entity::find()
        .filter(User::Column::Id.is_in(user_ids))
        .all(db)
        .await?
        .into_iter()
        .map(|u| (u.id, u.username))
        .collect();
    let target_names: HashMap<Uuid, String> = Target::Entity::find()
        .filter(Target::Column::Id.is_in(target_ids))
        .all(db)
        .await?
        .into_iter()
        .map(|t| (t.id, t.name))
        .collect();

    Ok(requests
        .into_iter()
        .map(|r| TicketRequestDetails {
            username: usernames.get(&r.user_id).cloned(),
            target_name: target_names.get(&r.target_id).cloned(),
            id: r.id,
            user_id: r.user_id,
            target_id: r.target_id,
            requested_duration_seconds: r.requested_duration_seconds,
            description: r.description,
            status: r.status,
            resolved_by_username: r
                .resolved_by_user_id
                .and_then(|id| usernames.get(&id).cloned()),
            resolved_by_user_id: r.resolved_by_user_id,
            ticket_id: r.ticket_id,
            created: r.created,
            resolved_at: r.resolved_at,
            deny_reason: r.deny_reason,
        })
        .collect())
}

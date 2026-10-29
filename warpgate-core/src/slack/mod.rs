//! Slack integration for admin (just-in-time) session approvals and
//! self-service ticket requests
//!
//! * A newly advertised admin approval request is sent as a DM to every
//!   approver (holders of the `ApproveSessions` admin permission), and a new
//!   ticket request to every holder of `TicketRequestsManage`. Approvers
//!   are found in Slack by the e-mail of their SSO credential, so an admin who
//!   signs in to Warpgate with Google as `alice@corp.com` is messaged as the
//!   Slack user `alice@corp.com`. Optionally, requests also go to a channel.
//! * Button clicks come back through the interactivity endpoint, signed with
//!   the app's signing secret. The clicking Slack user is mapped back to a
//!   Warpgate user the same way and the decision is recorded as them, under
//!   the same permission and self-approval rules as the admin UI.
//! * The node that posted a message keeps it in sync with the request status
//!   (decided anywhere, timed out or withdrawn) and then forgets it.
mod client;

use std::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
use sea_orm::prelude::Expr;
use sea_orm::sea_query::Func;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, DatabaseConnection, EntityTrait, ModelTrait,
    QueryFilter, Set,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use time::OffsetDateTime;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};
use uuid::Uuid;
use warpgate_common::auth::{ApprovalKind, ApprovalScope};
use warpgate_common::helpers::username::username_eq_ci;
use warpgate_common::{
    AdminPermission, AdminPermissionSet, NodeId, SlackConfig, UserSessionId, WarpgateError,
};
use warpgate_db_entities::SessionApprovalRequest::{
    self as SAR, ApprovalActor, ApprovalRequestStatus, UndecidedApprovalRequestStatus,
};
use warpgate_db_entities::TicketRequest::{self, TicketRequestStatus};
use warpgate_db_entities::{
    AdminRole, Node, Parameters, SlackApprovalMessage, SlackTicketRequestMessage, SsoCredential,
    Target, User, UserAdminRoleAssignment,
};

pub use self::client::SlackClient;
use crate::approvals::{ApprovalDecision, record_decision};
use crate::cluster::ClusterNotification;
use crate::services::Services;
use crate::ticket_requests::{approve_ticket_request, deny_ticket_request};

const ACTION_APPROVE_ONCE: &str = "warpgate_approve_once";
const ACTION_APPROVE_TARGET: &str = "warpgate_approve_target";
const ACTION_REJECT: &str = "warpgate_reject";
const ACTION_TICKET_APPROVE: &str = "warpgate_ticket_approve";
const ACTION_TICKET_DENY: &str = "warpgate_ticket_deny";

/// Catches requests that were closed without a cluster notification (timeouts)
const SYNC_INTERVAL: Duration = Duration::from_secs(15);

/// Slack refuses callbacks older than this, and so do we (replay protection)
const SIGNATURE_MAX_AGE: i64 = 5 * 60;

/// Give up updating a message after Slack has been failing for this long
const MESSAGE_MAX_AGE: time::Duration = time::Duration::days(1);

/// Settings saved in the admin UI, when they are enabled and complete
pub fn config_from_parameters(
    parameters: &Parameters::Model,
) -> Result<Option<SlackConfig>, WarpgateError> {
    if !parameters.slack_enabled
        || parameters.slack_bot_token.stored_value().is_empty()
        || parameters.slack_signing_secret.stored_value().is_empty()
    {
        return Ok(None);
    }
    Ok(Some(SlackConfig {
        enable: true,
        bot_token: parameters.slack_bot_token.reveal()?,
        signing_secret: parameters.slack_signing_secret.reveal()?,
        sso_provider: parameters.slack_sso_provider.clone(),
        channel: parameters.slack_channel.clone(),
    }))
}

/// The admin UI settings take precedence over the `slack` config file section
pub async fn slack_config(services: &Services) -> Option<SlackConfig> {
    match Parameters::Entity::get(&services.db)
        .await
        .map_err(WarpgateError::from)
        .and_then(|parameters| config_from_parameters(&parameters))
    {
        Ok(Some(config)) => return Some(config),
        Ok(None) => {}
        Err(error) => warn!(%error, "Failed to load the Slack settings"),
    }
    services
        .config
        .lock()
        .await
        .store
        .slack
        .clone()
        .filter(|c| c.enable)
}

/// Checks the settings by sending a DM to the given Warpgate user, found in
/// Slack the same way approvers are. Returns the Slack workspace name.
pub async fn send_test_message(
    db: &DatabaseConnection,
    config: &SlackConfig,
    user_id: Uuid,
) -> Result<String, WarpgateError> {
    let client = SlackClient::new(config.bot_token.clone());
    let team = client.auth_test().await?;

    let Some(user) = User::Entity::find_by_id(user_id).one(db).await? else {
        return Err(WarpgateError::InvalidRequest("Unknown user".into()));
    };
    let mut emails: Vec<String> = user
        .find_related(SsoCredential::Entity)
        .filter(sso_provider_matches(config.sso_provider.as_ref()))
        .all(db)
        .await?
        .into_iter()
        .map(|c| c.email)
        .collect();
    if emails.is_empty() && user.username.contains('@') {
        emails.push(user.username.clone());
    }
    if emails.is_empty() {
        return Err(WarpgateError::InvalidRequest(format!(
            "Connected to {team}, but your Warpgate account has no SSO e-mail{} to find you in Slack by",
            config
                .sso_provider
                .as_ref()
                .map(|p| format!(" from the `{p}` provider"))
                .unwrap_or_default(),
        )));
    }

    for email in &emails {
        if let Some(slack_user) = client.lookup_user_by_email(email).await? {
            client
                .post_message(
                    &slack_user,
                    "Warpgate is connected to Slack",
                    &json!([{
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": format!(
                                ":white_check_mark: Warpgate is connected to Slack. Session approval requests will be sent to you here as *{}*.",
                                escape(&user.username),
                            ),
                        },
                    }]),
                )
                .await?;
            if let Some(channel) = &config.channel {
                client
                    .post_message(
                        channel,
                        "Warpgate is connected to Slack",
                        &json!([{
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": ":white_check_mark: Warpgate session approval requests will be posted to this channel.",
                            },
                        }]),
                    )
                    .await?;
            }
            return Ok(team);
        }
    }
    Err(WarpgateError::InvalidRequest(format!(
        "Connected to {team}, but there is no Slack user with the e-mail {}",
        emails.join(", "),
    )))
}

/// Verifies `X-Slack-Signature` over `v0:{timestamp}:{body}`
pub fn verify_signature(
    signing_secret: &str,
    timestamp: &str,
    body: &[u8],
    signature: &str,
    now: OffsetDateTime,
) -> bool {
    let Ok(sent_at) = timestamp.parse::<i64>() else {
        return false;
    };
    if (now.unix_timestamp() - sent_at).abs() > SIGNATURE_MAX_AGE {
        return false;
    }
    let Some(signature) = signature
        .strip_prefix("v0=")
        .and_then(|hex_sig| hex::decode(hex_sig).ok())
    else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(signing_secret.as_bytes()) else {
        return false;
    };
    mac.update(b"v0:");
    mac.update(timestamp.as_bytes());
    mac.update(b":");
    mac.update(body);
    mac.verify_slice(&signature).is_ok()
}

/// Identifies the request a button acts on. `started` keeps a click on a
/// stale message from deciding a reopened request.
#[derive(Serialize, Deserialize)]
struct ButtonValue {
    session_id: UserSessionId,
    target: String,
    started: String,
}

fn request_details(row: &SAR::Model) -> String {
    let mut details = format!(
        "*User:* {}\n*Target:* {}\n*Protocol:* {}",
        escape(&row.username),
        escape(&row.target),
        escape(&row.protocol),
    );
    if let Some(address) = &row.remote_address {
        details.push_str(&format!("\n*From:* {}", escape(address)));
    }
    details
}

/// Slack mrkdwn control characters
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn button(action_id: &str, text: &str, value: &str, style: Option<&str>) -> Value {
    let mut button = json!({
        "type": "button",
        "action_id": action_id,
        "text": { "type": "plain_text", "text": text },
        "value": value,
    });
    if let Some(style) = style {
        button["style"] = json!(style);
    }
    button
}

fn pending_message(row: &SAR::Model) -> (String, Value) {
    let text = format!(
        "{} requests access to {} ({})",
        row.username, row.target, row.protocol
    );
    let value = serde_json::to_string(&ButtonValue {
        session_id: row.session_id,
        target: row.target.clone(),
        started: row.started.unix_timestamp_nanos().to_string(),
    })
    .unwrap_or_default();
    let blocks = json!([
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": format!(":lock: *Warpgate session approval requested*\n{}", request_details(row)),
            },
        },
        {
            "type": "actions",
            "block_id": "warpgate_session_approval",
            "elements": [
                button(ACTION_APPROVE_ONCE, "Approve", &value, Some("primary")),
                button(ACTION_APPROVE_TARGET, "Approve for this target", &value, None),
                button(ACTION_REJECT, "Reject", &value, Some("danger")),
            ],
        },
    ]);
    (text, blocks)
}

/// `row` is None when the request is gone or has been reopened since
fn settled_message(
    row: Option<&SAR::Model>,
    fallback: &SlackApprovalMessage::Model,
) -> (String, Value) {
    let by = |row: &SAR::Model| {
        escape(
            row.resolved_by_username
                .as_deref()
                .unwrap_or("an administrator"),
        )
    };
    let outcome = match row {
        Some(row) => match row.status {
            ApprovalRequestStatus::Approved => {
                let scope = match row.scope {
                    Some(ApprovalScope::Target) => " (remembered for this target)",
                    Some(ApprovalScope::AllTargets) => " (remembered for all targets)",
                    _ => "",
                };
                format!(":white_check_mark: Approved by {}{scope}", by(row))
            }
            ApprovalRequestStatus::Rejected => format!(":x: Rejected by {}", by(row)),
            ApprovalRequestStatus::TimedOut => ":hourglass: Timed out without a decision".into(),
            ApprovalRequestStatus::Abandoned | ApprovalRequestStatus::Pending => {
                ":heavy_minus_sign: Withdrawn - the connection ended".into()
            }
        },
        None => ":heavy_minus_sign: Withdrawn - the connection ended".into(),
    };
    let details = row.map_or_else(
        || format!("*Target:* {}", escape(&fallback.target)),
        request_details,
    );
    let blocks = json!([
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": format!(":lock: *Warpgate session approval*\n{details}"),
            },
        },
        {
            "type": "context",
            "elements": [{ "type": "mrkdwn", "text": outcome }],
        },
    ]);
    (format!("Warpgate session approval: {outcome}"), blocks)
}

fn sso_provider_matches(provider: Option<&String>) -> Condition {
    match provider {
        Some(provider) => Condition::any()
            .add(SsoCredential::Column::Provider.eq(provider))
            .add(SsoCredential::Column::Provider.is_null()),
        None => Condition::all(),
    }
}

/// E-mails of every user holding `permission`. Users without an SSO
/// credential are reachable when their username is an e-mail.
async fn approver_emails(
    db: &DatabaseConnection,
    config: &SlackConfig,
    permission: AdminPermission,
) -> Result<Vec<String>, WarpgateError> {
    let role_ids: Vec<Uuid> = AdminRole::Entity::find()
        .all(db)
        .await?
        .into_iter()
        .filter(|role| warpgate_common::AdminRole::from(role.clone()).has_permission(permission))
        .map(|role| role.id)
        .collect();
    if role_ids.is_empty() {
        return Ok(vec![]);
    }

    let mut user_ids: Vec<Uuid> = UserAdminRoleAssignment::Entity::find()
        .filter(UserAdminRoleAssignment::Column::AdminRoleId.is_in(role_ids))
        .all(db)
        .await?
        .into_iter()
        .map(|assignment| assignment.user_id)
        .collect();
    user_ids.sort();
    user_ids.dedup();

    let mut emails = vec![];
    for user in User::Entity::find()
        .filter(User::Column::Id.is_in(user_ids))
        .all(db)
        .await?
    {
        let credentials = user
            .find_related(SsoCredential::Entity)
            .filter(sso_provider_matches(config.sso_provider.as_ref()))
            .all(db)
            .await?;
        if credentials.is_empty() {
            if user.username.contains('@') {
                emails.push(user.username);
            } else {
                warn!(username = %user.username, "Approver has no SSO e-mail to find them in Slack by");
            }
        }
        emails.extend(credentials.into_iter().map(|c| c.email));
    }
    emails.sort_by_key(|e| e.to_lowercase());
    emails.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    Ok(emails)
}

/// The Warpgate user a Slack account's e-mail belongs to
async fn user_by_email(
    db: &DatabaseConnection,
    config: &SlackConfig,
    email: &str,
) -> Result<Option<User::Model>, WarpgateError> {
    let credential = SsoCredential::Entity::find()
        .filter(
            Expr::expr(Func::lower(Expr::col(SsoCredential::Column::Email)))
                .eq(email.to_lowercase()),
        )
        .filter(sso_provider_matches(config.sso_provider.as_ref()))
        .one(db)
        .await?;
    if let Some(credential) = credential {
        return Ok(credential.find_related(User::Entity).one(db).await?);
    }
    Ok(User::Entity::find()
        .filter(User::Entity::username_eq_ci(email))
        .one(db)
        .await?)
}

/// Slack user IDs of the holders of `permission`, plus the configured channel
async fn slack_recipients(
    client: &SlackClient,
    db: &DatabaseConnection,
    config: &SlackConfig,
    permission: AdminPermission,
) -> Result<Vec<String>, WarpgateError> {
    let emails = approver_emails(db, config, permission).await?;
    if emails.is_empty() {
        warn!(
            ?permission,
            sso_provider = ?config.sso_provider,
            "No admin with this permission has an SSO e-mail to find them in Slack by - check the admin roles and the users' SSO credentials"
        );
    }

    let mut recipients = vec![];
    for email in emails {
        match client.lookup_user_by_email(&email).await {
            Ok(Some(slack_user)) => recipients.push(slack_user),
            Ok(None) => warn!(%email, "No Slack user with this approver's e-mail"),
            Err(error) => warn!(%email, %error, "Failed to look up an approver in Slack"),
        }
    }
    recipients.extend(config.channel.clone());
    recipients.dedup();
    Ok(recipients)
}

/// Posts a freshly advertised admin request. Never fails the request itself.
pub(crate) fn announce_request(services: &Services, session_id: UserSessionId, target: String) {
    let services = services.clone();
    tokio::spawn(async move {
        let Some(config) = slack_config(&services).await else {
            return;
        };
        debug!(%session_id, %target, "Sending a session approval request to Slack");
        if let Err(error) = post_request(&services, &config, session_id, &target).await {
            warn!(%error, %session_id, "Failed to send a session approval request to Slack");
        }
    });
}

async fn post_request(
    services: &Services,
    config: &SlackConfig,
    session_id: UserSessionId,
    target: &str,
) -> Result<(), WarpgateError> {
    let db = &services.db;
    let Some(row) = SAR::Entity::find_by_id((session_id, ApprovalKind::Admin, target.to_owned()))
        .one(db)
        .await?
        .filter(|row| row.status == ApprovalRequestStatus::Pending)
    else {
        return Ok(());
    };

    let client = SlackClient::new(config.bot_token.clone());
    let recipients =
        slack_recipients(&client, db, config, AdminPermission::ApproveSessions).await?;
    if recipients.is_empty() {
        warn!(%session_id, "Nobody in Slack to send the session approval request to");
        return Ok(());
    }

    let (text, blocks) = pending_message(&row);
    let mut sent = 0;
    for recipient in recipients {
        match client.post_message(&recipient, &text, &blocks).await {
            Ok(posted) => {
                sent += 1;
                SlackApprovalMessage::ActiveModel {
                    id: Set(Uuid::new_v4()),
                    session_id: Set(row.session_id),
                    target: Set(row.target.clone()),
                    request_started: Set(row.started),
                    node_id: Set(services.cluster.node_id),
                    channel: Set(posted.channel),
                    ts: Set(posted.ts),
                }
                .insert(db)
                .await?;
            }
            Err(error) => {
                warn!(%recipient, %error, "Failed to post a session approval request to Slack")
            }
        }
    }
    info!(%session_id, target = %row.target, sent, "Sent a session approval request to Slack");
    // pick up a decision that raced the posting
    services
        .cluster
        .deliver_local(ClusterNotification::SessionApprovalsChanged);
    Ok(())
}

fn format_duration(seconds: i64) -> String {
    let (days, hours, minutes) = (seconds / 86400, seconds % 86400 / 3600, seconds % 3600 / 60);
    let parts: Vec<String> = [(days, "d"), (hours, "h"), (minutes, "m")]
        .into_iter()
        .filter(|(value, _)| *value > 0)
        .map(|(value, unit)| format!("{value}{unit}"))
        .collect();
    if parts.is_empty() {
        format!("{seconds}s")
    } else {
        parts.join(" ")
    }
}

/// Names for a ticket request, looked up once per message
struct TicketRequestNames {
    username: String,
    target: String,
}

impl TicketRequestNames {
    async fn load(
        db: &DatabaseConnection,
        request: &TicketRequest::Model,
    ) -> Result<Self, WarpgateError> {
        let username = User::Entity::find_by_id(request.user_id)
            .one(db)
            .await?
            .map_or_else(|| "a deleted user".into(), |u| u.username);
        let target = Target::Entity::find_by_id(request.target_id)
            .one(db)
            .await?
            .map_or_else(|| "a deleted target".into(), |t| t.name);
        Ok(Self { username, target })
    }
}

fn ticket_request_details(request: &TicketRequest::Model, names: &TicketRequestNames) -> String {
    let duration = request
        .requested_duration_seconds
        .map_or_else(|| "no limit".into(), format_duration);
    let mut details = format!(
        "*User:* {}\n*Target:* {}\n*Duration:* {duration}",
        escape(&names.username),
        escape(&names.target),
    );
    let reason = request.description.trim();
    if !reason.is_empty() {
        let reason: String = reason.chars().take(500).collect();
        details.push_str(&format!(
            "\n*Reason:*\n>{}",
            escape(&reason).replace('\n', "\n>")
        ));
    }
    details
}

fn pending_ticket_message(
    request: &TicketRequest::Model,
    names: &TicketRequestNames,
) -> (String, Value) {
    let text = format!("{} requests a ticket for {}", names.username, names.target);
    let value = request.id.to_string();
    let blocks = json!([
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": format!(":ticket: *Warpgate access request*\n{}", ticket_request_details(request, names)),
            },
        },
        {
            "type": "actions",
            "block_id": "warpgate_ticket_request",
            "elements": [
                button(ACTION_TICKET_APPROVE, "Approve", &value, Some("primary")),
                button(ACTION_TICKET_DENY, "Deny", &value, Some("danger")),
            ],
        },
    ]);
    (text, blocks)
}

/// `request` is None when the request has been deleted
async fn settled_ticket_message(
    db: &DatabaseConnection,
    request: Option<&TicketRequest::Model>,
) -> Result<(String, Value), WarpgateError> {
    let Some(request) = request else {
        let outcome = ":heavy_minus_sign: The request was deleted";
        return Ok((
            format!("Warpgate access request: {outcome}"),
            json!([{
                "type": "section",
                "text": { "type": "mrkdwn", "text": format!(":ticket: *Warpgate access request*\n{outcome}") },
            }]),
        ));
    };
    let by = match request.resolved_by_user_id {
        Some(id) => User::Entity::find_by_id(id)
            .one(db)
            .await?
            .map_or_else(|| "an administrator".into(), |u| escape(&u.username)),
        None => "an administrator".into(),
    };
    let outcome = match request.status {
        TicketRequestStatus::Approved => format!(":white_check_mark: Approved by {by}"),
        TicketRequestStatus::Denied => match request.deny_reason.as_deref().map(str::trim) {
            Some(reason) if !reason.is_empty() => {
                format!(":x: Denied by {by}: {}", escape(reason))
            }
            _ => format!(":x: Denied by {by}"),
        },
        TicketRequestStatus::Pending => ":hourglass: Pending".into(),
    };
    let names = TicketRequestNames::load(db, request).await?;
    let blocks = json!([
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": format!(":ticket: *Warpgate access request*\n{}", ticket_request_details(request, &names)),
            },
        },
        {
            "type": "context",
            "elements": [{ "type": "mrkdwn", "text": outcome }],
        },
    ]);
    Ok((format!("Warpgate access request: {outcome}"), blocks))
}

/// Posts a newly created, pending ticket request. Never fails the request itself.
pub fn announce_ticket_request(services: &Services, request_id: Uuid) {
    let services = services.clone();
    tokio::spawn(async move {
        let Some(config) = slack_config(&services).await else {
            return;
        };
        debug!(%request_id, "Sending a ticket request to Slack");
        if let Err(error) = post_ticket_request(&services, &config, request_id).await {
            warn!(%error, %request_id, "Failed to send a ticket request to Slack");
        }
    });
}

async fn post_ticket_request(
    services: &Services,
    config: &SlackConfig,
    request_id: Uuid,
) -> Result<(), WarpgateError> {
    let db = &services.db;
    let Some(request) = TicketRequest::Entity::find_by_id(request_id)
        .one(db)
        .await?
        .filter(|r| r.status == TicketRequestStatus::Pending)
    else {
        return Ok(());
    };

    let client = SlackClient::new(config.bot_token.clone());
    let recipients =
        slack_recipients(&client, db, config, AdminPermission::TicketRequestsManage).await?;
    if recipients.is_empty() {
        warn!(%request_id, "Nobody in Slack to send the ticket request to");
        return Ok(());
    }

    let names = TicketRequestNames::load(db, &request).await?;
    let (text, blocks) = pending_ticket_message(&request, &names);
    let mut sent = 0;
    for recipient in recipients {
        match client.post_message(&recipient, &text, &blocks).await {
            Ok(posted) => {
                sent += 1;
                SlackTicketRequestMessage::ActiveModel {
                    id: Set(Uuid::new_v4()),
                    ticket_request_id: Set(request.id),
                    node_id: Set(services.cluster.node_id),
                    channel: Set(posted.channel),
                    ts: Set(posted.ts),
                }
                .insert(db)
                .await?;
            }
            Err(error) => {
                warn!(%recipient, %error, "Failed to post a ticket request to Slack")
            }
        }
    }
    info!(%request_id, target = %names.target, sent, "Sent a ticket request to Slack");
    // pick up a decision that raced the posting
    services
        .cluster
        .deliver_local(ClusterNotification::SessionApprovalsChanged);
    Ok(())
}

/// Updates this node's ticket request messages once they are decided
async fn sync_ticket_messages(
    db: &DatabaseConnection,
    client: &SlackClient,
    node_id: NodeId,
) -> Result<(), WarpgateError> {
    for message in SlackTicketRequestMessage::Entity::find()
        .filter(SlackTicketRequestMessage::Column::NodeId.eq(node_id))
        .all(db)
        .await?
    {
        let request = TicketRequest::Entity::find_by_id(message.ticket_request_id)
            .one(db)
            .await?;
        if request
            .as_ref()
            .is_some_and(|r| r.status == TicketRequestStatus::Pending)
        {
            continue;
        }
        let (text, blocks) = settled_ticket_message(db, request.as_ref()).await?;
        match client
            .update_message(&message.channel, &message.ts, &text, &blocks)
            .await
        {
            Ok(()) => {}
            Err(error)
                if request.as_ref().is_some_and(|r| {
                    OffsetDateTime::now_utc() - r.resolved_at.unwrap_or(r.created) < MESSAGE_MAX_AGE
                }) =>
            {
                warn!(%error, "Failed to update a Slack ticket request message, will retry");
                continue;
            }
            Err(error) => warn!(%error, "Giving up on updating a Slack ticket request message"),
        }
        message.delete(db).await?;
    }
    Ok(())
}

/// Updates this node's messages whose request is no longer pending
async fn sync_messages(
    db: &DatabaseConnection,
    config: &SlackConfig,
    node_id: NodeId,
) -> Result<(), WarpgateError> {
    let client = SlackClient::new(config.bot_token.clone());
    sync_ticket_messages(db, &client, node_id).await?;

    let messages = SlackApprovalMessage::Entity::find()
        .filter(SlackApprovalMessage::Column::NodeId.eq(node_id))
        .all(db)
        .await?;

    for message in messages {
        let row = SAR::Entity::find_by_id((
            message.session_id,
            ApprovalKind::Admin,
            message.target.clone(),
        ))
        .one(db)
        .await?
        .filter(|row| row.started == message.request_started);
        if row
            .as_ref()
            .is_some_and(|row| row.status == ApprovalRequestStatus::Pending)
        {
            continue;
        }

        let (text, blocks) = settled_message(row.as_ref(), &message);
        match client
            .update_message(&message.channel, &message.ts, &text, &blocks)
            .await
        {
            Ok(()) => {}
            Err(error) if OffsetDateTime::now_utc() - message.request_started < MESSAGE_MAX_AGE => {
                warn!(%error, "Failed to update a Slack approval message, will retry");
                continue;
            }
            Err(error) => warn!(%error, "Giving up on updating a Slack approval message"),
        }
        message.delete(db).await?;
    }
    Ok(())
}

/// Keeps this node's Slack messages up to date
pub(crate) fn start(services: Services) {
    tokio::spawn(async move {
        let mut notifications = services.cluster.subscribe();
        let mut ticker = tokio::time::interval(SYNC_INTERVAL);
        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                msg = notifications.recv() => match msg {
                    Ok(ClusterNotification::SessionApprovalsChanged)
                    | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Ok(_) => continue,
                    Err(broadcast::error::RecvError::Closed) => return,
                },
            }
            let Some(config) = slack_config(&services).await else {
                continue;
            };
            if let Err(error) = sync_messages(&services.db, &config, services.cluster.node_id).await
            {
                warn!(%error, "Failed to sync Slack approval messages");
            }
        }
    });
}

#[derive(Deserialize)]
struct InteractionPayload {
    #[serde(rename = "type")]
    kind: String,
    user: InteractionUser,
    #[serde(default)]
    actions: Vec<InteractionAction>,
    response_url: Option<String>,
}

#[derive(Deserialize)]
struct InteractionUser {
    id: String,
}

#[derive(Deserialize)]
struct InteractionAction {
    action_id: String,
    value: Option<String>,
}

/// Handles a verified interactivity callback. Feedback for the clicking user
/// is sent back to Slack on its own: the callback has to be acknowledged within
/// three seconds regardless.
pub fn handle_interaction(services: &Services, config: SlackConfig, payload: &str) {
    let payload: InteractionPayload = match serde_json::from_str(payload) {
        Ok(payload) => payload,
        Err(error) => {
            warn!(%error, "Could not parse a Slack interaction");
            return;
        }
    };
    if payload.kind != "block_actions" {
        return;
    }
    let services = services.clone();
    tokio::spawn(async move {
        let client = SlackClient::new(config.bot_token.clone());
        let feedback = match decide(&services, &config, &client, &payload).await {
            Ok(feedback) => feedback,
            Err(error) => {
                warn!(%error, "Failed to handle a Slack approval action");
                Some("Warpgate could not record your decision, please use the admin UI.".into())
            }
        };
        if let (Some(feedback), Some(response_url)) = (feedback, &payload.response_url) {
            // only ever talk back to Slack itself
            if !response_url.starts_with("https://hooks.slack.com/") {
                return;
            }
            if let Err(error) = client.respond_ephemeral(response_url, &feedback).await {
                warn!(%error, "Failed to reply to a Slack interaction");
            }
        }
    });
}

/// What a clicked button asks for
enum ButtonAction {
    Session(ApprovalDecision, ButtonValue),
    Ticket { approve: bool, request_id: Uuid },
}

impl ButtonAction {
    fn parse(action: &InteractionAction) -> Option<Self> {
        let value = action.value.as_deref()?;
        let session = |decision| Some(Self::Session(decision, serde_json::from_str(value).ok()?));
        let ticket = |approve| {
            Some(Self::Ticket {
                approve,
                request_id: value.parse().ok()?,
            })
        };
        match action.action_id.as_str() {
            ACTION_APPROVE_ONCE => session(ApprovalDecision::Approved(ApprovalScope::Once)),
            ACTION_APPROVE_TARGET => session(ApprovalDecision::Approved(ApprovalScope::Target)),
            ACTION_REJECT => session(ApprovalDecision::Rejected),
            ACTION_TICKET_APPROVE => ticket(true),
            ACTION_TICKET_DENY => ticket(false),
            _ => None,
        }
    }
}

/// Returns feedback for the clicking user, if any
async fn decide(
    services: &Services,
    config: &SlackConfig,
    client: &SlackClient,
    payload: &InteractionPayload,
) -> Result<Option<String>, WarpgateError> {
    let Some(action) = payload.actions.iter().find_map(ButtonAction::parse) else {
        return Ok(None);
    };

    let db = &services.db;

    let Some(email) = client.user_email(&payload.user.id).await? else {
        return Ok(Some(
            "Your Slack account has no e-mail address to match a Warpgate user.".into(),
        ));
    };
    let Some(user) = user_by_email(db, config, &email).await? else {
        return Ok(Some(format!(
            "There is no Warpgate user with the e-mail {email}."
        )));
    };
    let roles = user.find_related(AdminRole::Entity).all(db).await?;
    let permissions = AdminPermissionSet::from_roles(roles.into_iter().map(Into::into));

    match action {
        ButtonAction::Session(decision, value) => {
            decide_session(services, &user, permissions, decision, value).await
        }
        ButtonAction::Ticket {
            approve,
            request_id,
        } => decide_ticket(services, &user, permissions, approve, request_id).await,
    }
}

async fn decide_ticket(
    services: &Services,
    user: &User::Model,
    permissions: AdminPermissionSet,
    approve: bool,
    request_id: Uuid,
) -> Result<Option<String>, WarpgateError> {
    if !permissions.contains(AdminPermission::TicketRequestsManage) {
        info!(username = %user.username, "Refused a Slack ticket request decision from a user without the permission");
        return Ok(Some(
            "You are not allowed to manage Warpgate ticket requests.".into(),
        ));
    }
    let db = &services.db;
    let decided = if approve {
        approve_ticket_request(db, request_id, Some(user.id)).await?
    } else {
        deny_ticket_request(db, request_id, Some(user.id), None).await?
    };
    if decided.is_none() {
        return Ok(Some("This request is no longer pending.".into()));
    }
    services
        .cluster
        .notify_global(ClusterNotification::SessionApprovalsChanged);
    Ok(None)
}

async fn decide_session(
    services: &Services,
    user: &User::Model,
    permissions: AdminPermissionSet,
    action: ApprovalDecision,
    value: ButtonValue,
) -> Result<Option<String>, WarpgateError> {
    let db = &services.db;
    if !permissions.contains(AdminPermission::ApproveSessions) {
        info!(username = %user.username, "Refused a Slack session approval from a user without the permission");
        return Ok(Some(
            "You are not allowed to approve Warpgate sessions.".into(),
        ));
    }

    let Some(row) =
        SAR::Entity::find_by_id((value.session_id, ApprovalKind::Admin, value.target.clone()))
            .one(db)
            .await?
            .filter(|row| {
                row.status == ApprovalRequestStatus::Pending
                    && row.started.unix_timestamp_nanos().to_string() == value.started
            })
    else {
        return Ok(Some("This request is no longer pending.".into()));
    };

    // same rule as the admin UI
    if matches!(action, ApprovalDecision::Approved(_))
        && username_eq_ci(&row.username, &user.username)
        && !permissions.contains(AdminPermission::TargetsEdit)
    {
        return Ok(Some("You cannot approve your own session.".into()));
    }

    // the owning node is gone, nobody is waiting for the answer
    if row.node_id != services.cluster.node_id
        && Node::Entity::find_by_id(row.node_id)
            .one(db)
            .await?
            .is_none()
    {
        SAR::close_request(
            db,
            row.session_id,
            row.kind,
            &row.target,
            UndecidedApprovalRequestStatus::Abandoned,
        )
        .await?;
        services
            .cluster
            .notify_global(ClusterNotification::SessionApprovalsChanged);
        return Ok(Some("This request is no longer pending.".into()));
    }

    let decided = record_decision(
        db,
        row.session_id,
        ApprovalKind::Admin,
        &row.target,
        action,
        ApprovalActor {
            username: Some(user.username.clone()),
            user_id: user.id,
        },
    )
    .await?;
    if !decided {
        return Ok(Some("This request is no longer pending.".into()));
    }
    services
        .cluster
        .notify_global(ClusterNotification::SessionApprovalsChanged);
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign(secret: &str, timestamp: &str, body: &[u8]) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(format!("v0:{timestamp}:").as_bytes());
        mac.update(body);
        format!("v0={}", hex::encode(mac.finalize().into_bytes()))
    }

    #[test]
    fn signature_verification() {
        let now = OffsetDateTime::now_utc();
        let ts = now.unix_timestamp().to_string();
        let body = b"payload=%7B%7D";
        let good = sign("secret", &ts, body);

        assert!(verify_signature("secret", &ts, body, &good, now));
        assert!(!verify_signature("other", &ts, body, &good, now));
        assert!(!verify_signature("secret", &ts, b"payload=x", &good, now));
        assert!(!verify_signature("secret", &ts, body, "v0=00", now));
        assert!(!verify_signature("secret", &ts, body, "garbage", now));

        let old = (now.unix_timestamp() - 600).to_string();
        let old_sig = sign("secret", &old, body);
        assert!(!verify_signature("secret", &old, body, &old_sig, now));
    }

    #[test]
    fn durations_are_readable() {
        assert_eq!(format_duration(45), "45s");
        assert_eq!(format_duration(3600), "1h");
        assert_eq!(format_duration(90061), "1d 1h 1m");
    }

    #[test]
    fn mrkdwn_is_escaped() {
        assert_eq!(escape("<!channel> & co"), "&lt;!channel&gt; &amp; co");
    }

    #[cfg(feature = "sqlite")]
    mod db {
        use sea_orm::{Database, IntoActiveModel};
        use warpgate_db_entities::Parameters::{
            ConfigMigrationValues, set_config_migration_values,
        };
        use warpgate_db_migrations::migrate_database;

        use super::super::*;

        fn config(sso_provider: Option<&str>) -> SlackConfig {
            SlackConfig {
                enable: true,
                bot_token: "xoxb-test".to_owned().into(),
                signing_secret: "secret".to_owned().into(),
                sso_provider: sso_provider.map(ToOwned::to_owned),
                channel: None,
            }
        }

        async fn user(
            db: &DatabaseConnection,
            username: &str,
            admin: bool,
            sso: Option<(&str, &str)>,
        ) -> Uuid {
            let id = Uuid::new_v4();
            User::Model {
                id,
                username: username.into(),
                credential_policy: serde_json::json!({}),
                description: String::new(),
                rate_limit_bytes_per_second: None,
                ldap_server_id: None,
                ldap_object_uuid: None,
                allowed_ip_ranges: serde_json::Value::Null,
            }
            .into_active_model()
            .insert(db)
            .await
            .unwrap();
            if admin {
                let role = AdminRole::Entity::find()
                    .filter(AdminRole::Column::Name.eq("warpgate:admin"))
                    .one(db)
                    .await
                    .unwrap()
                    .unwrap();
                UserAdminRoleAssignment::Model {
                    user_id: id,
                    admin_role_id: role.id,
                }
                .into_active_model()
                .insert(db)
                .await
                .unwrap();
            }
            if let Some((provider, email)) = sso {
                SsoCredential::Model {
                    id: Uuid::new_v4(),
                    user_id: id,
                    provider: Some(provider.into()),
                    email: email.into(),
                }
                .into_active_model()
                .insert(db)
                .await
                .unwrap();
            }
            id
        }

        #[tokio::test]
        async fn approvers_are_matched_by_sso_email() {
            set_config_migration_values(ConfigMigrationValues::default());
            let db = Database::connect("sqlite::memory:").await.unwrap();
            migrate_database(&db).await.unwrap();

            let gowtham = user(
                &db,
                "gowtham",
                true,
                Some(("google", "gowtham@ninjacart.com")),
            )
            .await;
            user(&db, "bob@ninjacart.com", true, None).await;
            user(&db, "carol", true, Some(("github", "carol@ninjacart.com"))).await;
            user(&db, "nobody", true, None).await;
            let dave = user(&db, "dave", false, Some(("google", "dave@ninjacart.com"))).await;

            let google = config(Some("google"));
            assert_eq!(
                approver_emails(&db, &google, AdminPermission::ApproveSessions)
                    .await
                    .unwrap(),
                vec!["bob@ninjacart.com", "gowtham@ninjacart.com"],
            );
            assert_eq!(
                approver_emails(&db, &config(None), AdminPermission::ApproveSessions)
                    .await
                    .unwrap(),
                vec![
                    "bob@ninjacart.com",
                    "carol@ninjacart.com",
                    "gowtham@ninjacart.com"
                ],
            );

            let found = |email: &'static str| {
                let db = db.clone();
                let google = google.clone();
                async move {
                    user_by_email(&db, &google, email)
                        .await
                        .unwrap()
                        .map(|u| u.id)
                }
            };
            assert_eq!(found("Gowtham@NinjaCart.com").await, Some(gowtham));
            assert_eq!(found("dave@ninjacart.com").await, Some(dave));
            // a credential of another provider does not count
            assert_eq!(found("carol@ninjacart.com").await, None);
        }
    }
}

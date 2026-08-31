use std::net::IpAddr;
use std::sync::Arc;

use sea_orm::sea_query::IntoCondition;
use sea_orm::{EntityTrait, QueryFilter};
use tokio::sync::Mutex;
use tracing::warn;
use warpgate_common::auth::{ApprovalKind, RememberApprovalBy};
use warpgate_common::{UserSessionId, WarpgateError};
use warpgate_db_entities::SessionApprovalRequest;
use warpgate_db_entities::SessionApprovalRequest::{
    Advertised, UndecidedApprovalRequestStatus, close_request, mark_consumed,
};

use super::*;
use crate::config_providers::{ApprovedTarget, TargetAuthorization};
use crate::protocols::AdmittedTarget;
use crate::services::Services;
use crate::{TargetSessionStart, WarpgateServerHandle};

#[must_use]
pub enum GateOutcome<O = warpgate_common::TargetOptions> {
    Approved(ApprovedTarget<O>),
    Refused,
    // timeout / disconnected / gone from the DB (may ask again)
    Expired,
}

impl<O> GateOutcome<O> {
    pub fn approved(self) -> Option<ApprovedTarget<O>> {
        match self {
            Self::Approved(target) => Some(target),
            Self::Refused | Self::Expired => None,
        }
    }
}

/// Current state of an approval gate
#[must_use]
pub enum PolledGate<O = warpgate_common::TargetOptions> {
    Approved(ApprovedTarget<O>),
    Refused,
    /// no response (yet or ever)
    Pending,
}

/// User session derived gate context
pub struct GatedConnection {
    pub remote_ip: Option<IpAddr>,
    pub credentials: RememberApprovalBy,
}

impl GatedConnection {
    /// Combine this user session context with the target session authorization context
    fn subject_for<O>(
        self,
        session_id: UserSessionId,
        authorization: &TargetAuthorization<O>,
    ) -> ApprovalSubject {
        ApprovalSubject {
            kind: ApprovalKind::Admin,
            session_id,
            user_info: authorization.user_info().clone(),
            protocol: authorization.protocol(),
            target_name: authorization.target().name.clone(),
            remote_ip: self.remote_ip,
            credentials: self.credentials,
            ticket_id: authorization.ticket_id(),
        }
    }
}

/// Start a target session, waiting for approval if needed
/// and handle approval result. This is the only transition path from "authorized" to "admitted" for protocols that can wait for approval.
///
/// protocols that can communicate with the user during the wait, must drive require_admin_approval() + poll_admin_approval() themselves
///
/// Refusal return WarpgateError::SessionNotApproved
///
/// This wraps require_admin_approval()
pub async fn admit_target_session<O: Send + Sync>(
    services: &Services,
    handle: &Arc<Mutex<WarpgateServerHandle>>,
    authorization: TargetAuthorization<O>,
    connection: GatedConnection,
) -> Result<AdmittedTarget<O>, WarpgateError> {
    let started = handle
        .lock()
        .await
        .start_target_session(authorization)
        .await?;
    let authorization = match started {
        TargetSessionStart::Started(started) => return Ok(started),
        TargetSessionStart::NeedsApproval(authorization) => authorization,
    };

    let session_id = handle.lock().await.user_session_id();

    let outcome: GateOutcome<O> = services
        .require_admin_approval(authorization, session_id, connection, || async {
            Ok::<_, WarpgateError>(())
        })
        .await?;

    let Some(approved) = outcome.approved() else {
        warn!(%session_id, "Session was not approved by an administrator");
        return Err(WarpgateError::SessionNotApproved);
    };

    handle
        .lock()
        .await
        .register_approved_target_session(approved)
        .await
}

impl Services {
    /// Wait for an admin approval. Dropping the future cancels the appoval requet
    pub async fn require_admin_approval<E, F, Fut, O>(
        &self,
        authorization: TargetAuthorization<O>,
        session_id: UserSessionId,
        connection: GatedConnection,
        notify_waiting: F,
    ) -> Result<GateOutcome<O>, E>
    where
        E: From<WarpgateError>,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        let subject = connection.subject_for(session_id, &authorization);
        if !authorization.target().require_approval {
            return Ok(GateOutcome::Approved(ApprovedTarget::new(authorization)));
        }

        let session_id = subject.session_id;

        if self.admin_approval_is_remembered(&subject).await? {
            subject.emit_bypassed_event();
            return Ok(GateOutcome::Approved(ApprovedTarget::new(authorization)));
        }

        let mut guard = PendingApproval::guarding(self.db.clone(), &subject);
        if matches!(
            self.announce_admin_request(&subject).await?,
            Advertised::TicketExhausted
        ) {
            return Ok(GateOutcome::Refused);
        }

        notify_waiting().await?;

        let timeout = self.admin_approval_timeout().await?;
        // audite event has already been emitted by the resolving code
        let decision = match await_row_decision(
            &self.db,
            session_id,
            ApprovalKind::Admin,
            &subject.target_name,
            timeout,
        )
        .await?
        {
            RowOutcome::Decided(decision) => {
                guard.decided();
                decision
            }
            RowOutcome::TimedOut => {
                guard.timed_out();
                subject.emit_timed_out_event();
                return Ok(GateOutcome::Expired);
            }
            RowOutcome::Ended => return Ok(GateOutcome::Expired),
        };

        match decision {
            ApprovalDecision::Approved(_) => {
                Ok(GateOutcome::Approved(ApprovedTarget::new(authorization)))
            }
            ApprovalDecision::Rejected => Ok(GateOutcome::Refused),
        }
    }

    async fn announce_admin_request(
        &self,
        subject: &ApprovalSubject,
    ) -> Result<Advertised, WarpgateError> {
        let advertised = advertise_admin_request(&self.db, self.cluster.node_id, subject).await?;
        // idempotent
        if matches!(advertised, Advertised::Asked) {
            subject.emit_requested_event();
            let _ = self.admin_approval_request_tx.send(subject.session_id);
        }
        Ok(advertised)
    }

    /// Non-blocking form of [`Self::require_admin_approval`], for protocols
    /// that answer each request separately and so cannot park on the gate.
    ///
    /// Each call answers from the request row: the row carries both the
    /// question and its answer, so where the gate stands *is* what the row
    /// says, on whichever node the request happens to land. No wait runs
    /// anywhere — the client's retry cadence is the poll.
    ///
    /// The caller that finds no live question asks it (idempotently — a
    /// concurrent asker's row is simply refreshed), and the one that finds the
    /// window run out closes the question as timed out and asks afresh, so
    /// expiry needs no waiter to notice it either. A client that stops polling
    /// leaves its question to the age sweep, exactly like a waiter that died.
    ///
    /// A ticket's use rides on the question's row like everywhere else: kept
    /// by an approval, given back by whatever else ends the row — including
    /// the timeout this poll itself records.
    pub async fn poll_admin_approval<O>(
        &self,
        authorization: TargetAuthorization<O>,
        session_id: UserSessionId,
        connection: GatedConnection,
    ) -> Result<PolledGate<O>, WarpgateError> {
        // Read off the authorization for the same reason the blocking gate
        // does; it also means a recorded denial stops applying the moment the
        // target stops requiring approval.
        if !authorization.target().require_approval {
            return Ok(PolledGate::Approved(ApprovedTarget::new(authorization)));
        }

        let subject = connection.subject_for(session_id, &authorization);

        if self.admin_approval_is_remembered(&subject).await? {
            subject.emit_bypassed_event();
            return Ok(PolledGate::Approved(ApprovedTarget::new(authorization)));
        }

        let key = SessionApprovalRequest::Key::new(
            subject.session_id,
            ApprovalKind::Admin,
            &subject.target_name,
        );
        let row = SessionApprovalRequest::Entity::find()
            .filter(key.clone().into_condition())
            .one(&self.db)
            .await?;
        let Some(row) = row else {
            // A fresh question is paid for by the use taken at authentication,
            // so this cannot come back exhausted; matched anyway so the enum
            // stays honest.
            return Ok(match self.announce_admin_request(&subject).await? {
                Advertised::TicketExhausted => PolledGate::Refused,
                _ => PolledGate::Pending,
            });
        };

        match row_state(&row)? {
            // A question that ended unanswered is history; this request is a
            // fresh asking.
            RowState::Ended => {
                // Asking afresh re-spends; a ticket that can no longer pay is
                // a denial, not an eternal 202.
                Ok(match self.announce_admin_request(&subject).await? {
                    Advertised::TicketExhausted => PolledGate::Refused,
                    _ => PolledGate::Pending,
                })
            }
            RowState::Pending => {
                let timeout = self.admin_approval_timeout().await?;
                #[allow(clippy::cast_possible_wrap)]
                let window = time::Duration::seconds(timeout.as_secs() as i64);
                if time::OffsetDateTime::now_utc() - row.started >= window {
                    // The transition names its source state, so a decision that
                    // landed in the meantime wins and nothing is emitted for a
                    // timeout that didn't happen.
                    if close_request(
                        &self.db,
                        subject.session_id,
                        ApprovalKind::Admin,
                        &subject.target_name,
                        UndecidedApprovalRequestStatus::TimedOut,
                    )
                    .await?
                    {
                        subject.emit_timed_out_event();
                    }
                    if matches!(
                        self.announce_admin_request(&subject).await?,
                        Advertised::TicketExhausted
                    ) {
                        return Ok(PolledGate::Refused);
                    }
                }
                Ok(PolledGate::Pending)
            }
            RowState::Decided(decision, _) => {
                mark_consumed(&self.db, key).await?;
                match decision {
                    ApprovalDecision::Approved(_) => {
                        Ok(PolledGate::Approved(ApprovedTarget::new(authorization)))
                    }
                    ApprovalDecision::Rejected => Ok(PolledGate::Refused),
                }
            }
        }
    }

    async fn admin_approval_is_remembered(
        &self,
        subject: &ApprovalSubject,
    ) -> Result<bool, WarpgateError> {
        // The key first: a subject with nothing to match on (HTTP passes no
        // credentials) answers without the Parameters read — and this now runs
        // per request on the polled path.
        let Some(key) = subject.match_key() else {
            return Ok(false);
        };
        let Some(grace) = self.admin_approval_grace_period().await? else {
            return Ok(false);
        };
        approval_is_remembered(&self.db, &key, grace).await
    }
}

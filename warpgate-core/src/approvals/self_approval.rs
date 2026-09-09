use std::sync::Arc;

use sea_orm::DatabaseConnection;
use tokio::sync::Mutex;
use warpgate_common::auth::{ApprovalKind, AuthCredential, AuthResult, AuthState, CredentialKind};
use warpgate_common::{NodeId, UserSessionId, WarpgateError};
use warpgate_db_entities::SessionApprovalRequest;
use warpgate_db_entities::SessionApprovalRequest::{
    mark_consumed, undelivered_user_approvals_for_session, upsert_request,
};

use super::*;
use crate::services::Services;

impl Services {
    // For protocols where the user actively "confirms" that an approval has already been made (SSH keyboard-interactive)
    pub async fn apply_recorded_user_decision(
        &self,
        session_id: &UserSessionId,
    ) -> Result<(), WarpgateError> {
        for row in
            undelivered_user_approvals_for_session(&self.db, self.cluster.node_id, *session_id)
                .await?
        {
            self.deliver_user_decision(&row).await?;
        }
        Ok(())
    }

    /// Apply decisions made elsewhere to the AuthStates on this node
    pub(crate) async fn apply_decided_user_approvals(&self) -> Result<(), WarpgateError> {
        let rows = SessionApprovalRequest::undelivered_user_approvals_for_node(
            &self.db,
            self.cluster.node_id,
        )
        .await?;

        for row in rows {
            self.deliver_user_decision(&row).await?;
        }
        Ok(())
    }

    /// Delivers one recorded decision to the auth state it was asked for —
    /// every decision reaches its state through here, on whichever node holds
    /// it: recording and delivering are separate acts, and only the recording
    /// is the approver's. The row is stamped consumed once nothing is left to
    /// deliver to, which is what stops the sweep re-offering it.
    async fn deliver_user_decision(
        &self,
        row: &SessionApprovalRequest::Model,
    ) -> Result<bool, WarpgateError> {
        let RowState::Decided(decision, _) = row_state(row)? else {
            return Ok(false);
        };
        let consumed =
            || SessionApprovalRequest::Key::new(row.session_id, ApprovalKind::User, &row.target);

        let Some(state_arc) = self.auth_state_store.lock().await.get(&row.session_id) else {
            // The state is gone (cleaned up or node is gone), mark consumed so
            // that it's not being picked up again
            mark_consumed(&self.db, consumed()).await?;
            return Ok(false);
        };

        // All the in-memory work under one lock
        {
            let mut state = state_arc.lock().await;
            let subject = ApprovalSubject::from_auth_state(&state);

            // Verify that the decision still matches the original request exactly
            if row.target != subject.target_name || row.user_id != subject.user_info.id {
                drop(state);
                mark_consumed(&self.db, consumed()).await?;
                return Ok(false);
            }

            // Verify that the state is still waiting for an approval
            if !matches!(
                state.verify(),
                AuthResult::Need(ref kinds) if kinds.contains(&CredentialKind::WebUserApproval)
            ) {
                drop(state);
                mark_consumed(&self.db, consumed()).await?;
                return Ok(false);
            }

            match decision {
                ApprovalDecision::Approved(_) => {
                    state.add_web_user_approval();
                }
                ApprovalDecision::Rejected => {
                    state.reject();
                    state.emit_authentication_failed_event(
                        Some(&AuthCredential::WebUserApproval),
                        "approval rejected by user",
                    );
                }
            }
        }

        mark_consumed(&self.db, consumed()).await?;
        Ok(true)
    }
}

pub(crate) async fn advertise_user_request(
    db: &DatabaseConnection,
    node_id: NodeId,
    state_arc: &Arc<Mutex<AuthState>>,
) -> Result<(), WarpgateError> {
    let row = {
        let state = state_arc.lock().await;
        let session_id = *state.session_id();
        SessionApprovalRequest::NewRequest {
            session_id,
            target: state.target_name().to_string(),
            node_id,
            protocol: state.protocol().to_string(),
            username: state.user_info().username.clone(),
            user_id: state.user_info().id,
            remote_address: state.remote_ip().map(|ip| ip.to_string()),
            match_digest: state
                .web_approval_match_key()
                .map(|key| key.identity().digest()),
            started: *state.started(),
            about: SessionApprovalRequest::RequestAsk::User {
                identification_string: state.identification_string().to_owned(),
            },
        }
    };

    upsert_request(db, row).await?;
    Ok(())
}

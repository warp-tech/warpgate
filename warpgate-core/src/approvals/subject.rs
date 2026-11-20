use std::net::IpAddr;

use uuid::Uuid;
use warpgate_common::auth::{
    ApprovalKind, AuthState, AuthStateUserInfo, RememberApprovalBy, WebApprovalMatchKey,
};
use warpgate_common::{Protocol, UserSessionId};

use crate::logging::{AuditEvent, SessionApprovalStep};

#[derive(Debug, Clone)]
pub(super) struct ApprovalSubject {
    pub(super) kind: ApprovalKind,
    pub(super) session_id: UserSessionId,
    pub(super) user_info: AuthStateUserInfo,
    pub(super) protocol: Protocol,
    pub(super) target_name: String,
    pub(super) remote_ip: Option<IpAddr>,
    pub(super) remember_by: RememberApprovalBy,
    /// Ticket to refund if the approval is not granted
    pub(super) ticket_id: Option<Uuid>,
}

impl ApprovalSubject {
    pub(super) fn from_auth_state(state: &AuthState) -> Self {
        Self {
            kind: ApprovalKind::User,
            session_id: *state.session_id(),
            user_info: state.user_info().clone(),
            protocol: state.protocol(),
            target_name: state.target_name().to_string(),
            remote_ip: state.remote_ip(),
            remember_by: state.remembered_by(),
            ticket_id: None,
        }
    }

    pub(super) fn match_digest(&self) -> Option<String> {
        Some(self.match_key()?.identity().digest())
    }

    pub(super) fn client_ip_for_logging(&self) -> String {
        self.remote_ip
            .map_or_else(|| "<unknown>".to_string(), |ip| ip.to_string())
    }

    /// Key for the "remember decision" bypass
    pub(super) fn match_key(&self) -> Option<WebApprovalMatchKey> {
        self.remote_ip.and_then(|ip| {
            WebApprovalMatchKey::build(
                self.kind,
                ip,
                self.protocol,
                &self.user_info.username,
                &self.target_name,
                &self.remember_by,
            )
        })
    }

    pub(super) fn emit_requested_event(&self) {
        self.emit(SessionApprovalStep::Requested);
    }

    pub(super) fn emit_timed_out_event(&self) {
        self.emit(SessionApprovalStep::TimedOut);
    }

    pub(super) fn emit_bypassed_event(&self) {
        self.emit(SessionApprovalStep::Bypassed);
    }

    fn emit(&self, step: SessionApprovalStep) {
        AuditEvent::SessionApproval {
            step,
            session_id: self.session_id,
            client_ip: self.client_ip_for_logging(),
            user_id: self.user_info.id,
            username: self.user_info.username.clone(),
            protocol: self.protocol.to_string(),
            target_name: self.target_name.clone(),
        }
        .emit();
    }
}

use std::net::IpAddr;

use tracing::info;
use uuid::Uuid;
use warpgate_common::auth::{
    ApprovalKind, AuthState, AuthStateUserInfo, RememberApprovalBy, WebApprovalMatchKey,
};
use warpgate_common::helpers::logging::format_related_ids;
use warpgate_common::{Protocol, UserSessionId};

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
        info!(
            target: "audit",
            _type = "SessionApprovalRequested1",
            session = %self.session_id,
            client_ip = %self.client_ip_for_logging(),
            user_id = %self.user_info.id,
            username = %self.user_info.username,
            protocol = %self.protocol,
            target = %self.target_name,
            related_users = %format_related_ids(&[self.user_info.id]),
            "Session is awaiting administrator approval",
        );
    }

    pub(super) fn emit_timed_out_event(&self) {
        info!(
            target: "audit",
            _type = "SessionApprovalTimedOut1",
            session = %self.session_id,
            client_ip = %self.client_ip_for_logging(),
            user_id = %self.user_info.id,
            username = %self.user_info.username,
            protocol = %self.protocol,
            target = %self.target_name,
            related_users = %format_related_ids(&[self.user_info.id]),
            "Session approval timed out",
        );
    }

    pub(super) fn emit_bypassed_event(&self) {
        info!(
            target: "audit",
            _type = "AdminApprovalBypassed1",
            session = %self.session_id,
            client_ip = %self.client_ip_for_logging(),
            user_id = %self.user_info.id,
            username = %self.user_info.username,
            protocol = %self.protocol,
            target = %self.target_name,
            related_users = %format_related_ids(&[self.user_info.id]),
            "Administrator approval bypassed within grace period",
        );
    }
}

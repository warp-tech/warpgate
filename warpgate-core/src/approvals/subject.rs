use std::net::IpAddr;

use tracing::info;
use uuid::Uuid;
use warpgate_common::auth::{
    ApprovalKind, AuthState, AuthStateUserInfo, CredentialDigestSalt, RememberedBy,
    WebApprovalMatchKey,
};
use warpgate_common::helpers::logging::format_related_ids;
use warpgate_common::{Protocol, UserSessionId};

/// The session an approval is about, and the single source for its request row,
/// audit events and grace key.
///
/// The administrator gate owns one directly — that is the point of the gate, no
/// auth state need exist. The self-approval path builds one from its auth state
/// via [`ApprovalSubject::from_auth_state`], so both kinds audit through the
/// same code.
#[derive(Debug, Clone)]
pub(super) struct ApprovalSubject {
    /// Which approval this subject describes. Part of every key it produces, so
    /// a grant of one kind can never satisfy a request of the other.
    pub(super) kind: ApprovalKind,
    pub(super) session_id: UserSessionId,
    pub(super) user_info: AuthStateUserInfo,
    pub(super) protocol: Protocol,
    pub(super) target_name: String,
    pub(super) remote_ip: Option<IpAddr>,
    /// What a grant to this session could be remembered on. Where that is
    /// nothing, remembering is disabled rather than keyed on less.
    pub(super) credentials: RememberedBy,
    /// The ticket an approval of this request consumes, where consumption is
    /// deferred to the gate — see [`TicketStake::ConsumedOnApproval`].
    pub(super) consumes_ticket_id: Option<Uuid>,
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
            credentials: state.remembered_by(),
            consumes_ticket_id: None,
        }
    }

    /// What the request row stores to match this session's credentials against
    /// a later connection. `None` mirrors [`Self::match_key`]'s: a row without
    /// a digest can never serve as a remembered approval.
    pub(super) fn credentials_digest(&self, salt: &CredentialDigestSalt) -> Option<String> {
        self.credentials.credentials().map(|c| c.digest(salt))
    }

    pub(super) fn client_ip_for_logging(&self) -> String {
        self.remote_ip
            .map_or_else(|| "<unknown>".to_string(), |ip| ip.to_string())
    }

    /// The key this session's approval is remembered under. `None` when
    /// [`WebApprovalMatchKey::build`] has nothing to pin a grant to.
    pub(super) fn match_key(&self) -> Option<WebApprovalMatchKey> {
        WebApprovalMatchKey::build(
            self.kind,
            self.remote_ip,
            self.protocol,
            &self.user_info.username,
            &self.target_name,
            &self.credentials,
        )
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

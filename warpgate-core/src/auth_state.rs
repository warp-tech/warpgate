use std::fmt::Write;
use std::net::IpAddr;

use rand::RngExt;
use time::OffsetDateTime;
use tracing::{debug, info};
use url::Url;
use uuid::Uuid;
use warpgate_common::SessionId;
use warpgate_common::auth::{
    ApprovalKind, AuthCredential, AuthCredentialFingerprint, AuthResult, AuthStateUserInfo,
    CredentialKind, CredentialPolicy, CredentialPolicyResponse,
};
use warpgate_common::helpers::logging::format_related_ids;

/// Cache matching key for approval bypass (both self web approval and
/// administrator approval).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WebApprovalMatchKey {
    /// The approval factor this remembered grant satisfies. A remembered
    /// self-approval must never satisfy an administrator-approval requirement,
    /// or vice versa, so the kind is part of the key.
    pub approval_kind: ApprovalKind,
    pub remote_ip: IpAddr,
    pub protocol: String,
    pub username: String,
    /// `None` when the approval was granted for *all* targets;
    /// `Some(name)` binds it to one target.
    pub target_name: Option<String>,
    pub other_credentials: Vec<AuthCredentialFingerprint>,
}

impl WebApprovalMatchKey {
    /// A copy of this key that matches an approval remembered for all targets.
    #[must_use]
    pub fn for_all_targets(&self) -> Self {
        Self {
            target_name: None,
            ..self.clone()
        }
    }
}

/// A pure in-memory authentication state machine. Reading is open; every
/// mutator is `pub(crate)`, so state can only change through the `Services`
/// wrappers.
pub struct AuthState {
    id: Uuid,
    user_info: AuthStateUserInfo,
    session_id: Option<Uuid>,
    remote_ip: Option<IpAddr>,
    protocol: String,
    target_name: String,
    force_rejected: bool,
    policy: Box<dyn CredentialPolicy + Sync + Send>,
    valid_credentials: Vec<AuthCredential>,
    started: OffsetDateTime,
    identification_string: String,
    last_result: Option<AuthResult>,
    authenticated_event_emitted: bool,
}

fn generate_identification_string() -> String {
    let mut s = String::new();
    let mut rng = rand::rng();
    for _ in 0..4 {
        let _ = write!(&mut s, "{:X}", rng.random_range(0..16));
    }
    s
}

impl AuthState {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        id: Uuid,
        session_id: Option<SessionId>,
        remote_ip: Option<IpAddr>,
        user_info: AuthStateUserInfo,
        protocol: String,
        target_name: String,
        policy: Box<dyn CredentialPolicy + Sync + Send>,
    ) -> Self {
        let mut this = Self {
            id,
            session_id,
            remote_ip,
            user_info,
            protocol,
            target_name,
            force_rejected: false,
            policy,
            valid_credentials: vec![],
            started: OffsetDateTime::now_utc(),
            identification_string: generate_identification_string(),
            last_result: None,
            authenticated_event_emitted: false,
        };
        this.maybe_update_verification_state();
        this
    }

    pub const fn id(&self) -> &Uuid {
        &self.id
    }

    pub const fn session_id(&self) -> Option<&SessionId> {
        self.session_id.as_ref()
    }

    pub(crate) const fn set_session_id(&mut self, session_id: SessionId) {
        self.session_id = Some(session_id);
    }

    pub const fn user_info(&self) -> &AuthStateUserInfo {
        &self.user_info
    }

    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    pub fn target_name(&self) -> &str {
        &self.target_name
    }

    pub const fn remote_ip(&self) -> Option<IpAddr> {
        self.remote_ip
    }

    /// Builds the key used to match this attempt against a remembered approval
    /// of the given `approval_kind`.
    pub fn approval_match_key(&self, approval_kind: ApprovalKind) -> Option<WebApprovalMatchKey> {
        let remote_ip = self.remote_ip?;

        // Both approval factors are excluded so the key describes the *other*
        // credentials presented, and is identical whether computed before the
        // approval is added (check) or after (save).
        let mut other_credentials: Vec<AuthCredentialFingerprint> = self
            .valid_credentials
            .iter()
            .filter(|c| {
                !matches!(
                    c.kind(),
                    CredentialKind::WebUserApproval | CredentialKind::AdminApproval
                )
            })
            .map(Into::into)
            .collect();
        other_credentials.sort_unstable();
        other_credentials.dedup();

        Some(WebApprovalMatchKey {
            approval_kind,
            remote_ip,
            protocol: self.protocol.clone(),
            username: self.user_info.username.to_lowercase(),
            target_name: Some(self.target_name.clone()),
            other_credentials,
        })
    }

    /// Match key for a remembered self (in-browser) approval.
    pub fn web_approval_match_key(&self) -> Option<WebApprovalMatchKey> {
        self.approval_match_key(ApprovalKind::User)
    }

    /// Match key for a remembered administrator approval.
    pub fn admin_approval_match_key(&self) -> Option<WebApprovalMatchKey> {
        self.approval_match_key(ApprovalKind::Admin)
    }

    pub const fn started(&self) -> &OffsetDateTime {
        &self.started
    }

    pub fn identification_string(&self) -> &str {
        &self.identification_string
    }

    pub(crate) fn add_valid_credential(&mut self, credential: AuthCredential) -> AuthResult {
        self.valid_credentials.push(credential);
        self.maybe_update_verification_state()
    }

    pub(crate) fn reject(&mut self) -> AuthResult {
        self.force_rejected = true;
        self.maybe_update_verification_state()
    }

    pub fn verify(&self) -> AuthResult {
        self.current_verification_state()
    }

    fn valid_credentials_description(&self) -> String {
        self.valid_credentials
            .iter()
            .map(AuthCredential::safe_description)
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn client_ip_for_logging(&self) -> String {
        self.remote_ip
            .map_or_else(|| "<unknown>".to_string(), |x| x.to_string())
    }

    pub fn emit_authenticated_event_once(&mut self) {
        if self.authenticated_event_emitted {
            return;
        }

        let AuthResult::Accepted { .. } = self.current_verification_state() else {
            return;
        };

        let Some(session_id) = self.session_id.as_ref() else {
            return;
        };

        info!(
            target: "audit",
            _type = "UserAuthenticated1",
            session = %session_id,
            client_ip = %self.client_ip_for_logging(),
            user_id = %self.user_info.id,
            username = %self.user_info.username,
            credentials = %self.valid_credentials_description(),
            related_users = %format_related_ids(&[self.user_info.id]),
            "Authenticated",
        );

        self.authenticated_event_emitted = true;
    }

    pub fn emit_web_approval_bypassed_event(&self) {
        let Some(session_id) = self.session_id.as_ref() else {
            return;
        };

        info!(
            target: "audit",
            _type = "WebApprovalBypassed1",
            session = %session_id,
            client_ip = %self.client_ip_for_logging(),
            user_id = %self.user_info.id,
            username = %self.user_info.username,
            protocol = %self.protocol,
            target = %self.target_name,
            related_users = %format_related_ids(&[self.user_info.id]),
            "Web approval bypassed within grace period",
        );
    }

    pub fn emit_admin_approval_bypassed_event(&self) {
        let Some(session_id) = self.session_id.as_ref() else {
            return;
        };

        info!(
            target: "audit",
            _type = "AdminApprovalBypassed1",
            session = %session_id,
            client_ip = %self.client_ip_for_logging(),
            user_id = %self.user_info.id,
            username = %self.user_info.username,
            protocol = %self.protocol,
            target = %self.target_name,
            related_users = %format_related_ids(&[self.user_info.id]),
            "Administrator approval bypassed within grace period",
        );
    }

    pub fn emit_session_approval_requested_event(&self) {
        let Some(session_id) = self.session_id.as_ref() else {
            return;
        };

        info!(
            target: "audit",
            _type = "SessionApprovalRequested1",
            session = %session_id,
            client_ip = %self.client_ip_for_logging(),
            user_id = %self.user_info.id,
            username = %self.user_info.username,
            protocol = %self.protocol,
            target = %self.target_name,
            related_users = %format_related_ids(&[self.user_info.id]),
            "Session is awaiting administrator approval",
        );
    }

    /// `resolved_by_user_id` is `None` when the resolver isn't a user (the admin
    /// API token). It is recorded in `related_users` so the decision also shows
    /// up in the resolver's own audit trail, matching how every other
    /// actor-driven event is attributed.
    pub fn emit_session_approval_resolved_event(
        &self,
        resolved_by: &str,
        resolved_by_user_id: Option<Uuid>,
        approved: bool,
    ) {
        let Some(session_id) = self.session_id.as_ref() else {
            return;
        };

        // A user approving their own session is both parties — don't list twice.
        let mut related = vec![self.user_info.id];
        if let Some(actor) = resolved_by_user_id.filter(|id| *id != self.user_info.id) {
            related.push(actor);
        }

        info!(
            target: "audit",
            _type = "SessionApprovalResolved1",
            session = %session_id,
            client_ip = %self.client_ip_for_logging(),
            user_id = %self.user_info.id,
            username = %self.user_info.username,
            protocol = %self.protocol,
            target = %self.target_name,
            resolved_by = %resolved_by,
            approved = approved,
            related_users = %format_related_ids(&related),
            "Session approval resolved",
        );
    }

    pub fn emit_session_approval_timed_out_event(&self) {
        let Some(session_id) = self.session_id.as_ref() else {
            return;
        };

        info!(
            target: "audit",
            _type = "SessionApprovalTimedOut1",
            session = %session_id,
            client_ip = %self.client_ip_for_logging(),
            user_id = %self.user_info.id,
            username = %self.user_info.username,
            protocol = %self.protocol,
            target = %self.target_name,
            related_users = %format_related_ids(&[self.user_info.id]),
            "Session approval request timed out",
        );
    }

    pub fn emit_authentication_failed_event(
        &self,
        credential: Option<&AuthCredential>,
        reason: &str,
    ) {
        let Some(session_id) = self.session_id.as_ref() else {
            return;
        };

        let credentials =
            credential.map_or_else(|| "<unknown>".to_string(), AuthCredential::safe_description);

        info!(
            target: "audit",
            _type = "UserAuthenticationFailed1",
            session = %session_id,
            client_ip = %self.client_ip_for_logging(),
            user_id = %self.user_info.id,
            username = %self.user_info.username,
            credentials = %credentials,
            reason = %reason,
            related_users = %format_related_ids(&[self.user_info.id]),
            "Authentication failed",
        );
    }

    fn current_verification_state(&self) -> AuthResult {
        if self.force_rejected {
            return AuthResult::Rejected;
        }
        match self
            .policy
            .is_sufficient(&self.protocol, &self.valid_credentials[..])
        {
            CredentialPolicyResponse::Ok => AuthResult::Accepted {
                user_info: self.user_info.clone(),
            },
            CredentialPolicyResponse::Need(kinds) => AuthResult::Need(kinds),
        }
    }

    fn maybe_update_verification_state(&mut self) -> AuthResult {
        let new_result = self.current_verification_state();
        if self.last_result.as_ref() != Some(&new_result) {
            self.emit_authenticated_event_once();
            debug!(
                "Verification state changed for auth state {}: {:?} -> {:?}",
                self.id, self.last_result, &new_result
            );
            self.last_result = Some(new_result.clone());
        }
        new_result
    }

    pub fn construct_web_approval_url(&self, mut external_url: Url) -> url::Url {
        external_url.set_path("@warpgate");
        external_url.set_fragment(Some(&format!("/login/{}", self.id())));
        external_url
    }
}

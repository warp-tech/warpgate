use std::collections::HashSet;
use std::fmt::Write;
use std::future::Future;
use std::net::IpAddr;

use rand::RngExt;
use time::OffsetDateTime;
use tokio::sync::broadcast;
use tracing::{debug, info};
use url::Url;
use uuid::Uuid;

use super::{
    AuthCredential, AuthCredentialFingerprint, CredentialKind, CredentialPolicy,
    CredentialPolicyResponse,
};
use crate::helpers::logging::format_related_ids;
use crate::{Protocol, User, UserSessionId, WarpgateError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthResult {
    Accepted { user_info: AuthStateUserInfo },
    Need(HashSet<CredentialKind>),
    Rejected,
}

/// The outcome of submitting a single credential: whether *that credential*
/// passed validation, alongside the resulting overall verification state.
///
/// The two are independent: a wrong credential leaves the state as it was
/// (typically `Need(..)`, not `Rejected`), and a wrong extra credential on an
/// already-satisfied policy yields `Invalid(Accepted { .. })`. Brute-force
/// accounting must key off credential validity, never off the overall state.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// The credential passed validation and was recorded.
    Valid(AuthResult),
    /// The credential failed validation; the auth state is unchanged.
    Invalid(AuthResult),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedSubmission {
    /// Whether the specific credential failed validation. False when
    /// the cred was ok but the policy requires more
    pub credential_rejected: bool,
    pub state: AuthResult,
}

impl SubmitOutcome {
    pub const fn is_valid(&self) -> bool {
        matches!(self, Self::Valid(_))
    }

    pub const fn result(&self) -> &AuthResult {
        match self {
            Self::Valid(result) | Self::Invalid(result) => result,
        }
    }

    // Protects against an Invalid(Accepted) from authorising a session
    pub fn into_accepted(self) -> Result<AuthStateUserInfo, RejectedSubmission> {
        match self {
            Self::Valid(AuthResult::Accepted { user_info }) => Ok(user_info),
            Self::Valid(state) => Err(RejectedSubmission {
                credential_rejected: false,
                state,
            }),
            Self::Invalid(state) => Err(RejectedSubmission {
                credential_rejected: true,
                state,
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthStateUserInfo {
    pub id: Uuid,
    pub username: String,
}

/// Cache matching key for web approval bypass.
/// What a remembered web approval covers — and, on the lookup side, what a login
/// is asking for. Kept as three explicit states because "no target yet" and
/// "every target" are different things that a single `Option` would conflate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum WebApprovalScopeKey {
    /// The flow isn't target-scoped: an HTTP portal sign-in, or SSH before the
    /// menu selection.
    Untargeted,
    /// Bound to a single target.
    Target(String),
    /// Granted for every target.
    AllTargets,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WebApprovalMatchKey {
    pub remote_ip: IpAddr,
    pub protocol: Protocol,
    pub username: String,
    pub scope: WebApprovalScopeKey,
    pub other_credentials: Vec<AuthCredentialFingerprint>,
}

impl WebApprovalMatchKey {
    /// A copy of this key that matches an approval remembered for all targets.
    #[must_use]
    pub fn for_all_targets(&self) -> Self {
        Self {
            scope: WebApprovalScopeKey::AllTargets,
            ..self.clone()
        }
    }
}

impl From<&User> for AuthStateUserInfo {
    fn from(user: &User) -> Self {
        Self {
            id: user.id,
            username: user.username.clone(),
        }
    }
}

pub struct AuthState {
    session_id: UserSessionId,
    user_info: AuthStateUserInfo,
    remote_ip: Option<IpAddr>,
    protocol: Protocol,
    target_name: String,
    force_rejected: bool,
    policy: Box<dyn CredentialPolicy + Sync + Send>,
    valid_credentials: Vec<AuthCredential>,
    started: OffsetDateTime,
    identification_string: String,
    last_result: Option<AuthResult>,
    state_change_signal: broadcast::Sender<AuthResult>,
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
    pub fn new(
        session_id: UserSessionId,
        remote_ip: Option<IpAddr>,
        user_info: AuthStateUserInfo,
        protocol: Protocol,
        target_name: String,
        policy: Box<dyn CredentialPolicy + Sync + Send>,
        state_change_signal: broadcast::Sender<AuthResult>,
    ) -> Self {
        let mut this = Self {
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
            state_change_signal,
            authenticated_event_emitted: false,
        };
        this.maybe_update_verification_state();
        this
    }

    pub const fn session_id(&self) -> &UserSessionId {
        &self.session_id
    }

    pub const fn user_info(&self) -> &AuthStateUserInfo {
        &self.user_info
    }

    pub const fn protocol(&self) -> Protocol {
        self.protocol
    }

    pub const fn remote_ip(&self) -> Option<IpAddr> {
        self.remote_ip
    }

    pub fn target_name(&self) -> &str {
        &self.target_name
    }

    /// Builds the key used to match this attempt against a remembered web
    /// approval.
    pub fn web_approval_match_key(&self) -> Option<WebApprovalMatchKey> {
        let remote_ip = self.remote_ip?;

        // `WebUserApproval` itself is excluded so the key describes the
        // *other* credentials presented, and is identical whether computed before
        // the approval is added (check) or after (save)
        let mut other_credentials: Vec<AuthCredentialFingerprint> = self
            .valid_credentials
            .iter()
            .filter(|c| c.kind() != CredentialKind::WebUserApproval)
            .map(Into::into)
            .collect();
        other_credentials.sort_unstable();
        other_credentials.dedup();

        Some(WebApprovalMatchKey {
            remote_ip,
            protocol: self.protocol,
            username: self.user_info.username.to_lowercase(),
            // An empty target name means the flow hasn't picked one (HTTP sign-in,
            // SSH menu) — which is not the same as an approval covering all targets.
            scope: if self.target_name.is_empty() {
                WebApprovalScopeKey::Untargeted
            } else {
                WebApprovalScopeKey::Target(self.target_name.clone())
            },
            other_credentials,
        })
    }

    pub const fn started(&self) -> &OffsetDateTime {
        &self.started
    }

    pub fn identification_string(&self) -> &str {
        &self.identification_string
    }

    /// Runs `validate` on the credential and records it only if it passes.
    /// This is the sole path for adding a credential that requires validation,
    /// so a credential in `valid_credentials` is validated by construction.
    pub async fn submit_credential<F, Fut>(
        &mut self,
        credential: AuthCredential,
        validate: F,
    ) -> Result<SubmitOutcome, WarpgateError>
    where
        F: FnOnce(String, AuthCredential) -> Fut,
        Fut: Future<Output = Result<bool, WarpgateError>>,
    {
        if validate(self.user_info.username.clone(), credential.clone()).await? {
            self.valid_credentials.push(credential);
            Ok(SubmitOutcome::Valid(self.maybe_update_verification_state()))
        } else {
            self.emit_authentication_failed_event(Some(&credential), "invalid credential");
            Ok(SubmitOutcome::Invalid(self.current_verification_state()))
        }
    }

    /// Records a web user approval. Unlike other credential kinds, the act of
    /// approval is itself the validation, so there is nothing to check.
    pub fn add_web_user_approval(&mut self) -> AuthResult {
        self.valid_credentials.push(AuthCredential::WebUserApproval);
        self.maybe_update_verification_state()
    }

    pub fn reject(&mut self) {
        self.force_rejected = true;
        self.maybe_update_verification_state();
    }

    pub fn verify(&self) -> AuthResult {
        self.current_verification_state()
    }

    /// Receives every verification-state change, including the terminal
    /// `Accepted` / `Rejected`. Sends happen while the state's lock is held,
    /// so subscribing under that lock cannot miss a transition.
    pub fn subscribe(&self) -> broadcast::Receiver<AuthResult> {
        self.state_change_signal.subscribe()
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

        info!(
            target: "audit",
            _type = "UserAuthenticated1",
            session = %self.session_id,
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
        info!(
            target: "audit",
            _type = "WebApprovalBypassed1",
            session = %self.session_id,
            client_ip = %self.client_ip_for_logging(),
            user_id = %self.user_info.id,
            username = %self.user_info.username,
            protocol = %self.protocol,
            target = %self.target_name,
            related_users = %format_related_ids(&[self.user_info.id]),
            "Web approval bypassed within grace period",
        );
    }

    pub fn emit_authentication_failed_event(
        &self,
        credential: Option<&AuthCredential>,
        reason: &str,
    ) {
        let credentials =
            credential.map_or_else(|| "<unknown>".to_string(), AuthCredential::safe_description);

        info!(
            target: "audit",
            _type = "UserAuthenticationFailed1",
            session = %self.session_id,
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
            .is_sufficient(self.protocol, &self.valid_credentials[..])
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
                self.session_id, self.last_result, &new_result
            );
            let _ = self.state_change_signal.send(new_result.clone());
            self.last_result = Some(new_result.clone());
        }

        new_result
    }

    pub fn construct_web_approval_url(&self, mut external_url: Url) -> url::Url {
        external_url.set_path("@warpgate");
        external_url.set_fragment(Some(&format!("/login/{}", self.session_id())));
        external_url
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Secret;

    struct RequireAll(HashSet<CredentialKind>);

    impl CredentialPolicy for RequireAll {
        fn is_sufficient(
            &self,
            _protocol: Protocol,
            valid_credentials: &[AuthCredential],
        ) -> CredentialPolicyResponse {
            let have: HashSet<CredentialKind> =
                valid_credentials.iter().map(AuthCredential::kind).collect();
            let needed: HashSet<CredentialKind> = self.0.difference(&have).copied().collect();
            if needed.is_empty() {
                CredentialPolicyResponse::Ok
            } else {
                CredentialPolicyResponse::Need(needed)
            }
        }
    }

    fn make_state(kinds: &[CredentialKind]) -> AuthState {
        AuthState::new(
            UserSessionId(Uuid::new_v4()),
            None,
            AuthStateUserInfo {
                id: Uuid::new_v4(),
                username: "alice".into(),
            },
            Protocol::Ssh,
            "target".into(),
            Box::new(RequireAll(kinds.iter().copied().collect())),
            broadcast::channel(8).0,
        )
    }

    fn password() -> AuthCredential {
        AuthCredential::Password(Secret::new("pw".into()))
    }

    #[tokio::test]
    async fn valid_credential_is_recorded() {
        let mut state = make_state(&[CredentialKind::Password]);
        let outcome = state
            .submit_credential(password(), |_, _| async { Ok(true) })
            .await
            .unwrap();
        assert!(outcome.is_valid());
        assert!(matches!(outcome.result(), AuthResult::Accepted { .. }));
        assert!(matches!(state.verify(), AuthResult::Accepted { .. }));
    }

    #[tokio::test]
    async fn invalid_credential_leaves_state_unchanged() {
        let mut state = make_state(&[CredentialKind::Password]);
        let outcome = state
            .submit_credential(password(), |_, _| async { Ok(false) })
            .await
            .unwrap();
        assert!(!outcome.is_valid());
        assert!(matches!(
            outcome.result(),
            AuthResult::Need(needed) if needed.contains(&CredentialKind::Password)
        ));
        assert!(matches!(
            state.verify(),
            AuthResult::Need(needed) if needed.contains(&CredentialKind::Password)
        ));
    }

    #[tokio::test]
    async fn invalid_extra_credential_keeps_accepted_state() {
        let mut state = make_state(&[CredentialKind::Password]);
        let _ = state
            .submit_credential(password(), |_, _| async { Ok(true) })
            .await
            .unwrap();
        let outcome = state
            .submit_credential(password(), |_, _| async { Ok(false) })
            .await
            .unwrap();
        assert!(!outcome.is_valid());
        assert!(matches!(outcome.result(), AuthResult::Accepted { .. }));

        // ...and `into_accepted` refuses to hand back the user for it, so an
        // invalid extra credential can never (re-)authorize the session.
        let rejection = outcome.into_accepted().unwrap_err();
        assert!(rejection.credential_rejected);
        assert!(matches!(rejection.state, AuthResult::Accepted { .. }));
    }

    #[tokio::test]
    async fn into_accepted_yields_user_only_on_valid_success() {
        let mut state = make_state(&[CredentialKind::Password]);
        let outcome = state
            .submit_credential(password(), |_, _| async { Ok(true) })
            .await
            .unwrap();
        assert!(outcome.into_accepted().is_ok());
    }

    #[tokio::test]
    async fn validator_error_records_nothing() {
        let mut state = make_state(&[CredentialKind::Password]);
        let result = state
            .submit_credential(password(), |_, _| async {
                Err(WarpgateError::UserNotFound("alice".into()))
            })
            .await;
        assert!(result.is_err());
        assert!(matches!(state.verify(), AuthResult::Need(_)));
    }

    #[tokio::test]
    async fn reject_broadcasts_and_is_sticky() {
        let mut state = make_state(&[CredentialKind::WebUserApproval]);
        let mut rx = state.subscribe();
        state.reject();
        assert!(matches!(rx.recv().await.unwrap(), AuthResult::Rejected));
        let _ = state.add_web_user_approval();
        assert!(matches!(state.verify(), AuthResult::Rejected));
    }

    #[tokio::test]
    async fn web_approval_accepts_and_broadcasts() {
        let mut state = make_state(&[CredentialKind::WebUserApproval]);
        let mut rx = state.subscribe();
        assert!(matches!(
            state.add_web_user_approval(),
            AuthResult::Accepted { .. }
        ));
        assert!(matches!(
            rx.recv().await.unwrap(),
            AuthResult::Accepted { .. }
        ));
    }
}

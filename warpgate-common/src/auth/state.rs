use std::collections::HashSet;
use std::fmt::Write;
use std::future::Future;
use std::net::IpAddr;

use data_encoding::HEXLOWER;
use rand::RngExt;
use sha2::Digest;
use time::OffsetDateTime;
use tokio::sync::broadcast;
use tracing::{debug, info};
use url::Url;
use uuid::Uuid;

use super::{
    ApprovalKind, AuthCredential, CredentialKind, CredentialPolicy, CredentialPolicyResponse,
    StoredCredential, ValidCredential,
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

/// What a login is asking a remembered approval for. Explicit rather than an
/// `Option`, because "no target yet" is a real bucket of its own: an untargeted
/// grant must not stand in for approval of an actual target.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum WebApprovalScopeKey {
    /// The flow isn't target-scoped: an HTTP portal sign-in, or SSH before the
    /// menu selection.
    Untargeted,
    /// Bound to a single target.
    Target(String),
}

/// A non-empty, sorted, deduplicated, equatable set of the stored credentials
/// an authentication was made with — what a "remember approval" decision is
/// keyed on.
///
/// A web approval cannot appear here by construction: the set is built through
/// [`ValidCredential::stored`], and an approval has no stored row.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StoredCredentials(Vec<StoredCredential>);

impl StoredCredentials {
    #[must_use]
    pub fn new(mut credentials: Vec<StoredCredential>) -> Option<Self> {
        credentials.sort_unstable();
        credentials.dedup();
        (!credentials.is_empty()).then_some(Self(credentials))
    }

    /// A stable digest for the credential set (for matching)
    #[must_use]
    pub fn digest(&self) -> String {
        // Version 2 keys on stored rows; version 1 keyed on verifier hashes
        // alone. Bump this with any encoding change — every remembered approval
        // in flight stops matching, which is the intended, fail-closed effect.
        let mut bytes = vec![2];

        for credential in &self.0 {
            credential.write_canonical_bytes(&mut bytes);
        }

        let digest = sha2::Sha256::digest(&bytes);
        HEXLOWER.encode(&digest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RememberApprovalBy {
    /// Approval can be reused if this credential set matches
    Credentials(StoredCredentials),
    /// Cannot be remembered because there are no credentials to match
    Nothing,
}

impl RememberApprovalBy {
    #[must_use]
    pub fn from_credentials(credentials: Vec<StoredCredential>) -> Self {
        StoredCredentials::new(credentials).map_or(Self::Nothing, Self::Credentials)
    }

    #[must_use]
    pub const fn credentials(&self) -> Option<&StoredCredentials> {
        match self {
            Self::Credentials(credentials) => Some(credentials),
            Self::Nothing => None,
        }
    }
}

/// The exact identity half of a remember approval key
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WebApprovalIdentity {
    kind: ApprovalKind,
    remote_ip: IpAddr,
    protocol: Protocol,
    username: String,
    other_credentials: StoredCredentials,
}

impl WebApprovalIdentity {
    #[must_use]
    pub fn digest(&self) -> String {
        let mut bytes = vec![1]; // version tag
        // Length-prefix everything to avoid collisions via string boundaries
        let mut push = |part: &[u8]| {
            bytes.extend_from_slice(&(part.len() as u64).to_le_bytes());
            bytes.extend_from_slice(part);
        };

        push(&[self.kind as u8]);
        push(self.remote_ip.to_string().as_bytes());
        push(self.protocol.to_string().as_bytes());
        push(self.username.as_bytes());
        push(self.other_credentials.digest().as_bytes());

        HEXLOWER.encode(&sha2::Sha256::digest(&bytes))
    }

    pub fn kind(&self) -> ApprovalKind {
        self.kind
    }

    pub fn remote_ip(&self) -> IpAddr {
        self.remote_ip
    }

    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn other_credentials(&self) -> &StoredCredentials {
        &self.other_credentials
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WebApprovalMatchKey {
    // compared by "scope is narrower", so it cannot be a part of the digest
    scope: WebApprovalScopeKey,
    // compared by equality
    identity: WebApprovalIdentity,
}

impl WebApprovalMatchKey {
    #[must_use]
    pub fn build(
        kind: ApprovalKind,
        remote_ip: IpAddr,
        protocol: Protocol,
        username: &str,
        target_name: &str,
        remember_by: &RememberApprovalBy,
    ) -> Option<Self> {
        Some(Self {
            scope: if target_name.is_empty() {
                // currenrly, only the SSH menu can do this
                WebApprovalScopeKey::Untargeted
            } else {
                WebApprovalScopeKey::Target(target_name.to_string())
            },
            identity: WebApprovalIdentity {
                kind,
                remote_ip,
                protocol,
                username: username.to_lowercase(),
                other_credentials: remember_by.credentials()?.clone(),
            },
        })
    }

    pub fn identity(&self) -> &WebApprovalIdentity {
        &self.identity
    }

    pub fn scope(&self) -> &WebApprovalScopeKey {
        &self.scope
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
    valid_credentials: Vec<ValidCredential>,
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

    /// Best possible "remember by" key for approving this AuthState
    #[must_use]
    pub fn remembered_by(&self) -> RememberApprovalBy {
        RememberApprovalBy::from_credentials(
            self.valid_credentials
                .iter()
                .filter_map(ValidCredential::stored)
                .copied()
                .collect(),
        )
    }

    /// Builds the key used to match this attempt against a remembered web
    /// approval.
    pub fn web_approval_match_key(&self) -> Option<WebApprovalMatchKey> {
        self.remote_ip.and_then(|ip| {
            WebApprovalMatchKey::build(
                ApprovalKind::User,
                ip,
                self.protocol,
                &self.user_info.username,
                &self.target_name,
                &self.remembered_by(),
            )
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
    ///
    /// validate() should return None for rejected credentials
    pub async fn submit_credential<F, Fut>(
        &mut self,
        credential: AuthCredential,
        validate: F,
    ) -> Result<SubmitOutcome, WarpgateError>
    where
        F: FnOnce(String, AuthCredential) -> Fut,
        Fut: Future<Output = Result<Option<StoredCredential>, WarpgateError>>,
    {
        if let Some(stored) = validate(self.user_info.username.clone(), credential.clone()).await? {
            self.valid_credentials.push(ValidCredential::Stored(stored));
            Ok(SubmitOutcome::Valid(self.maybe_update_verification_state()))
        } else {
            self.emit_authentication_failed_event(Some(&credential), "invalid credential");
            Ok(SubmitOutcome::Invalid(self.current_verification_state()))
        }
    }

    /// Records a web user approval. Unlike other credential kinds, the act of
    /// approval is itself the validation, so there is nothing to check.
    pub fn add_web_user_approval(&mut self) -> AuthResult {
        self.valid_credentials
            .push(ValidCredential::WebUserApproval);
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

    fn valid_credential_kinds(&self) -> HashSet<CredentialKind> {
        self.valid_credentials
            .iter()
            .map(ValidCredential::kind)
            .collect()
    }

    fn valid_credentials_description(&self) -> String {
        self.valid_credentials
            .iter()
            .map(ValidCredential::readable_description)
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
        let credentials = credential.map_or_else(
            || "<unknown>".to_string(),
            AuthCredential::readable_description,
        );

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
            .is_sufficient(self.protocol, &self.valid_credential_kinds())
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
    use crate::auth::{StoredCredentialFingerprint, StoredCredentialKind};

    fn stored_credential(byte: u8) -> StoredCredential {
        StoredCredential::new(
            StoredCredentialKind::Password,
            Uuid::from_u128(u128::from(byte)),
            StoredCredentialFingerprint::of_stored_verifier([byte; 32].as_slice()),
        )
    }

    fn fingerprints(byte: u8) -> StoredCredentials {
        #[allow(clippy::expect_used)]
        StoredCredentials::new(vec![stored_credential(byte)]).expect("non-empty")
    }

    fn identity() -> WebApprovalIdentity {
        WebApprovalIdentity {
            kind: ApprovalKind::Admin,
            remote_ip: "10.0.0.1".parse().unwrap(),
            protocol: Protocol::Ssh,
            username: "someone".into(),
            other_credentials: fingerprints(1),
        }
    }

    /// The digest *is* the comparison a remembered approval is matched by, so
    /// a field that doesn't reach it is a field two different sessions are
    /// allowed to differ in and still share a grant.
    ///
    /// The destructuring is the point: adding a field to the identity stops
    /// this compiling until someone says what it does to the digest.
    #[test]
    fn every_part_of_the_identity_reaches_the_digest() {
        let base = identity();
        let WebApprovalIdentity {
            kind,
            remote_ip,
            protocol,
            username,
            other_credentials,
        } = identity();

        let differing = [
            WebApprovalIdentity {
                kind: ApprovalKind::User,
                ..identity()
            },
            WebApprovalIdentity {
                remote_ip: "10.0.0.2".parse().unwrap(),
                ..identity()
            },
            WebApprovalIdentity {
                protocol: Protocol::Http,
                ..identity()
            },
            WebApprovalIdentity {
                username: "someone-else".into(),
                ..identity()
            },
            WebApprovalIdentity {
                other_credentials: fingerprints(2),
                ..identity()
            },
        ];
        // Names the destructured bindings, so none is quietly unused if a
        // field is added and left out of the cases above.
        let _ = (kind, remote_ip, protocol, username, other_credentials);

        for altered in differing {
            assert_ne!(
                base.digest(),
                altered.digest(),
                "identities differing in one field must not share a digest: {altered:?}",
            );
        }
    }

    /// The whole point of the type: a session with nothing to pin a grant to
    /// must produce no key, not a key that matches on origin and username
    /// alone. A policy whose only factor is the approval itself lands here.
    #[test]
    fn an_empty_credential_set_is_not_remembered() {
        assert_eq!(
            RememberApprovalBy::from_credentials(vec![]),
            RememberApprovalBy::Nothing
        );
        assert!(StoredCredentials::new(vec![]).is_none());
    }

    #[test]
    fn credential_sets_key_the_same_whatever_the_order() {
        let a = stored_credential(1);
        let b = stored_credential(2);
        assert_eq!(
            StoredCredentials::new(vec![a, b, a]),
            StoredCredentials::new(vec![b, a]),
        );
    }

    struct RequireAll(HashSet<CredentialKind>);

    impl CredentialPolicy for RequireAll {
        fn is_sufficient(
            &self,
            _protocol: Protocol,
            valid_credentials: &HashSet<CredentialKind>,
        ) -> CredentialPolicyResponse {
            let needed: HashSet<CredentialKind> =
                self.0.difference(valid_credentials).copied().collect();
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
            .submit_credential(password(), |_, _| async { Ok(Some(stored_credential(1))) })
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
            .submit_credential(password(), |_, _| async { Ok(None) })
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
            .submit_credential(password(), |_, _| async { Ok(Some(stored_credential(1))) })
            .await
            .unwrap();
        let outcome = state
            .submit_credential(password(), |_, _| async { Ok(None) })
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
            .submit_credential(password(), |_, _| async { Ok(Some(stored_credential(1))) })
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

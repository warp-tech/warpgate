use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, broadcast};
use warpgate_common::auth::{
    AuthResult, AuthState, CredentialKind, CredentialPolicy, WebApprovalMatchKey,
};
use warpgate_common::helpers::ipnet::WarpgateIpNet;
use warpgate_common::helpers::username::username_eq_ci;
use warpgate_common::{Protocol, User, UserSessionId, WarpgateError};

use crate::login_protection::{FailedAttemptInfo, LoginProtectionService};
use crate::{ConfigProvider, ConfigProviderEnum};

#[allow(clippy::unwrap_used)]
pub static TIMEOUT: LazyLock<Duration> = LazyLock::new(|| Duration::from_mins(10));

// Absolute maximum cache duration for cleanup
const RECENT_APPROVAL_RETENTION: Duration = Duration::from_hours(24 * 30);

/// If the address is an IPv4-mapped IPv6 address (e.g. `::ffff:192.168.1.1`),
/// extract the inner IPv4 address. Otherwise return as-is.
const fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        IpAddr::V4(_) => ip,
    }
}

/// Whether `remote_ip` is permitted by the user's `allowed_ip_ranges`.
///
/// An unset or empty range list, or an unknown remote IP, counts as
/// unrestricted. Both the interactive auth path and the ticket path decide IP
/// access through this, so the two can't drift.
pub fn ip_allowed(
    allowed_ip_ranges: Option<&Vec<WarpgateIpNet>>,
    remote_ip: Option<IpAddr>,
) -> bool {
    let Some(ranges) = allowed_ip_ranges else {
        return true;
    };
    if ranges.is_empty() {
        return true;
    }
    let Some(raw_ip) = remote_ip else {
        return true;
    };
    let ip = normalize_ip(raw_ip);
    ranges.iter().any(|network| network.contains(&ip))
}

/// Checks whether the given IP is allowed by the user's `allowed_ip_ranges` setting.
/// Returns `Ok(())` if access is allowed, or an appropriate `WarpgateError` if denied.
pub fn check_ip_allowed(
    allowed_ip_ranges: Option<&Vec<WarpgateIpNet>>,
    remote_ip: Option<IpAddr>,
    username: &str,
) -> Result<(), WarpgateError> {
    if ip_allowed(allowed_ip_ranges, remote_ip) {
        return Ok(());
    }
    // `ip_allowed` only denies when a remote IP is present and outside the ranges.
    let ip_str = remote_ip.map_or_else(String::new, |ip| normalize_ip(ip).to_string());
    tracing::warn!(
        "Access denied for IP '{ip_str}' (not in any allowed range for user '{username}')"
    );
    Err(WarpgateError::IpAddrNotAllowed(ip_str, username.into()))
}

/// Vets a user resolved from a non-interactive credential — a ticket, an API
/// token, a Kubernetes transport credential — against the account-status checks
/// an interactive login goes through: account lockout and the user's IP
/// allow-list. Callers check the source IP against login protection ahead of
/// their credential lookup, so that a blocked caller can't use it as an
/// existence oracle.
///
/// `Ok(false)` means denied; callers report that as an invalid credential, so a
/// denial is indistinguishable from a bad credential.
pub async fn vet_credential_bearer(
    login_protection: &LoginProtectionService,
    user: &User,
    remote_ip: Option<IpAddr>,
) -> Result<bool, WarpgateError> {
    if login_protection
        .check_user_locked(&user.username)
        .await?
        .is_some()
    {
        tracing::warn!("Credential presented for a locked user: {}", user.username);
        return Ok(false);
    }
    Ok(check_ip_allowed(user.allowed_ip_ranges.as_ref(), remote_ip, &user.username).is_ok())
}

/// Record a failed attempt for an unknown username so that username
/// enumeration counts toward IP blocking, just like a wrong password would.
///
/// `credential_type` is `None` for contexts that must not be penalised —
/// notably SSH public-key offers, which legitimately fail as clients try
/// each agent key in turn — in which case nothing is recorded.
async fn record_unknown_user_attempt(
    login_protection: &LoginProtectionService,
    username: &str,
    protocol: Protocol,
    remote_ip: Option<IpAddr>,
    credential_type: Option<&str>,
) {
    let (Some(remote_ip), Some(credential_type)) = (remote_ip, credential_type) else {
        return;
    };
    let _ = login_protection
        .record_failed_attempt(FailedAttemptInfo {
            username: username.to_string(),
            remote_ip,
            protocol,
            credential_type: credential_type.to_string(),
        })
        .await;
}

/// Waits until the auth state reaches a terminal result (accepted or
/// rejected), or [`TIMEOUT`] elapses (treated as rejection).
///
/// Subscribing and checking happen under a single state lock, and state
/// changes are only broadcast while that same lock is held — so a transition
/// cannot slip between the check and the subscription.
pub async fn wait_for_auth_completion(state_arc: &Arc<Mutex<AuthState>>) -> AuthResult {
    wait_for_auth_completion_within(state_arc, *TIMEOUT).await
}

async fn wait_for_auth_completion_within(
    state_arc: &Arc<Mutex<AuthState>>,
    timeout: Duration,
) -> AuthResult {
    let mut rx = {
        let state = state_arc.lock().await;
        match state.verify() {
            result @ (AuthResult::Accepted { .. } | AuthResult::Rejected) => return result,
            AuthResult::Need(_) => state.subscribe(),
        }
    };
    tokio::time::timeout(timeout, async {
        loop {
            match rx.recv().await {
                Ok(result @ (AuthResult::Accepted { .. } | AuthResult::Rejected)) => return result,
                Ok(AuthResult::Need(_)) => (),
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    let result = state_arc.lock().await.verify();
                    if !matches!(result, AuthResult::Need(_)) {
                        return result;
                    }
                }
                Err(broadcast::error::RecvError::Closed) => return AuthResult::Rejected,
            }
        }
    })
    .await
    .unwrap_or(AuthResult::Rejected)
}

pub struct AuthStateStore {
    store: HashMap<UserSessionId, (Arc<Mutex<AuthState>>, Instant)>,
    web_auth_request_signal: broadcast::Sender<UserSessionId>,
    recent_approvals: HashMap<WebApprovalMatchKey, Instant>,
}

impl Default for AuthStateStore {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthStateStore {
    pub fn new() -> Self {
        Self {
            store: HashMap::new(),
            web_auth_request_signal: broadcast::channel(100).0,
            recent_approvals: HashMap::new(),
        }
    }

    pub fn contains_key(&self, id: &UserSessionId) -> bool {
        self.store.contains_key(id)
    }

    /// Returns cloned `Arc` handles to every stored [`AuthState`].
    ///
    /// This only clones the handles and never locks the inner states, so the
    /// store lock is held for the shortest possible time. Callers can then
    /// inspect each state (which requires locking it) *after* releasing the
    /// store lock, avoiding lock convoys on the store under concurrent logins.
    pub fn snapshot_states(&self) -> Vec<Arc<Mutex<AuthState>>> {
        self.store.values().map(|auth| auth.0.clone()).collect()
    }

    pub fn get(&self, id: &UserSessionId) -> Option<Arc<Mutex<AuthState>>> {
        self.store.get(id).map(|x| x.0.clone())
    }

    pub fn subscribe_web_auth_request(&self) -> broadcast::Receiver<UserSessionId> {
        self.web_auth_request_signal.subscribe()
    }

    /// Resolves the user record and credential policy for an authentication
    /// attempt.
    ///
    /// This performs the config-provider database lookups (`list_users`,
    /// `get_credential_policy`) and the IP-range check **without** holding the
    /// [`AuthStateStore`] lock. Callers must run this before locking the store
    /// and pass the result to [`AuthStateStore::create`], so that concurrent
    /// logins don't serialise on the store lock while doing database I/O.
    pub(crate) async fn resolve_user_and_policy(
        config_provider: &Arc<ConfigProviderEnum>,
        login_protection: &LoginProtectionService,
        username: &str,
        protocol: Protocol,
        supported_credential_types: &[CredentialKind],
        remote_ip: Option<IpAddr>,
        rate_limit_credential_type: Option<&str>,
    ) -> Result<(User, Box<dyn CredentialPolicy + Sync + Send>), WarpgateError> {
        let Some(user) = config_provider
            .list_users()
            .await?
            .iter()
            .find(|u| username_eq_ci(&u.username, username))
            .cloned()
        else {
            record_unknown_user_attempt(
                login_protection,
                username,
                protocol,
                remote_ip,
                rate_limit_credential_type,
            )
            .await;
            return Err(WarpgateError::UserNotFound(username.into()));
        };

        check_ip_allowed(user.allowed_ip_ranges.as_ref(), remote_ip, username)?;

        let policy = config_provider
            .get_credential_policy(username, supported_credential_types)
            .await?;
        let Some(policy) = policy else {
            record_unknown_user_attempt(
                login_protection,
                username,
                protocol,
                remote_ip,
                rate_limit_credential_type,
            )
            .await;
            return Err(WarpgateError::UserNotFound(username.into()));
        };

        Ok((user, policy))
    }

    /// Creates and stores a new [`AuthState`] from an already-resolved user and
    /// credential policy (see [`AuthStateStore::resolve_user_and_policy`]).
    ///
    /// This is deliberately synchronous and does no database I/O, so the store
    /// lock is only held for the in-memory insert.
    ///
    /// A session holds at most one auth state, keyed by its session id, so a new
    /// attempt on the same session (a different username or target) supersedes
    /// the previous one. Anything already waiting on the old state holds its
    /// `Arc` and still observes its outcome; it just stops being reachable by
    /// session id.
    pub(crate) fn create(
        &mut self,
        session_id: &UserSessionId,
        user: &User,
        protocol: Protocol,
        target_name: &str,
        policy: Box<dyn CredentialPolicy + Sync + Send>,
        remote_ip: Option<IpAddr>,
    ) -> Arc<Mutex<AuthState>> {
        // The auth state is identified by its session id, so a cross-node web
        // approval can resolve the owning node straight from the `user_sessions`
        // table (which records `node_id`).
        let id = *session_id;

        // Small backlog so subscribers that briefly fall behind still see the
        // terminal transition; laggards re-check the state directly.
        let (state_change_tx, mut state_change_rx) = broadcast::channel(8);
        let web_auth_request_signal = self.web_auth_request_signal.clone();
        tokio::spawn(async move {
            while let Ok(AuthResult::Need(result)) = state_change_rx.recv().await {
                if result.contains(&CredentialKind::WebUserApproval) {
                    let _ = web_auth_request_signal.send(id);
                }
            }
        });

        let state = AuthState::new(
            id,
            remote_ip,
            user.into(),
            protocol,
            target_name.to_string(),
            policy,
            state_change_tx,
        );
        let state_arc = Arc::new(Mutex::new(state));
        self.store.insert(id, (state_arc.clone(), Instant::now()));

        state_arc
    }

    /// Drops a session's auth state, so a cancelled login stops being reachable
    /// by session id.
    pub fn remove(&mut self, session_id: &UserSessionId) {
        self.store.remove(session_id);
    }

    /// Drops a session's auth state only if it is still `state`: a concurrent
    /// attempt may have superseded it, and the newer attempt must not be torn
    /// down by the older one's cleanup.
    pub fn remove_if_same(&mut self, session_id: &UserSessionId, state: &Arc<Mutex<AuthState>>) {
        if self
            .get(session_id)
            .is_some_and(|current| Arc::ptr_eq(&current, state))
        {
            self.store.remove(session_id);
        }
    }

    /// Records a web approval for later bypass checks
    pub fn record_web_approval(&mut self, key: WebApprovalMatchKey) {
        self.recent_approvals.insert(key, Instant::now());
    }

    pub fn recent_approval_is_fresh(&self, key: &WebApprovalMatchKey, grace: Duration) -> bool {
        self.recent_approvals
            .get(key)
            .is_some_and(|at| at.elapsed() < grace)
    }

    /// If there is a matching web approval within `grace`, accept it as a valid credential
    pub async fn try_web_approval_bypass(
        &self,
        state_arc: &Arc<Mutex<AuthState>>,
        grace: Duration,
    ) -> Result<bool, WarpgateError> {
        let Some(key) = state_arc.lock().await.web_approval_match_key() else {
            return Ok(false);
        };

        // A remembered approval matches this exact scope, or one granted for all
        // targets. The all-targets probe deliberately also covers an untargeted
        // login: approving every target is strictly broader than approving a
        // portal sign-in, so it subsumes it.
        if !self.recent_approval_is_fresh(&key, grace)
            && !self.recent_approval_is_fresh(&key.for_all_targets(), grace)
        {
            return Ok(false);
        }

        let mut state = state_arc.lock().await;

        // A concurrent change may have satisfied or cancelled the requirement.
        if !matches!(state.verify(), AuthResult::Need(ref kinds) if kinds.contains(&CredentialKind::WebUserApproval))
        {
            return Ok(false);
        }

        state.add_web_user_approval();
        state.emit_web_approval_bypassed_event();
        Ok(true)
    }

    pub fn vacuum(&mut self) {
        self.store
            .retain(|_, (_, started_at)| started_at.elapsed() < *TIMEOUT);

        self.recent_approvals
            .retain(|_, at| at.elapsed() < RECENT_APPROVAL_RETENTION);
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ipnet::IpNet;
    use uuid::Uuid;
    use warpgate_common::auth::{
        AuthCredential, AuthCredentialFingerprint, AuthStateUserInfo, CredentialPolicyResponse,
        WebApprovalScopeKey,
    };

    use super::*;

    struct RequireWebApproval;

    impl CredentialPolicy for RequireWebApproval {
        fn is_sufficient(
            &self,
            _protocol: Protocol,
            valid_credentials: &[AuthCredential],
        ) -> CredentialPolicyResponse {
            if valid_credentials
                .iter()
                .any(|c| c.kind() == CredentialKind::WebUserApproval)
            {
                CredentialPolicyResponse::Ok
            } else {
                CredentialPolicyResponse::Need(
                    [CredentialKind::WebUserApproval].into_iter().collect(),
                )
            }
        }
    }

    fn interactive_state() -> Arc<Mutex<AuthState>> {
        Arc::new(Mutex::new(AuthState::new(
            UserSessionId(Uuid::new_v4()),
            None,
            AuthStateUserInfo {
                id: Uuid::new_v4(),
                username: "alice".into(),
            },
            Protocol::Ssh,
            "target".into(),
            Box::new(RequireWebApproval),
            broadcast::channel(8).0,
        )))
    }

    fn test_user() -> User {
        User {
            id: Uuid::new_v4(),
            username: "alice".into(),
            description: String::new(),
            credential_policy: None,
            rate_limit_bytes_per_second: None,
            ldap_server_id: None,
            allowed_ip_ranges: None,
        }
    }

    fn create_for(
        store: &mut AuthStateStore,
        user: &User,
        session_id: &UserSessionId,
    ) -> Arc<Mutex<AuthState>> {
        store.create(
            session_id,
            user,
            Protocol::Ssh,
            "target",
            Box::new(RequireWebApproval),
            None,
        )
    }

    // Cross-node web-approval routing keys on this: an auth state is identified
    // by its session id, so the owning node resolves from `user_sessions`.
    #[tokio::test]
    async fn create_keys_auth_state_by_session_id() {
        let mut store = AuthStateStore::new();
        let user = test_user();
        let session_id = UserSessionId(Uuid::new_v4());

        let state = create_for(&mut store, &user, &session_id);
        assert!(Arc::ptr_eq(&store.get(&session_id).unwrap(), &state));
    }

    #[tokio::test]
    async fn a_new_attempt_supersedes_the_session_s_previous_state() {
        let mut store = AuthStateStore::new();
        let user = test_user();
        let session_id = UserSessionId(Uuid::new_v4());

        let first = create_for(&mut store, &user, &session_id);
        let second = create_for(&mut store, &user, &session_id);

        assert!(!Arc::ptr_eq(&second, &first));
        assert!(Arc::ptr_eq(&store.get(&session_id).unwrap(), &second));

        // The superseded attempt's cleanup must not tear down the newer one.
        store.remove_if_same(&session_id, &first);
        assert!(store.contains_key(&session_id));

        store.remove_if_same(&session_id, &second);
        assert!(!store.contains_key(&session_id));
    }

    #[tokio::test]
    async fn wait_returns_immediately_when_already_terminal() {
        let state = interactive_state();
        state.lock().await.reject();
        assert!(matches!(
            wait_for_auth_completion(&state).await,
            AuthResult::Rejected
        ));
    }

    #[tokio::test]
    async fn wait_resolves_on_approval() {
        let state = interactive_state();
        let waiter = {
            let state = state.clone();
            tokio::spawn(async move { wait_for_auth_completion(&state).await })
        };
        tokio::task::yield_now().await;
        let _ = state.lock().await.add_web_user_approval();
        assert!(matches!(waiter.await.unwrap(), AuthResult::Accepted { .. }));
    }

    #[tokio::test]
    async fn wait_resolves_on_rejection() {
        let state = interactive_state();
        let waiter = {
            let state = state.clone();
            tokio::spawn(async move { wait_for_auth_completion(&state).await })
        };
        tokio::task::yield_now().await;
        state.lock().await.reject();
        assert!(matches!(waiter.await.unwrap(), AuthResult::Rejected));
    }

    #[tokio::test]
    async fn wait_times_out_to_rejected() {
        let state = interactive_state();
        assert!(matches!(
            wait_for_auth_completion_within(&state, Duration::from_millis(50)).await,
            AuthResult::Rejected
        ));
    }

    #[test]
    fn ip_allowed_no_restriction() {
        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        assert!(check_ip_allowed(None, Some(ip), "user").is_ok());
    }

    #[test]
    fn ip_allowed_no_remote_ip() {
        let range = Some(vec![IpNet::from_str("10.0.0.0/8").unwrap().into()]);
        assert!(check_ip_allowed(range.as_ref(), None, "user").is_ok());
    }

    #[test]
    fn ip_allowed_within_range() {
        let range = Some(vec![IpNet::from_str("192.168.1.0/24").unwrap().into()]);
        let ip: IpAddr = "192.168.1.42".parse().unwrap();
        assert!(check_ip_allowed(range.as_ref(), Some(ip), "user").is_ok());
    }

    #[test]
    fn ip_denied_outside_range() {
        let range = Some(vec![IpNet::from_str("192.168.1.0/24").unwrap().into()]);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let err = check_ip_allowed(range.as_ref(), Some(ip), "testuser").unwrap_err();
        assert!(
            matches!(err, WarpgateError::IpAddrNotAllowed(addr, user) if addr == "10.0.0.1" && user == "testuser")
        );
    }

    #[test]
    fn ip_allowed_exact_match() {
        let range = Some(vec![IpNet::from_str("10.20.30.40/32").unwrap().into()]);
        let ip: IpAddr = "10.20.30.40".parse().unwrap();
        assert!(check_ip_allowed(range.as_ref(), Some(ip), "user").is_ok());
    }

    #[test]
    fn ip_denied_exact_mismatch() {
        let range = Some(vec![IpNet::from_str("10.20.30.40/32").unwrap().into()]);
        let ip: IpAddr = "10.20.30.41".parse().unwrap();
        assert!(check_ip_allowed(range.as_ref(), Some(ip), "user").is_err());
    }

    #[test]
    fn ipv6_allowed_within_range() {
        let range = Some(vec![IpNet::from_str("fd00::/8").unwrap().into()]);
        let ip: IpAddr = "fd12:3456::1".parse().unwrap();
        assert!(check_ip_allowed(range.as_ref(), Some(ip), "user").is_ok());
    }

    #[test]
    fn ipv6_denied_outside_range() {
        let range = Some(vec![IpNet::from_str("fd00::/8").unwrap().into()]);
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(check_ip_allowed(range.as_ref(), Some(ip), "user").is_err());
    }

    #[test]
    fn ip_allowed_both_none() {
        assert!(check_ip_allowed(None, None, "user").is_ok());
    }

    #[test]
    fn ip_allowed_empty_ranges_treated_as_no_restriction() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(check_ip_allowed(Some(&vec![]), Some(ip), "user").is_ok());
    }

    #[test]
    fn ipv4_mapped_ipv6_matches_ipv4_range() {
        let range = Some(vec![IpNet::from_str("192.168.1.0/24").unwrap().into()]);
        // ::ffff:192.168.1.42 is the IPv4-mapped IPv6 form of 192.168.1.42
        let ip: IpAddr = "::ffff:192.168.1.42".parse().unwrap();
        assert!(check_ip_allowed(range.as_ref(), Some(ip), "user").is_ok());
    }

    #[test]
    fn ipv4_mapped_ipv6_denied_outside_ipv4_range() {
        let range = Some(vec![IpNet::from_str("192.168.1.0/24").unwrap().into()]);
        let ip: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        assert!(check_ip_allowed(range.as_ref(), Some(ip), "user").is_err());
    }

    #[test]
    fn ip_allowed_helper_matches_auth_path_semantics() {
        let range = Some(vec![IpNet::from_str("10.0.0.0/8").unwrap().into()]);
        // In range -> allowed.
        assert!(ip_allowed(
            range.as_ref(),
            Some("10.1.2.3".parse().unwrap())
        ));
        // Out of range -> denied.
        assert!(!ip_allowed(
            range.as_ref(),
            Some("192.168.0.1".parse().unwrap())
        ));
        // Empty range list is unrestricted.
        assert!(ip_allowed(
            Some(&vec![]),
            Some("192.168.0.1".parse().unwrap())
        ));
        // No remote IP is treated as unrestricted.
        assert!(ip_allowed(range.as_ref(), None));
        // No restriction configured.
        assert!(ip_allowed(None, Some("192.168.0.1".parse().unwrap())));
    }

    fn approval_key(scope: WebApprovalScopeKey) -> WebApprovalMatchKey {
        WebApprovalMatchKey {
            remote_ip: "10.0.0.5".parse().unwrap(),
            protocol: Protocol::Ssh,
            username: "alice".into(),
            scope,
            other_credentials: vec![AuthCredentialFingerprint::Password { hash: [7u8; 32] }],
        }
    }

    fn for_target(name: &str) -> WebApprovalMatchKey {
        approval_key(WebApprovalScopeKey::Target(name.into()))
    }

    #[test]
    fn web_approval_bypass_requires_full_match_within_grace() {
        let mut store = AuthStateStore::new();
        let grace = Duration::from_secs(3600);

        // No approval recorded yet.
        assert!(!store.recent_approval_is_fresh(&for_target("prod"), grace));

        store.record_web_approval(for_target("prod"));

        // Exact match within grace bypasses.
        assert!(store.recent_approval_is_fresh(&for_target("prod"), grace));
        // A different target is not a full match.
        assert!(!store.recent_approval_is_fresh(&for_target("staging"), grace));
        // Different credentials are not a full match.
        let mut wrong_cred = for_target("prod");
        wrong_cred.other_credentials =
            vec![AuthCredentialFingerprint::Password { hash: [9u8; 32] }];
        assert!(!store.recent_approval_is_fresh(&wrong_cred, grace));
        // A zero grace never counts as fresh, so approval is required again.
        assert!(!store.recent_approval_is_fresh(&for_target("prod"), Duration::ZERO));
    }

    #[test]
    fn web_approval_for_all_targets_matches_any_target() {
        let mut store = AuthStateStore::new();
        let grace = Duration::from_secs(3600);

        store.record_web_approval(approval_key(WebApprovalScopeKey::AllTargets));

        // An all-targets approval is found via `for_all_targets` for any target.
        assert!(store.recent_approval_is_fresh(&for_target("prod").for_all_targets(), grace));
        assert!(store.recent_approval_is_fresh(&for_target("staging").for_all_targets(), grace));
        // ...but not by an exact-target lookup.
        assert!(!store.recent_approval_is_fresh(&for_target("prod"), grace));
    }

    #[test]
    fn untargeted_approval_is_its_own_bucket() {
        let mut store = AuthStateStore::new();
        let grace = Duration::from_secs(3600);

        // An HTTP sign-in / SSH menu login carries no target.
        store.record_web_approval(approval_key(WebApprovalScopeKey::Untargeted));

        assert!(
            store.recent_approval_is_fresh(&approval_key(WebApprovalScopeKey::Untargeted), grace)
        );
        // It must not stand in for approval of an actual target...
        assert!(!store.recent_approval_is_fresh(&for_target("prod"), grace));
        // ...nor be mistaken for an all-targets grant.
        assert!(!store.recent_approval_is_fresh(&for_target("prod").for_all_targets(), grace));
    }

    #[test]
    fn all_targets_approval_covers_an_untargeted_login() {
        let mut store = AuthStateStore::new();
        let grace = Duration::from_secs(3600);

        store.record_web_approval(approval_key(WebApprovalScopeKey::AllTargets));

        // Deliberate: approving every target subsumes a portal sign-in, and the
        // bypass reaches it through the same `for_all_targets` probe.
        assert!(store.recent_approval_is_fresh(
            &approval_key(WebApprovalScopeKey::Untargeted).for_all_targets(),
            grace
        ));
        // The untargeted bucket itself stays empty.
        assert!(
            !store.recent_approval_is_fresh(&approval_key(WebApprovalScopeKey::Untargeted), grace)
        );
    }
}

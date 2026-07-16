use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, broadcast};
use uuid::Uuid;
use warpgate_common::auth::{
    AuthCredential, AuthResult, AuthState, CredentialKind, CredentialPolicy, WebApprovalMatchKey,
};
use warpgate_common::helpers::ipnet::WarpgateIpNet;
use warpgate_common::helpers::username::username_eq_ci;
use warpgate_common::{SessionId, User, WarpgateError};

use crate::login_protection::{FailedAttemptInfo, LoginProtectionService};
use crate::{ConfigProvider, ConfigProviderEnum};

#[allow(clippy::unwrap_used)]
pub static TIMEOUT: LazyLock<Duration> = LazyLock::new(|| Duration::from_secs(60 * 10));

// Absolute maximum cache duration for cleanup
const RECENT_APPROVAL_RETENTION: Duration = Duration::from_secs(60 * 60 * 24 * 30);

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

/// Checks whether the given IP is allowed by the user's `allowed_ip_ranges` setting.
/// Returns `Ok(())` if access is allowed, or an appropriate `WarpgateError` if denied.
fn check_ip_allowed(
    allowed_ip_ranges: Option<&Vec<WarpgateIpNet>>,
    remote_ip: Option<IpAddr>,
    username: &str,
) -> Result<(), WarpgateError> {
    let Some(ranges) = allowed_ip_ranges else {
        return Ok(());
    };
    if ranges.is_empty() {
        return Ok(());
    }
    let Some(raw_ip) = remote_ip else {
        return Ok(());
    };
    let ip = normalize_ip(raw_ip);
    for network in ranges {
        if network.contains(&ip) {
            return Ok(());
        }
    }
    tracing::warn!(
        "Access denied for IP '{}' (not in any allowed range for user '{}')",
        ip,
        username
    );
    Err(WarpgateError::IpAddrNotAllowed(
        ip.to_string(),
        username.into(),
    ))
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
    protocol: &str,
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
            protocol: protocol.to_string(),
            credential_type: credential_type.to_string(),
        })
        .await;
}

struct AuthCompletionSignal {
    sender: broadcast::Sender<AuthResult>,
    created_at: Instant,
}

impl AuthCompletionSignal {
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > *TIMEOUT
    }
}

pub struct AuthStateStore {
    store: HashMap<Uuid, (Arc<Mutex<AuthState>>, Instant)>,
    completion_signals: HashMap<Uuid, AuthCompletionSignal>,
    web_auth_request_signal: broadcast::Sender<Uuid>,
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
            completion_signals: HashMap::new(),
            web_auth_request_signal: broadcast::channel(100).0,
            recent_approvals: HashMap::new(),
        }
    }

    pub fn contains_key(&self, id: &Uuid) -> bool {
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

    pub fn get(&self, id: &Uuid) -> Option<Arc<Mutex<AuthState>>> {
        self.store.get(id).map(|x| x.0.clone())
    }

    pub fn subscribe_web_auth_request(&self) -> broadcast::Receiver<Uuid> {
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
        protocol: &str,
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
    pub(crate) fn create(
        &mut self,
        session_id: Option<&SessionId>,
        user: &User,
        protocol: &str,
        target_name: &str,
        policy: Box<dyn CredentialPolicy + Sync + Send>,
        remote_ip: Option<IpAddr>,
    ) -> (Uuid, Arc<Mutex<AuthState>>) {
        let id = Uuid::new_v4();

        let (state_change_tx, mut state_change_rx) = broadcast::channel(1);
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
            session_id.copied(),
            remote_ip,
            user.into(),
            protocol.to_string(),
            target_name.to_string(),
            policy,
            state_change_tx,
        );
        let state_arc = Arc::new(Mutex::new(state));
        self.store.insert(id, (state_arc.clone(), Instant::now()));

        (id, state_arc)
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
            return Ok(false)
        };

        // A remembered approval matches either this exact target or all targets.
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

        state.add_valid_credential(AuthCredential::WebUserApproval);
        state.emit_web_approval_bypassed_event();
        Ok(true)
    }

    pub fn subscribe(&mut self, id: Uuid) -> broadcast::Receiver<AuthResult> {
        let signal = self.completion_signals.entry(id).or_insert_with(|| {
            let (sender, _) = broadcast::channel(1);
            AuthCompletionSignal {
                sender,
                created_at: Instant::now(),
            }
        });

        signal.sender.subscribe()
    }

    pub async fn complete(&mut self, id: &Uuid) {
        let Some((state, _)) = self.store.get(id) else {
            return;
        };
        if let Some(sig) = self.completion_signals.remove(id) {
            let _ = sig.sender.send(state.lock().await.verify());
        }
    }

    pub fn vacuum(&mut self) {
        self.store
            .retain(|_, (_, started_at)| started_at.elapsed() < *TIMEOUT);

        self.completion_signals
            .retain(|_, signal| !signal.is_expired());

        self.recent_approvals
            .retain(|_, at| at.elapsed() < RECENT_APPROVAL_RETENTION);
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ipnet::IpNet;
    use warpgate_common::auth::AuthCredentialFingerprint;

    use super::*;

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

    fn approval_key(target: Option<&str>) -> WebApprovalMatchKey {
        WebApprovalMatchKey {
            remote_ip: "10.0.0.5".parse().unwrap(),
            protocol: "ssh".into(),
            username: "alice".into(),
            target_name: target.map(Into::into),
            other_credentials: vec![AuthCredentialFingerprint::Password { hash: [7u8; 32] }],
        }
    }

    #[test]
    fn web_approval_bypass_requires_full_match_within_grace() {
        let mut store = AuthStateStore::new();
        let grace = Duration::from_secs(3600);

        // No approval recorded yet.
        assert!(!store.recent_approval_is_fresh(&approval_key(Some("prod")), grace));

        store.record_web_approval(approval_key(Some("prod")));

        // Exact match within grace bypasses.
        assert!(store.recent_approval_is_fresh(&approval_key(Some("prod")), grace));
        // A different target is not a full match.
        assert!(!store.recent_approval_is_fresh(&approval_key(Some("staging")), grace));
        // Different credentials are not a full match.
        let mut wrong_cred = approval_key(Some("prod"));
        wrong_cred.other_credentials = vec![AuthCredentialFingerprint::Password { hash: [9u8; 32] }];
        assert!(!store.recent_approval_is_fresh(&wrong_cred, grace));
        // A zero grace never counts as fresh, so approval is required again.
        assert!(!store.recent_approval_is_fresh(&approval_key(Some("prod")), Duration::ZERO));
    }

    #[test]
    fn web_approval_for_all_targets_matches_any_target() {
        let mut store = AuthStateStore::new();
        let grace = Duration::from_secs(3600);

        store.record_web_approval(approval_key(None));

        // An all-targets approval is found via `for_all_targets` for any target.
        assert!(store.recent_approval_is_fresh(&approval_key(Some("prod")).for_all_targets(), grace));
        assert!(
            store.recent_approval_is_fresh(&approval_key(Some("staging")).for_all_targets(), grace)
        );
        // ...but not by an exact-target lookup.
        assert!(!store.recent_approval_is_fresh(&approval_key(Some("prod")), grace));
    }
}

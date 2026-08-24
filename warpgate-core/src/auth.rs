use tracing::warn;
use warpgate_common::WarpgateError;
use warpgate_common::auth::{AuthCredential, AuthState, SubmitOutcome};

use crate::ConfigProvider;
use crate::login_protection::LoginProtectionService;

/// The one per-submission choke point for brute-force protection: a login path
/// that skips its own pre-checks still cannot validate a credential for a
/// blocked IP or a locked-out user. The refusal reads as an invalid credential,
/// so every caller fails closed without knowing about the gate.
pub async fn submit_credential<C: ConfigProvider>(
    state: &mut AuthState,
    credential: AuthCredential,
    cp: &C,
    login_protection: &LoginProtectionService,
) -> Result<SubmitOutcome, WarpgateError> {
    if let Some(ip) = state.remote_ip()
        && login_protection.check_ip_blocked(&ip).await?.is_some()
    {
        warn!(%ip, "Credential submission from a blocked IP");
        return Ok(SubmitOutcome::Invalid(state.verify()));
    }
    if login_protection
        .check_user_locked(&state.user_info().username)
        .await?
        .is_some()
    {
        warn!(username = %state.user_info().username, "Credential submission for a locked-out user");
        return Ok(SubmitOutcome::Invalid(state.verify()));
    }

    state
        .submit_credential(credential, |username, credential| async move {
            cp.validate_credential(&username, &credential).await
        })
        .await
}

//! Shared viewer authentication for the native desktop protocols (RDP, VNC).
//!
//! Both collect a username + password up front and then, when the credential policy needs
//! more, gather an interactive second factor (TOTP / web approval) on a per-protocol holding
//! screen. The up-front evaluation, target resolution, brute-force wiring, and web-approval
//! URL are identical between them and live here once; each protocol supplies only its
//! options-variant type (`TargetVncOptions` / `TargetRdpOptions`), which carries the
//! protocol name and narrows the target.

mod hold_screen;
mod otp;

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{Result, bail};
pub use hold_screen::{
    Deadline, HoldEvent, HoldFrame, HoldInputSource, HoldPainter, run_hold_screen,
};
pub use otp::{MAX_OTP_ATTEMPTS, OtpAction, OtpActionApplyOutcome, OtpEntry};
use tokio::sync::Mutex;
use tracing::warn;
use warpgate_common::auth::{AuthCredential, AuthResult, AuthSelector, AuthState, CredentialKind};
use warpgate_common::{Secret, TargetOptionsVariant, TargetSessionId, UserSessionId};
use warpgate_common_http::ext::construct_external_url;
use warpgate_core::auth::submit_credential;
use warpgate_core::login_protection::FailedAttemptInfo;
use warpgate_core::recordings::{DesktopRecorder, DesktopRecordingMetadata};
use warpgate_core::{
    AuthorizedIdentity, Services, TargetAuthorization, WarpgateServerHandle,
    authorize_for_target_by_name, authorize_and_spend_ticket,
};
use warpgate_desktop_ui::AuthPrompt;

/// A session awaiting its interactive second factor after a valid password.
pub struct InteractiveAuth {
    pub state_id: UserSessionId,
    pub username: String,
    pub target_name: String,
    pub remote_ip: IpAddr,
}

/// Result of evaluating the viewer's up-front (password / ticket) credentials.
#[allow(clippy::large_enum_variant)]
pub enum DesktopAuthOutcome<O> {
    /// Fully authenticated (password-only policy, or ticket auth). The target
    /// and its protocol-specific options travel inside the authorization.
    Authorized {
        authorization: TargetAuthorization<O>,
    },
    /// Password accepted, but the policy needs an interactive second factor — collected on
    /// the per-protocol holding screen.
    NeedsInteractive(InteractiveAuth),
    /// Rejected, invalid, blocked, or a required factor that can't be collected over the
    /// desktop protocol.
    Failed,
}

/// Evaluate the viewer's submitted credentials for the protocol whose options
/// variant is `O`.
///
/// A password-only policy (or a ticket) authorises immediately; a policy that additionally
/// needs a factor the holding screen can collect (TOTP / web approval) — and *only* such
/// factors — returns [`DesktopAuthOutcome::NeedsInteractive`]. Anything else fails.
pub async fn authenticate<O: TargetOptionsVariant>(
    services: &Services,
    server_handle: &Arc<Mutex<WarpgateServerHandle>>,
    selector: &str,
    password: String,
    remote_address: SocketAddr,
) -> Result<DesktopAuthOutcome<O>> {
    let selector: AuthSelector = selector.into();

    match selector {
        AuthSelector::User {
            username,
            target_name,
        } => {
            let remote_ip = remote_address.ip();

            // Brute-force protection: reject blocked IPs / locked users before evaluating
            // credentials. Fail closed (propagate lookup errors).
            if services
                .login_protection
                .check_ip_blocked(&remote_ip)
                .await?
                .is_some()
            {
                warn!(ip = %remote_ip, protocol = %O::PROTOCOL, "Desktop auth attempt from blocked IP");
                return Ok(DesktopAuthOutcome::Failed);
            }
            if services
                .login_protection
                .check_user_locked(&username)
                .await?
                .is_some()
            {
                warn!(username = %username, protocol = %O::PROTOCOL, "Desktop auth attempt for locked user");
                return Ok(DesktopAuthOutcome::Failed);
            }

            let session_id = server_handle.lock().await.user_session_id();

            let state_arc = services
                .create_auth_state(
                    &session_id,
                    &username,
                    O::PROTOCOL,
                    &target_name,
                    &[
                        CredentialKind::Password,
                        CredentialKind::Totp,
                        CredentialKind::WebUserApproval,
                    ],
                    Some(remote_address.ip()),
                    Some("password"),
                )
                .await?;

            // Password is mandatory; we don't serve an anonymous session.
            {
                let mut state = state_arc.lock().await;
                let outcome = submit_credential(
                    &mut state,
                    AuthCredential::Password(Secret::new(password)),
                    services.config_provider.as_ref(),
                    &services.login_protection,
                )
                .await?;
                if !outcome.is_valid() {
                    let _ = services
                        .login_protection
                        .record_failed_attempt(FailedAttemptInfo {
                            username: username.clone(),
                            remote_ip,
                            protocol: O::PROTOCOL,
                            credential_type: "password".to_string(),
                        })
                        .await;
                    return Ok(DesktopAuthOutcome::Failed);
                }
            }

            // Bypass the web-approval step when a matching approval is still
            // within the grace period.
            let needs_web_approval = matches!(
                state_arc.lock().await.verify(),
                AuthResult::Need(ref kinds) if kinds.contains(&CredentialKind::WebUserApproval)
            );
            if needs_web_approval {
                services.try_web_approval_bypass(&state_arc).await?;
            }

            let verification = state_arc.lock().await.verify();
            match verification {
                AuthResult::Accepted { user_info } => {
                    let _ = services
                        .login_protection
                        .clear_failed_attempts(&remote_ip, &user_info.username)
                        .await;
                    // Verified `Accepted` a moment ago; a state that no longer
                    // is means the login was concurrently rejected — deny.
                    let Some(identity) =
                        AuthorizedIdentity::from_auth_state(&*state_arc.lock().await)
                    else {
                        return Ok(DesktopAuthOutcome::Failed);
                    };
                    let authorization =
                        finalize_user_auth::<O>(services, &identity, &target_name).await?;
                    Ok(DesktopAuthOutcome::Authorized { authorization })
                }
                // Go interactive only when *every* still-needed factor is one the holding
                // screen can collect; otherwise the session could never complete.
                AuthResult::Need(kinds)
                    if kinds.iter().all(|k| {
                        matches!(k, CredentialKind::Totp | CredentialKind::WebUserApproval)
                    }) =>
                {
                    Ok(DesktopAuthOutcome::NeedsInteractive(InteractiveAuth {
                        state_id: session_id,
                        username,
                        target_name,
                        remote_ip,
                    }))
                }
                AuthResult::Need(_) | AuthResult::Rejected => Ok(DesktopAuthOutcome::Failed),
            }
        }
        AuthSelector::Ticket { secret } => {
            match authorize_and_spend_ticket(
                &services.db,
                &services.login_protection,
                &secret,
                Some(remote_address.ip()),
                O::PROTOCOL,
            )
            .await?
            {
                Some(authorization) => {
                    let target_name = authorization.target().name.clone();
                    let Ok(authorization) = authorization.narrow::<O>() else {
                        bail!("Target {target_name} is not a {} target", O::PROTOCOL);
                    };
                    Ok(DesktopAuthOutcome::Authorized { authorization })
                }
                None => Ok(DesktopAuthOutcome::Failed),
            }
        }
    }
}

/// Authorise an authenticated identity against a target and narrow it to the
/// protocol's options variant. Used after the holding screen completes the
/// interactive factor; taking the sealed [`AuthorizedIdentity`] means the
/// authentication behind it happened by construction.
pub async fn finalize_user_auth<O: TargetOptionsVariant>(
    services: &Services,
    identity: &AuthorizedIdentity,
    target_name: &str,
) -> Result<TargetAuthorization<O>> {
    let Some(authorization) =
        authorize_for_target_by_name(services.config_provider.as_ref(), &identity, target_name)
            .await?
    else {
        bail!(
            "Target {target_name} not authorized for {}",
            identity.username
        );
    };
    let Ok(authorization) = authorization.narrow::<O>() else {
        bail!("Target {target_name} is not a {} target", O::PROTOCOL);
    };
    Ok(authorization)
}

/// Build the browser web-approval URL for the current auth state, or `None` if the external
/// URL can't be constructed.
async fn web_approval_url(services: &Services, state: &Arc<Mutex<AuthState>>) -> Option<String> {
    let external_url = {
        let config = services.config.lock().await;
        construct_external_url(None, &config, None)
            .await
            .inspect_err(|error| warn!(%error, "Failed to construct external URL"))
            .ok()?
    };
    let url = state.lock().await.construct_web_approval_url(external_url);
    Some(url.to_string())
}

/// Start a Desktop recording for a native desktop session (RDP / VNC). Returns `None` when
/// recording is disabled, or fails to start (logged against `protocol_label`).
pub async fn start_recording(
    services: &Services,
    target_session_id: &TargetSessionId,
    protocol_label: &str,
) -> Option<DesktopRecorder> {
    match services
        .recordings
        .start::<DesktopRecorder, _>(target_session_id, None, DesktopRecordingMetadata::Desktop)
        .await
    {
        Ok(recorder) => Some(recorder),
        Err(warpgate_core::recordings::Error::Disabled) => None,
        Err(error) => {
            warn!(%error, protocol = protocol_label, "Failed to start desktop session recording");
            None
        }
    }
}

/// Pick the holding-screen prompt for the still-needed credentials: TOTP takes precedence
/// over web approval when the policy allows either. `None` when neither is collectable on the
/// holding screen. `entered_otp` is echoed back into the OTP prompt.
pub async fn auth_prompt(
    services: &Services,
    state: &Arc<Mutex<AuthState>>,
    needed: &HashSet<CredentialKind>,
    entered_otp: &str,
) -> Option<AuthPrompt> {
    if needed.contains(&CredentialKind::Totp) {
        Some(AuthPrompt::Otp {
            entered: entered_otp.to_owned(),
        })
    } else if needed.contains(&CredentialKind::WebUserApproval) {
        Some(AuthPrompt::WebApproval {
            url: web_approval_url(services, state).await,
            security_key: state.lock().await.identification_string().to_owned(),
        })
    } else {
        None
    }
}

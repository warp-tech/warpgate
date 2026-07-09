//! Shared viewer authentication for the native desktop protocols (RDP, VNC).
//!
//! Both collect a username + password up front and then, when the credential policy needs
//! more, gather an interactive second factor (TOTP / web approval) on a per-protocol holding
//! screen. The up-front evaluation, target resolution, brute-force wiring, and web-approval
//! URL are identical between them and live here once; each protocol supplies only its name,
//! audit label, and target-options extractor via [`DesktopProtocol`].

mod otp;

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{Result, bail};
pub use otp::{MAX_OTP_ATTEMPTS, OtpAction, OtpActionApplyOutcome, OtpEntry};
use tokio::sync::Mutex;
use tracing::warn;
use uuid::Uuid;
use warpgate_common::auth::{
    AuthCredential, AuthResult, AuthSelector, AuthState, AuthStateUserInfo, CredentialKind,
};
use warpgate_common::{Secret, Target};
use warpgate_common_http::ext::construct_external_url;
use warpgate_core::auth::validate_and_add_credential;
use warpgate_core::login_protection::FailedAttemptInfo;
use warpgate_core::recordings::{DesktopRecorder, DesktopRecordingMetadata};
use warpgate_core::{
    ConfigProvider, Services, WarpgateServerHandle, authorize_ticket, consume_ticket,
};
use warpgate_desktop_ui::AuthPrompt;

/// The per-protocol specifics the shared auth flow needs.
pub trait DesktopProtocol {
    /// The protocol's target-options type (`TargetRdpOptions` / `TargetVncOptions`).
    type Options;
    /// Warpgate protocol name, recorded on the auth state (e.g. `"RDP"`).
    const NAME: &'static str;
    /// Lowercase audit / brute-force label (e.g. `"rdp"`).
    const LABEL: &'static str;
    /// Clone out this protocol's options from a target, or `None` if it's a different kind.
    fn options(target: &Target) -> Option<Self::Options>;
}

/// A session awaiting its interactive second factor after a valid password.
pub struct InteractiveAuth {
    pub state_id: Uuid,
    pub username: String,
    pub target_name: String,
    pub remote_ip: IpAddr,
}

/// Result of evaluating the viewer's up-front (password / ticket) credentials.
pub enum DesktopAuthOutcome<O> {
    /// Fully authenticated (password-only policy, or ticket auth).
    Authorized {
        user_info: AuthStateUserInfo,
        target: Target,
        options: O,
    },
    /// Password accepted, but the policy needs an interactive second factor — collected on
    /// the per-protocol holding screen.
    NeedsInteractive(InteractiveAuth),
    /// Rejected, invalid, blocked, or a required factor that can't be collected over the
    /// desktop protocol.
    Failed,
}

/// Evaluate the viewer's submitted credentials for protocol `P`.
///
/// A password-only policy (or a ticket) authorises immediately; a policy that additionally
/// needs a factor the holding screen can collect (TOTP / web approval) — and *only* such
/// factors — returns [`DesktopAuthOutcome::NeedsInteractive`]. Anything else fails.
pub async fn authenticate<P: DesktopProtocol>(
    services: &Services,
    server_handle: &Arc<Mutex<WarpgateServerHandle>>,
    selector: &str,
    password: String,
    remote_address: SocketAddr,
) -> Result<DesktopAuthOutcome<P::Options>> {
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
                warn!(ip = %remote_ip, protocol = P::LABEL, "Desktop auth attempt from blocked IP");
                return Ok(DesktopAuthOutcome::Failed);
            }
            if services
                .login_protection
                .check_user_locked(&username)
                .await?
                .is_some()
            {
                warn!(username = %username, protocol = P::LABEL, "Desktop auth attempt for locked user");
                return Ok(DesktopAuthOutcome::Failed);
            }

            let session_id = server_handle.lock().await.id();
            let (state_id, state_arc) = services
                .create_auth_state(
                    Some(&session_id),
                    &username,
                    P::NAME,
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
                let credential = AuthCredential::Password(Secret::new(password));
                let mut state = state_arc.lock().await;
                let credential_valid = validate_and_add_credential(
                    &mut state,
                    &credential,
                    &mut *services.config_provider.lock().await,
                )
                .await?;
                if !credential_valid {
                    let _ = services
                        .login_protection
                        .record_failed_attempt(FailedAttemptInfo {
                            username: username.clone(),
                            remote_ip,
                            protocol: P::LABEL.to_string(),
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

            // Bind to a local so the guard drops before `complete()` re-locks it.
            let verification = state_arc.lock().await.verify();
            match verification {
                AuthResult::Accepted { user_info } => {
                    let _ = services
                        .login_protection
                        .clear_failed_attempts(&remote_ip, &user_info.username)
                        .await;
                    services
                        .auth_state_store
                        .lock()
                        .await
                        .complete(&state_id)
                        .await;
                    let (target, options) =
                        finalize_user_auth::<P>(services, &user_info.username, &target_name)
                            .await?;
                    Ok(DesktopAuthOutcome::Authorized {
                        user_info,
                        target,
                        options,
                    })
                }
                // Go interactive only when *every* still-needed factor is one the holding
                // screen can collect; otherwise the session could never complete.
                AuthResult::Need(kinds)
                    if kinds.iter().all(|k| {
                        matches!(k, CredentialKind::Totp | CredentialKind::WebUserApproval)
                    }) =>
                {
                    Ok(DesktopAuthOutcome::NeedsInteractive(InteractiveAuth {
                        state_id,
                        username,
                        target_name,
                        remote_ip,
                    }))
                }
                AuthResult::Need(_) | AuthResult::Rejected => Ok(DesktopAuthOutcome::Failed),
            }
        }
        AuthSelector::Ticket { secret } => match authorize_ticket(&services.db, &secret).await? {
            Some((ticket, target_model, user_info)) => {
                consume_ticket(&services.db, &ticket.id).await?;
                let (target, options) = find_target::<P>(services, &target_model.name).await?;
                Ok(DesktopAuthOutcome::Authorized {
                    user_info,
                    target,
                    options,
                })
            }
            None => Ok(DesktopAuthOutcome::Failed),
        },
    }
}

/// Authorise a fully-authenticated user against a target and resolve its options. Used after
/// the holding screen completes the interactive factor.
pub async fn finalize_user_auth<P: DesktopProtocol>(
    services: &Services,
    username: &str,
    target_name: &str,
) -> Result<(Target, P::Options)> {
    let authorized = services
        .config_provider
        .lock()
        .await
        .authorize_target(username, target_name)
        .await?;
    if !authorized {
        bail!("Target {target_name} not authorized for {username}");
    }
    find_target::<P>(services, target_name).await
}

async fn find_target<P: DesktopProtocol>(
    services: &Services,
    target_name: &str,
) -> Result<(Target, P::Options)> {
    let Some(target) = services
        .config_provider
        .lock()
        .await
        .get_target_by_name(target_name)
        .await?
    else {
        bail!("Target {target_name} not found");
    };
    let Some(options) = P::options(&target) else {
        bail!("Target {target_name} is not a {} target", P::LABEL);
    };
    Ok((target, options))
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
    session_id: &Uuid,
    protocol_label: &str,
) -> Option<DesktopRecorder> {
    match services
        .recordings
        .lock()
        .await
        .start::<DesktopRecorder, _>(session_id, None, DesktopRecordingMetadata::Desktop)
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

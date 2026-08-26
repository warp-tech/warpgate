//! The authorization flow shared by the database protocols (MySQL, PostgreSQL).
//!
//! Both speak the same sequence — IP block, user lockout, credential policy,
//! brute-force accounting, target authorization — and differ only in how they
//! word a handful of messages. That difference is [`DbAuthTransport`];
//! everything else is [`run_db_authorization`], so the two protocols cannot
//! drift apart on any of the security-relevant steps.

use std::net::IpAddr;

use tracing::{error, info, warn};
use url::Url;
use warpgate_common::auth::{AuthCredential, AuthResult, AuthSelector, CredentialKind};
use warpgate_common::{Protocol, Secret, UserSessionId, WarpgateError};

use crate::auth::submit_credential;
use crate::login_protection::FailedAttemptInfo;
use crate::{
    AuthorizedIdentity, Services, TargetAuthorization, authorize_and_spend_ticket,
    authorize_for_target_by_name, wait_for_auth_completion,
};

/// Proof that the success message has not been sent yet. Exactly one is minted
/// per login and consumed by [`DbAuthTransport::send_auth_ok`], so a second send
/// doesn't compile — both protocols' clients treat a repeat as a protocol error.
#[non_exhaustive]
pub struct AuthOkPermit;

#[allow(async_fn_in_trait)]
pub trait DbAuthTransport {
    /// The owning protocol's error type. Core failures must convert into it so
    /// the flow can propagate rather than fail open.
    type Error: From<WarpgateError>;

    const PROTOCOL: Protocol;

    /// Whether this protocol can present a web-approval prompt mid-authentication.
    /// When false, a policy requiring web approval denies before the success
    /// message is sent, so the client sees a clean denial rather than an OK packet
    /// immediately followed by an error.
    const SUPPORTS_WEB_APPROVAL: bool;

    /// Ask the client for a password. `Ok(None)` means this protocol has no way
    /// to ask again — MySQL sends its password once, inside the handshake — and
    /// the login is denied.
    async fn prompt_password(&mut self) -> Result<Option<Secret<String>>, Self::Error>;

    /// Report a successful authentication. Consumes the login's only
    /// [`AuthOkPermit`], which is what limits it to one call.
    async fn send_auth_ok(&mut self, permit: AuthOkPermit) -> Result<(), Self::Error>;

    /// The gateway's externally reachable URL. Supplied by the protocol because
    /// deriving it lives in a crate above this one.
    async fn external_url(&mut self) -> Result<Url, Self::Error>;

    /// Show the user the web-approval link. `Ok(false)` if this protocol has no
    /// way to display one mid-authentication, which denies the login.
    async fn send_web_approval_prompt(
        &mut self,
        url: &Url,
        identification_string: &str,
    ) -> Result<bool, Self::Error>;

    /// Tell the client the login was denied.
    async fn send_denied(&mut self) -> Result<(), Self::Error>;
}

/// Authorizes a database-protocol login end to end.
///
/// `Ok(None)` means the login was denied and the client has already been told;
/// the caller only has to stop. A returned [`TargetAuthorization`] is proof the
/// user may open the target it names.
pub async fn run_db_authorization<T: DbAuthTransport>(
    transport: &mut T,
    services: &Services,
    session_id: UserSessionId,
    selector: AuthSelector,
    remote_ip: IpAddr,
) -> Result<Option<TargetAuthorization>, T::Error> {
    // A lookup error must fail closed: propagate it rather than letting a
    // possibly-blocked IP through.
    if let Some(block_info) = services
        .login_protection
        .check_ip_blocked(&remote_ip)
        .await?
    {
        warn!(
            ip = %remote_ip,
            expires_at = %block_info.expires_at,
            protocol = %T::PROTOCOL,
            "Auth from blocked IP"
        );
        transport.send_denied().await?;
        return Ok(None);
    }

    match selector {
        AuthSelector::User {
            username,
            target_name,
        } => {
            authorize_user(
                transport,
                services,
                session_id,
                &username,
                &target_name,
                remote_ip,
                AuthOkPermit,
            )
            .await
        }
        AuthSelector::Ticket { secret } => {
            let Some(authorization) = authorize_and_spend_ticket(
                &services.db,
                &services.login_protection,
                &secret,
                Some(remote_ip),
                T::PROTOCOL,
            )
            .await?
            else {
                transport.send_denied().await?;
                return Ok(None);
            };

            info!(
                "Authorized for {} with a ticket",
                authorization.target().name
            );
            transport.send_auth_ok(AuthOkPermit).await?;
            Ok(Some(authorization))
        }
    }
}

async fn authorize_user<T: DbAuthTransport>(
    transport: &mut T,
    services: &Services,
    session_id: UserSessionId,
    username: &str,
    target_name: &str,
    remote_ip: IpAddr,
    auth_ok: AuthOkPermit,
) -> Result<Option<TargetAuthorization>, T::Error> {
    // As with the IP check above, a lookup error fails closed.
    if services
        .login_protection
        .check_user_locked(username)
        .await?
        .is_some()
    {
        warn!(%username, protocol = %T::PROTOCOL, "Auth for locked user");
        transport.send_denied().await?;
        return Ok(None);
    }

    let state_arc = services
        .create_auth_state(
            &session_id,
            username,
            T::PROTOCOL,
            target_name,
            &[CredentialKind::Password],
            Some(remote_ip),
            Some("password"),
        )
        .await?;

    // Sent before the approval prompt because some clients discard anything that
    // arrives ahead of it, which spends the permit early.
    let mut auth_ok = Some(auth_ok);

    loop {
        let verification = state_arc.lock().await.verify();

        match verification {
            AuthResult::Accepted { user_info } => {
                let identity = {
                    let state = state_arc.lock().await;
                    AuthorizedIdentity::from_auth_state(&state)
                };
                // Verified `Accepted` a moment ago; a state that no longer is
                // means the login was concurrently rejected — deny.
                let Some(identity) = identity else {
                    transport.send_denied().await?;
                    return Ok(None);
                };

                let Some(authorization) = authorize_for_target_by_name(
                    services.config_provider.as_ref(),
                    &identity,
                    target_name,
                )
                .await?
                else {
                    warn!("Target {target_name} not authorized for user {username}");
                    record_password_failure(services, username, remote_ip, T::PROTOCOL).await;
                    transport.send_denied().await?;
                    return Ok(None);
                };

                if let Some(permit) = auth_ok.take() {
                    transport.send_auth_ok(permit).await?;
                }

                let _ = services
                    .login_protection
                    .clear_failed_attempts(&remote_ip, &user_info.username)
                    .await;

                return Ok(Some(authorization));
            }

            AuthResult::Need(kinds) if kinds.contains(&CredentialKind::Password) => {
                let Some(password) = transport.prompt_password().await? else {
                    transport.send_denied().await?;
                    return Ok(None);
                };

                let outcome = submit_credential(
                    &mut *state_arc.lock().await,
                    AuthCredential::Password(password),
                    services.config_provider.as_ref(),
                    &services.login_protection,
                )
                .await?;

                // Only an invalid password counts toward brute-force protection;
                // a valid one that needs a further factor does not.
                if !outcome.is_valid() {
                    record_password_failure(services, username, remote_ip, T::PROTOCOL).await;
                    transport.send_denied().await?;
                    return Ok(None);
                }
            }

            AuthResult::Need(kinds) if kinds.contains(&CredentialKind::WebUserApproval) => {
                if services.try_web_approval_bypass(&state_arc).await? {
                    continue;
                }

                // Deny before the success message is sent: a protocol that can't
                // show the prompt would otherwise reach `send_denied` having
                // already spent the permit, sending the client OK then error.
                if !T::SUPPORTS_WEB_APPROVAL {
                    warn!(
                        protocol = %T::PROTOCOL,
                        "Web user approval is required but not supported by this protocol"
                    );
                    transport.send_denied().await?;
                    return Ok(None);
                }

                let identification_string =
                    state_arc.lock().await.identification_string().to_owned();

                let external_url = match transport.external_url().await {
                    Ok(url) => url,
                    Err(error) => {
                        error!("Failed to construct external URL");
                        transport.send_denied().await?;
                        return Err(error);
                    }
                };
                let login_url = state_arc
                    .lock()
                    .await
                    .construct_web_approval_url(external_url);

                if let Some(permit) = auth_ok.take() {
                    transport.send_auth_ok(permit).await?;
                }

                if !transport
                    .send_web_approval_prompt(&login_url, &identification_string)
                    .await?
                {
                    transport.send_denied().await?;
                    return Ok(None);
                }

                if !matches!(
                    wait_for_auth_completion(&state_arc).await,
                    AuthResult::Accepted { .. }
                ) {
                    warn!("Web user approval failed");
                    transport.send_denied().await?;
                    return Ok(None);
                }
            }

            // A factor this protocol can't collect.
            AuthResult::Need(_) => {
                transport.send_denied().await?;
                return Ok(None);
            }

            AuthResult::Rejected => {
                record_password_failure(services, username, remote_ip, T::PROTOCOL).await;
                transport.send_denied().await?;
                return Ok(None);
            }
        }
    }
}

async fn record_password_failure(
    services: &Services,
    username: &str,
    remote_ip: IpAddr,
    protocol: Protocol,
) {
    let _ = services
        .login_protection
        .record_failed_attempt(FailedAttemptInfo {
            username: username.to_owned(),
            remote_ip,
            protocol,
            credential_type: "password".to_owned(),
        })
        .await;
}

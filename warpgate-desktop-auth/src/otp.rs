//! The OTP entry field shared by the RDP and VNC holding screens.
//!
//! Accumulating typed digits, validating a completed code, recording failed attempts and
//! bounding retries is identical across the desktop protocols. Only mapping raw key events
//! to an [`OtpAction`] differs (RDP scancodes / Unicode, VNC X11 keysyms), and that stays in
//! each protocol's holding screen.

use std::net::IpAddr;
use std::sync::Arc;

use tokio::sync::Mutex;
use tracing::warn;
use warpgate_common::auth::{AuthCredential, AuthState};
use warpgate_common::helpers::otp::OTP_DIGITS;
use warpgate_common::{Protocol, Secret};
use warpgate_core::Services;
use warpgate_core::auth::submit_credential;
use warpgate_core::login_protection::FailedAttemptInfo;

/// Max wrong one-time passwords before the holding screen gives up.
pub const MAX_OTP_ATTEMPTS: usize = 3;

/// One key event's effect on the OTP field. Protocol code maps its own raw input to this.
pub enum OtpAction {
    Digit(char),
    Backspace,
    Submit,
}

/// Collects typed OTP digits and validates a completed code, tracking wrong attempts.
pub struct OtpEntry {
    entered: String,
    failures: usize,
    /// Recorded on failed attempts for audit and brute-force accounting.
    protocol: Protocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpActionApplyOutcome {
    Applied,
    AcceptedAndValidated,
    TooManyFailures,
}

impl OtpEntry {
    pub const fn new(protocol: Protocol) -> Self {
        Self {
            entered: String::new(),
            failures: 0,
            protocol,
        }
    }

    /// The digits typed so far, for the on-screen prompt.
    pub fn entered(&self) -> &str {
        &self.entered
    }

    /// Apply one key action. A completed entry (Enter, or a full field) is validated against
    /// `state`, recording a failed attempt on a wrong code. Returns `true` when too many wrong
    /// OTPs have been entered and the session should be abandoned.
    pub async fn apply(
        &mut self,
        action: OtpAction,
        services: &Services,
        state: &Arc<Mutex<AuthState>>,
        username: &str,
        remote_ip: IpAddr,
    ) -> OtpActionApplyOutcome {
        let submit = match action {
            OtpAction::Digit(c) => {
                // OTP chars are always ASCII digits, so byte length == char count.
                if self.entered.len() < OTP_DIGITS {
                    self.entered.push(c);
                }
                self.entered.len() >= OTP_DIGITS
            }
            OtpAction::Backspace => {
                self.entered.pop();
                false
            }
            OtpAction::Submit => !self.entered.is_empty(),
        };
        if !submit {
            return OtpActionApplyOutcome::Applied;
        }

        let credential = AuthCredential::Otp(Secret::new(std::mem::take(&mut self.entered)));
        // Route through the shared validator so a bad OTP emits the same audit event as the
        // other protocols. A validation error counts as an invalid code (fail closed).
        let valid = submit_credential(
            &mut *state.lock().await,
            credential,
            services.config_provider.as_ref(),
            &services.login_protection,
        )
        .await
        .is_ok_and(|outcome| outcome.is_valid());
        if valid {
            return OtpActionApplyOutcome::AcceptedAndValidated;
        }

        warn!(
            protocol = %self.protocol,
            "Incorrect one-time password"
        );
        self.failures += 1;
        let _ = services
            .login_protection
            .record_failed_attempt(FailedAttemptInfo {
                username: username.to_string(),
                remote_ip,
                protocol: self.protocol,
                credential_type: "otp".to_string(),
            })
            .await;

        if self.failures >= MAX_OTP_ATTEMPTS {
            OtpActionApplyOutcome::TooManyFailures
        } else {
            OtpActionApplyOutcome::Applied
        }
    }
}

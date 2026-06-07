use std::collections::HashSet;
use std::fmt::Write;
use std::net::IpAddr;

use rand::RngExt;
use time::OffsetDateTime;
use tokio::sync::broadcast;
use tracing::{debug, info};
use url::Url;
use uuid::Uuid;

use super::{AuthCredential, CredentialKind, CredentialPolicy, CredentialPolicyResponse};
use crate::helpers::logging::format_related_ids;
use crate::{SessionId, User};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthResult {
    Accepted { user_info: AuthStateUserInfo },
    Need(HashSet<CredentialKind>),
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthStateUserInfo {
    pub id: Uuid,
    pub username: String,
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
    id: Uuid,
    user_info: AuthStateUserInfo,
    session_id: Option<Uuid>,
    remote_ip: Option<IpAddr>,
    protocol: String,
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
    pub fn new(
        id: Uuid,
        session_id: Option<SessionId>,
        remote_ip: Option<IpAddr>,
        user_info: AuthStateUserInfo,
        protocol: String,
        policy: Box<dyn CredentialPolicy + Sync + Send>,
        state_change_signal: broadcast::Sender<AuthResult>,
    ) -> Self {
        let mut this = Self {
            id,
            session_id,
            remote_ip,
            user_info,
            protocol,
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

    pub const fn id(&self) -> &Uuid {
        &self.id
    }

    pub const fn session_id(&self) -> Option<&SessionId> {
        self.session_id.as_ref()
    }

    pub fn set_session_id(&mut self, session_id: SessionId) {
        self.session_id = Some(session_id);
    }

    pub const fn user_info(&self) -> &AuthStateUserInfo {
        &self.user_info
    }

    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    pub const fn started(&self) -> &OffsetDateTime {
        &self.started
    }

    pub fn identification_string(&self) -> &str {
        &self.identification_string
    }

    pub fn add_valid_credential(&mut self, credential: AuthCredential) {
        self.valid_credentials.push(credential);
        self.maybe_update_verification_state();
    }

    pub const fn reject(&mut self) {
        self.force_rejected = true;
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
            .map(|x| x.to_string())
            .unwrap_or_else(|| "<unknown>".to_string())
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

    pub fn emit_authentication_failed_event(
        &self,
        credential: Option<&AuthCredential>,
        reason: &str,
    ) {
        let Some(session_id) = self.session_id.as_ref() else {
            return;
        };

        let credentials = credential
            .map(AuthCredential::safe_description)
            .unwrap_or_else(|| "<unknown>".to_string());

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
            let _ = self.state_change_signal.send(new_result.clone());
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

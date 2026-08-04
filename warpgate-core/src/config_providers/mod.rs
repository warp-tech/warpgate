use std::collections::HashSet;
use std::net::IpAddr;

mod db;
mod sso_user;

pub use db::DatabaseConfigProvider;
use enum_dispatch::enum_dispatch;
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
pub use sso_user::resolve_and_map_sso_user;
use time::OffsetDateTime;
use tracing::warn;
use uuid::Uuid;
use warpgate_common::auth::{
    AuthCredential, AuthResult, AuthState, AuthStateUserInfo, CredentialKind, CredentialPolicy,
};
use warpgate_common::{Protocol, Secret, Target, User, WarpgateError};
use warpgate_db_entities as e;
use warpgate_sso::SsoProviderConfig;

use crate::login_protection::LoginProtectionService;

#[enum_dispatch]
pub enum ConfigProviderEnum {
    Database(DatabaseConfigProvider),
}

#[enum_dispatch(ConfigProviderEnum)]
#[allow(async_fn_in_trait)]
pub trait ConfigProvider {
    async fn list_users(&self) -> Result<Vec<User>, WarpgateError>;

    async fn list_targets(&self) -> Result<Vec<Target>, WarpgateError>;

    async fn get_target_by_name(&self, name: &str) -> Result<Option<Target>, WarpgateError>;

    async fn get_target_by_id(&self, id: Uuid) -> Result<Option<Target>, WarpgateError>;

    async fn get_target_by_hostname(&self, hostname: &str)
    -> Result<Option<Target>, WarpgateError>;

    async fn validate_credential(
        &self,
        username: &str,
        client_credential: &AuthCredential,
    ) -> Result<bool, WarpgateError>;

    async fn username_for_sso_credential(
        &self,
        client_credential: &AuthCredential,
        preferred_username: Option<String>,
        sso_config: SsoProviderConfig,
    ) -> Result<Option<String>, WarpgateError>;

    async fn apply_sso_role_mappings(
        &self,
        username: &str,
        managed_role_names: Option<Vec<String>>,
        active_role_names: Vec<String>,
    ) -> Result<(), WarpgateError>;

    /// Similar to `apply_sso_role_mappings` but operates on *admin* roles.
    async fn apply_sso_admin_role_mappings(
        &self,
        username: &str,
        managed_admin_role_names: Option<Vec<String>>,
        active_admin_role_names: Vec<String>,
    ) -> Result<(), WarpgateError>;

    async fn get_credential_policy(
        &self,
        username: &str,
        supported_credential_types: &[CredentialKind],
    ) -> Result<Option<Box<dyn CredentialPolicy + Sync + Send>>, WarpgateError>;

    async fn authorize_target(&self, username: &str, target: &str) -> Result<bool, WarpgateError>;

    async fn authorize_target_by_id(
        &self,
        user_id: Uuid,
        target_id: Uuid,
    ) -> Result<bool, WarpgateError>;

    /// IDs of all targets the user is authorized for, in a single query.
    async fn authorized_target_ids(&self, user_id: Uuid) -> Result<HashSet<Uuid>, WarpgateError>;

    async fn update_public_key_last_used(
        &self,
        credential: Option<AuthCredential>,
    ) -> Result<(), WarpgateError>;

    async fn validate_api_token(&self, token: &str) -> Result<Option<User>, WarpgateError>;
}

/// Proof that a user authenticated for a given protocol, and so may be handed to
/// [`authorize_for_target`]. Every constructor corresponds to a real
/// authentication path, so a new protocol can't authorize a target by building an
/// [`AuthStateUserInfo`] out of thin air — it has to route through one of these.
#[derive(Clone)]
pub struct AuthorizedIdentity {
    user_info: AuthStateUserInfo,
    protocol: Protocol,
}

impl AuthorizedIdentity {
    /// From an [`AuthState`] that has reached [`AuthResult::Accepted`] — i.e. the
    /// per-protocol credential policy was satisfied. `None` otherwise, so the
    /// gate can't be reached with an unsatisfied state.
    pub fn from_auth_state(state: &AuthState) -> Option<Self> {
        match state.verify() {
            AuthResult::Accepted { user_info } => Some(Self {
                user_info,
                protocol: state.protocol(),
            }),
            AuthResult::Need(_) | AuthResult::Rejected => None,
        }
    }

    /// For a request already authenticated out of band — an established HTTP
    /// session (backed by a `FullUserAuthorization`) or a Kubernetes credential
    /// the caller validated itself. The caller vouches that authentication
    /// happened; this is the one path that isn't a fresh [`AuthState`], so its
    /// call sites are the ones to audit when reasoning about the gate.
    pub const fn for_authenticated_session(
        user_info: AuthStateUserInfo,
        protocol: Protocol,
    ) -> Self {
        Self {
            user_info,
            protocol,
        }
    }

    pub const fn user_info(&self) -> &AuthStateUserInfo {
        &self.user_info
    }

    pub const fn protocol(&self) -> Protocol {
        self.protocol
    }
}

impl std::ops::Deref for AuthorizedIdentity {
    type Target = AuthStateUserInfo;

    fn deref(&self) -> &Self::Target {
        &self.user_info
    }
}

/// Proof that a user is authorized for a specific target. Only
/// [`authorize_for_target`] and [`authorize_ticket`] construct it, so a
/// session can't be opened for a target without passing authorization.
#[derive(Clone)]
pub struct TargetAuthorization {
    user_info: AuthStateUserInfo,
    target: Target,
    protocol: Protocol,
}

impl TargetAuthorization {
    pub const fn user_info(&self) -> &AuthStateUserInfo {
        &self.user_info
    }

    /// The target this authorization was granted for. Carrying it means a dial
    /// site never has to re-resolve — and so can't resolve a *different* one.
    pub const fn target(&self) -> &Target {
        &self.target
    }

    /// The protocol the authorizing authentication ran under.
    pub const fn protocol(&self) -> Protocol {
        self.protocol
    }

    pub fn into_parts(self) -> (AuthStateUserInfo, Target) {
        (self.user_info, self.target)
    }
}

/// Checks whether the user may access the target; `Ok(None)` means not
/// authorized.
///
/// Takes the resolved [`Target`] rather than a name so the authorization and the
/// subsequent connection are provably about the same row.
pub async fn authorize_for_target<C: ConfigProvider + ?Sized>(
    config_provider: &C,
    identity: &AuthorizedIdentity,
    target: Target,
) -> Result<Option<TargetAuthorization>, WarpgateError> {
    Ok(config_provider
        .authorize_target_by_id(identity.user_info.id, target.id)
        .await?
        .then(|| TargetAuthorization {
            user_info: identity.user_info.clone(),
            target,
            protocol: identity.protocol,
        }))
}

/// Resolves the target by name and checks authorization. A target that
/// doesn't exist and one the user may not reach are the same `None` here, so
/// a caller can't be used as a target-existence oracle.
pub async fn authorize_for_target_by_name<C: ConfigProvider + ?Sized>(
    config_provider: &C,
    identity: &AuthorizedIdentity,
    target_name: &str,
) -> Result<Option<TargetAuthorization>, WarpgateError> {
    match config_provider.get_target_by_name(target_name).await? {
        Some(target) => authorize_for_target(config_provider, identity, target).await,
        None => Ok(None),
    }
}

//TODO: move this somewhere
pub async fn authorize_ticket(
    db: &DatabaseConnection,
    login_protection: &LoginProtectionService,
    secret: &Secret<String>,
    remote_ip: Option<IpAddr>,
    protocol: Protocol,
) -> Result<Option<(e::Ticket::Model, TargetAuthorization)>, WarpgateError> {
    // Spending a ticket is a login, so a blocked IP can't do it either. Checked ahead of the
    // lookup so a blocked caller can't use this as a ticket-existence oracle.
    if let Some(ip) = remote_ip
        && login_protection.check_ip_blocked(&ip).await?.is_some()
    {
        warn!("Ticket presented from a blocked IP: {ip}");
        return Ok(None);
    }

    let ticket = {
        e::Ticket::Entity::find()
            .filter(e::Ticket::Column::Secret.eq(&secret.expose_secret()[..]))
            .one(db)
            .await?
    };
    if let Some(ticket) = ticket {
        if ticket.uses_left == Some(0) {
            warn!("Ticket is used up: {}", &ticket.id);
            return Ok(None);
        }

        if let Some(datetime) = ticket.expiry
            && datetime < OffsetDateTime::now_utc()
        {
            warn!("Ticket has expired: {}", &ticket.id);
            return Ok(None);
        }

        let Some(ticket_user) = e::User::Entity::find_by_id(ticket.user_id).one(db).await? else {
            return Err(WarpgateError::UserNotFound(ticket.user_id.to_string()));
        };
        let user = User::try_from(ticket_user)?;

        // A ticket is only as good as its user, and this path mints authorization
        // directly, bypassing the auth state store where interactive logins are
        // vetted. A denied user returns the missing-ticket shape, preserving the
        // no-existence-oracle property.
        if !crate::auth_state_store::vet_credential_bearer(login_protection, &user, remote_ip)
            .await?
        {
            return Ok(None);
        }

        let Some(ticket_target) = e::Target::Entity::find_by_id(ticket.target_id)
            .one(db)
            .await?
        else {
            warn!("Ticket target not found: {}", &ticket.target_id);
            return Ok(None);
        };

        // A ticket binds user↔target directly, so it mints the proof without a
        // role check — that's what makes it a ticket.
        let authorization = TargetAuthorization {
            user_info: (&user).into(),
            target: Target::try_from(ticket_target)?,
            protocol,
        };
        Ok(Some((ticket, authorization)))
    } else {
        warn!("Ticket not found");
        Ok(None)
    }
}

pub async fn consume_ticket(
    db: &DatabaseConnection,
    ticket_id: &Uuid,
) -> Result<(), WarpgateError> {
    let ticket = e::Ticket::Entity::find_by_id(*ticket_id).one(db).await?;
    let Some(ticket) = ticket else {
        return Err(WarpgateError::InvalidTicket(*ticket_id));
    };

    // Decrement atomically
    if ticket.uses_left.is_some() {
        e::Ticket::Entity::update_many()
            .col_expr(
                e::Ticket::Column::UsesLeft,
                Expr::col(e::Ticket::Column::UsesLeft).sub(1),
            )
            .filter(e::Ticket::Column::Id.eq(*ticket_id))
            .filter(e::Ticket::Column::UsesLeft.gt(0))
            .exec(db)
            .await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::sync::broadcast;
    use warpgate_common::auth::CredentialPolicyResponse;

    use super::*;

    struct FixedPolicy(bool);
    impl CredentialPolicy for FixedPolicy {
        fn is_sufficient(&self, _p: Protocol, _c: &[AuthCredential]) -> CredentialPolicyResponse {
            if self.0 {
                CredentialPolicyResponse::Ok
            } else {
                CredentialPolicyResponse::Need([CredentialKind::Password].into_iter().collect())
            }
        }
    }

    fn auth_state(satisfied: bool) -> AuthState {
        let (tx, _rx) = broadcast::channel(1);
        AuthState::new(
            Uuid::new_v4(),
            None,
            AuthStateUserInfo {
                id: Uuid::nil(),
                username: "alice".into(),
            },
            Protocol::Kubernetes,
            String::new(),
            Box::new(FixedPolicy(satisfied)),
            tx,
        )
    }

    #[test]
    fn identity_minted_only_from_accepted_state() {
        // Accepted → a sealed identity carrying the state's protocol and user.
        let accepted = AuthorizedIdentity::from_auth_state(&auth_state(true))
            .expect("an accepted state yields an identity");
        assert_eq!(accepted.protocol(), Protocol::Kubernetes);
        assert_eq!(accepted.user_info().username, "alice");

        // An unsatisfied policy yields no identity, so `authorize_for_target`
        // can't be reached from a state that never passed the policy.
        assert!(AuthorizedIdentity::from_auth_state(&auth_state(false)).is_none());
    }
}

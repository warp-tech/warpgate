use std::collections::{HashMap, HashSet};

use data_encoding::BASE64;
use sea_orm::sea_query::{Expr, Func, Query};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseBackend, DatabaseConnection,
    EntityTrait, ModelTrait, QueryFilter, QueryOrder, Set,
};
use time::OffsetDateTime;
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use warpgate_common::auth::{
    AllCredentialsPolicy, AnySingleCredentialPolicy, AuthCredential, CredentialKind,
    CredentialPolicy, PerProtocolCredentialPolicy,
};
use warpgate_common::helpers::hash::verify_password_hash;
use warpgate_common::helpers::otp::verify_totp;
use warpgate_common::{
    Target, User, UserAuthCredential, UserPasswordCredential, UserPublicKeyCredential,
    UserRequireCredentialsPolicy, UserSsoCredential, UserTotpCredential, WarpgateError,
};
use warpgate_db_entities as entities;
use warpgate_sso::SsoProviderConfig;

use super::ConfigProvider;

pub struct DatabaseConfigProvider {
    db: DatabaseConnection,
}

/// Joins active (non-revoked, non-expired) user role assignments to target
/// role assignments; callers add the authorization predicates and selection.
fn active_role_assignment_query() -> sea_orm::sea_query::SelectStatement {
    let now = OffsetDateTime::now_utc();
    Query::select()
        .from(entities::UserRoleAssignment::Entity)
        .inner_join(
            entities::TargetRoleAssignment::Entity,
            Expr::col((
                entities::UserRoleAssignment::Entity,
                entities::UserRoleAssignment::Column::RoleId,
            ))
            .equals((
                entities::TargetRoleAssignment::Entity,
                entities::TargetRoleAssignment::Column::RoleId,
            )),
        )
        .and_where(
            Expr::col((
                entities::UserRoleAssignment::Entity,
                entities::UserRoleAssignment::Column::RevokedAt,
            ))
            .is_null(),
        )
        .and_where(
            Expr::col((
                entities::UserRoleAssignment::Entity,
                entities::UserRoleAssignment::Column::ExpiresAt,
            ))
            .is_null()
            .or(Expr::col((
                entities::UserRoleAssignment::Entity,
                entities::UserRoleAssignment::Column::ExpiresAt,
            ))
            .gt(now)),
        )
        .to_owned()
}

/// SQL `EXISTS`-style check for a query built with [`Query::select`].
trait SelectExists {
    /// Whether the query matches at least one row; selects a constant instead
    /// of any column data.
    async fn exists(&mut self, db: &DatabaseConnection) -> Result<bool, WarpgateError>;
}

impl SelectExists for sea_orm::sea_query::SelectStatement {
    async fn exists(&mut self, db: &DatabaseConnection) -> Result<bool, WarpgateError> {
        self.expr(Expr::val(1)).limit(1);
        Ok(db
            .query_one(db.get_database_backend().build(&*self))
            .await?
            .is_some())
    }
}

impl DatabaseConfigProvider {
    pub fn new(db: &DatabaseConnection) -> Self {
        Self { db: db.clone() }
    }

    async fn sync_ldap_ssh_keys(
        &self,
        db: &DatabaseConnection,
        user_id: Uuid,
        ldap_server_id: Uuid,
        ldap_object_uuid: &Uuid,
    ) -> Result<(), WarpgateError> {
        // Fetch LDAP server config
        let ldap_server = entities::LdapServer::Entity::find_by_id(ldap_server_id)
            .one(db)
            .await?
            .ok_or_else(|| {
                warpgate_ldap::LdapError::InvalidConfiguration("LDAP server not found".to_string())
            })?;

        if !ldap_server.enabled {
            debug!(
                "LDAP server {} is disabled, skipping SSH key sync",
                ldap_server.name
            );
            return Ok(());
        }

        let ldap_config = warpgate_ldap::LdapConfig::try_from(&ldap_server)?;

        // Find user in LDAP by object UUID
        let ldap_user = warpgate_ldap::find_user_by_uuid(&ldap_config, ldap_object_uuid).await?;

        let Some(ldap_user) = ldap_user else {
            warn!(
                "LDAP user with UUID {} not found in server {}",
                ldap_object_uuid, ldap_server.name
            );
            return Ok(());
        };

        // Delete existing public key credentials for this user
        entities::PublicKeyCredential::Entity::delete_many()
            .filter(entities::PublicKeyCredential::Column::UserId.eq(user_id))
            .exec(db)
            .await?;

        // Insert SSH keys from LDAP
        for ssh_key in &ldap_user.ssh_public_keys {
            let ssh_key = ssh_key.trim();
            if ssh_key.is_empty() {
                continue;
            }

            // Parse and validate the SSH key
            let key_result = russh::keys::PublicKey::from_openssh(ssh_key);
            if let Ok(mut key) = key_result {
                key.set_comment("");
                let openssh_key = key.to_openssh().map_err(russh::keys::Error::from)?;

                entities::PublicKeyCredential::ActiveModel {
                    id: Set(Uuid::new_v4()),
                    user_id: Set(user_id),
                    date_added: Set(Some(OffsetDateTime::now_utc())),
                    last_used: Set(None),
                    label: Set("Public key synchronized from LDAP".to_string()),
                    ..entities::PublicKeyCredential::ActiveModel::from(UserPublicKeyCredential {
                        key: openssh_key.into(),
                    })
                }
                .insert(db)
                .await?;
            } else {
                warn!("Invalid SSH key from LDAP: {}", ssh_key);
            }
        }

        info!(
            "Synced {} SSH key(s) from LDAP for {}",
            ldap_user.ssh_public_keys.len(),
            ldap_user.username
        );

        Ok(())
    }

    async fn maybe_autocreate_sso_user(
        &self,
        db: &DatabaseConnection,
        credential: UserSsoCredential,
        preferred_username: String,
        default_credential_policy: Option<serde_json::Value>,
    ) -> Result<Option<String>, WarpgateError> {
        // Check for LDAP servers with auto-linking enabled
        let ldap_servers: Vec<entities::LdapServer::Model> = entities::LdapServer::Entity::find()
            .filter(entities::LdapServer::Column::Enabled.eq(true))
            .filter(entities::LdapServer::Column::AutoLinkSsoUsers.eq(true))
            .all(db)
            .await?;

        let mut ldap_server_id = None;
        let mut ldap_object_uuid = None;

        for ldap_server in ldap_servers {
            let ldap_config = warpgate_ldap::LdapConfig::try_from(&ldap_server).map_err(|e| {
                warn!(
                    "Failed to parse LDAP config for server {}: {}",
                    ldap_server.name, e
                );
                e
            })?;

            match warpgate_ldap::find_user_by_username(&ldap_config, &preferred_username).await {
                Ok(Some(ldap_user)) => {
                    info!(
                        "Found LDAP user for username {}: {:?}",
                        preferred_username, ldap_user.username
                    );
                    ldap_server_id = Some(ldap_server.id);
                    ldap_object_uuid = Some(ldap_user.object_uuid);
                    break;
                }
                Ok(None) => {
                    debug!(
                        "No LDAP user found with username {} in server {}",
                        preferred_username, ldap_server.name
                    );
                }
                Err(e) => {
                    warn!(
                        "Error searching for LDAP user in {}: {}",
                        ldap_server.name, e
                    );
                }
            }
        }

        let existing_user = entities::User::Entity::find()
            .filter(entities::User::Entity::username_eq_ci(&preferred_username))
            .one(db)
            .await?;

        if existing_user.is_some() {
            error!(
                "Cannot auto-create SSO user with username {preferred_username} because it already exists and does not have a matching SSO credential."
            );
            return Err(WarpgateError::UserAlreadyExists(preferred_username));
        }

        let user = entities::User::ActiveModel {
            id: Set(Uuid::new_v4()),
            username: Set(preferred_username.clone()),
            description: Set("".into()),
            credential_policy: Set(default_credential_policy.unwrap_or_else(|| {
                serde_json::to_value(UserRequireCredentialsPolicy::default()).unwrap_or_default()
            })),
            rate_limit_bytes_per_second: Set(None),
            ldap_server_id: Set(ldap_server_id),
            ldap_object_uuid: Set(ldap_object_uuid),
            allowed_ip_ranges: Set(serde_json::Value::Null),
        }
        .insert(db)
        .await?;

        let default_roles = entities::Role::Entity::grant_default_roles(db, user.id).await?;

        entities::SsoCredential::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(user.id),
            ..credential.into()
        }
        .insert(db)
        .await?;

        if ldap_server_id.is_some() {
            info!(
                "Auto-created SSO user {} and linked to LDAP account",
                preferred_username
            );
        } else {
            info!(
                "Auto-created SSO user {} (no LDAP link)",
                preferred_username
            );
        }

        if !default_roles.is_empty() {
            info!(
                "Assigned default role(s) to auto-created SSO user {}: {:?}",
                preferred_username,
                default_roles
                    .iter()
                    .map(|role| &role.name)
                    .collect::<Vec<_>>()
            );
        }

        Ok(Some(preferred_username))
    }
}

impl ConfigProvider for DatabaseConfigProvider {
    async fn list_users(&self) -> Result<Vec<User>, WarpgateError> {
        let db = &self.db;

        let users = entities::User::Entity::find()
            .order_by_asc(entities::User::Column::Username)
            .all(db)
            .await?;

        let users: Result<Vec<User>, _> = users.into_iter().map(TryInto::try_into).collect();

        users
    }

    async fn list_targets(&self) -> Result<Vec<Target>, WarpgateError> {
        let db = &self.db;

        let targets = entities::Target::Entity::find()
            .order_by_asc(entities::Target::Column::Name)
            .all(db)
            .await?;

        let targets: Result<Vec<Target>, _> = targets.into_iter().map(TryInto::try_into).collect();

        Ok(targets?)
    }

    async fn get_target_by_name(&self, name: &str) -> Result<Option<Target>, WarpgateError> {
        let db = &self.db;

        let target = entities::Target::Entity::find()
            .filter(entities::Target::Column::Name.eq(name))
            .one(db)
            .await?;

        target
            .map(TryInto::try_into)
            .transpose()
            .map_err(Into::into)
    }

    async fn get_target_by_hostname(
        &self,
        hostname: &str,
    ) -> Result<Option<Target>, WarpgateError> {
        let db = &self.db;

        let hostname_query = match db.get_database_backend() {
            DatabaseBackend::MySql => {
                Expr::cust("JSON_UNQUOTE(JSON_EXTRACT(options, '$.http.external_host'))")
            }
            DatabaseBackend::Postgres => Expr::cust(r"options->'http'->>'external_host'"),
            DatabaseBackend::Sqlite => Expr::cust(r"json_extract(options, '$.http.external_host')"),
        };

        let target = entities::Target::Entity::find()
            .filter(hostname_query.eq(hostname))
            .one(db)
            .await?;

        target
            .map(TryInto::try_into)
            .transpose()
            .map_err(Into::into)
    }

    async fn get_credential_policy(
        &self,
        username: &str,
        supported_credential_types: &[CredentialKind],
    ) -> Result<Option<Box<dyn CredentialPolicy + Sync + Send>>, WarpgateError> {
        let db = &self.db;

        let user_model = entities::User::Entity::find()
            .filter(entities::User::Entity::username_eq_ci(username))
            .one(db)
            .await?;

        let Some(user_model) = user_model else {
            error!("Selected user not found: {}", username);
            return Ok(None);
        };

        let user = user_model.load_details(db).await?;

        let mut available_credential_types = user
            .credentials
            .iter()
            .map(UserAuthCredential::kind)
            .collect::<HashSet<_>>();
        available_credential_types.insert(CredentialKind::WebUserApproval);

        let supported_credential_types = supported_credential_types
            .iter()
            .copied()
            .collect::<HashSet<_>>()
            .intersection(&available_credential_types)
            .copied()
            .collect::<HashSet<_>>();

        // The "any single credential" default must never let an approval factor
        // stand alone: an approval only ever confirms an otherwise-authenticated
        // session, so both approval kinds are dropped from the default set when
        // any real credential is also available.
        let default_policy = Box::new(AnySingleCredentialPolicy {
            supported_credential_types: if supported_credential_types.len() > 1 {
                supported_credential_types
                    .iter()
                    .copied()
                    .filter(|x| !matches!(x, CredentialKind::WebUserApproval))
                    .collect()
            } else {
                supported_credential_types.clone()
            },
        }) as Box<dyn CredentialPolicy + Sync + Send>;

        if let Some(req) = user.credential_policy.clone() {
            let mut policy = PerProtocolCredentialPolicy {
                default: default_policy,
                protocols: HashMap::new(),
            };

            if let Some(p) = req.http {
                policy.protocols.insert(
                    "HTTP",
                    Box::new(AllCredentialsPolicy {
                        supported_credential_types: supported_credential_types.clone(),
                        required_credential_types: p.into_iter().collect(),
                    }),
                );
            }
            if let Some(p) = req.mysql {
                policy.protocols.insert(
                    "MySQL",
                    Box::new(AllCredentialsPolicy {
                        supported_credential_types: supported_credential_types.clone(),
                        required_credential_types: p.into_iter().collect(),
                    }),
                );
            }
            if let Some(p) = req.postgres {
                policy.protocols.insert(
                    "PostgreSQL",
                    Box::new(AllCredentialsPolicy {
                        supported_credential_types: supported_credential_types.clone(),
                        required_credential_types: p.into_iter().collect(),
                    }),
                );
            }
            if let Some(p) = req.ssh {
                policy.protocols.insert(
                    "SSH",
                    Box::new(AllCredentialsPolicy {
                        supported_credential_types: supported_credential_types.clone(),
                        required_credential_types: p.into_iter().collect(),
                    }),
                );
            }
            if let Some(p) = req.vnc {
                policy.protocols.insert(
                    "VNC",
                    Box::new(AllCredentialsPolicy {
                        supported_credential_types: supported_credential_types.clone(),
                        required_credential_types: p.into_iter().collect(),
                    }),
                );
            }
            if let Some(p) = req.rdp {
                policy.protocols.insert(
                    "RDP",
                    Box::new(AllCredentialsPolicy {
                        supported_credential_types,
                        required_credential_types: p.into_iter().collect(),
                    }),
                );
            }

            Ok(Some(
                Box::new(policy) as Box<dyn CredentialPolicy + Sync + Send>
            ))
        } else {
            Ok(Some(default_policy))
        }
    }

    async fn username_for_sso_credential(
        &self,
        client_credential: &AuthCredential,
        preferred_username: Option<String>,
        sso_config: SsoProviderConfig,
    ) -> Result<Option<String>, WarpgateError> {
        let db = &self.db;

        let AuthCredential::Sso {
            provider: client_provider,
            email: client_email,
        } = client_credential
        else {
            return Ok(None);
        };

        let cred = entities::SsoCredential::Entity::find()
            .filter(
                entities::SsoCredential::Column::Email.eq(client_email).and(
                    entities::SsoCredential::Column::Provider
                        .eq(client_provider)
                        .or(entities::SsoCredential::Column::Provider.is_null()),
                ),
            )
            .one(db)
            .await?;

        if let Some(cred) = cred {
            let user = cred.find_related(entities::User::Entity).one(db).await?;

            if let Some(user) = user {
                return Ok(Some(user.username));
            }
        }

        if sso_config.auto_create_users {
            let Some(preferred_username) = preferred_username else {
                error!("The OIDC server did not provide a preferred_username claim for this user");
                return Ok(None);
            };
            return self
                .maybe_autocreate_sso_user(
                    db,
                    UserSsoCredential {
                        email: client_email.clone(),
                        provider: Some(client_provider.clone()),
                    },
                    preferred_username,
                    sso_config.default_credential_policy.clone(),
                )
                .await;
        }

        Ok(None)
    }

    async fn validate_credential(
        &self,
        username: &str,
        client_credential: &AuthCredential,
    ) -> Result<bool, WarpgateError> {
        let db = &self.db;

        let user_model = entities::User::Entity::find()
            .filter(entities::User::Entity::username_eq_ci(username))
            .one(db)
            .await?;

        let Some(user_model) = user_model else {
            error!("Selected user not found: {}", username);
            return Ok(false);
        };

        // Sync SSH keys from LDAP if user is linked
        if matches!(client_credential, AuthCredential::PublicKey { .. })
            && let (Some(ldap_server_id), Some(ldap_object_uuid)) =
                (user_model.ldap_server_id, &user_model.ldap_object_uuid)
            && let Err(e) = self
                .sync_ldap_ssh_keys(db, user_model.id, ldap_server_id, ldap_object_uuid)
                .await
        {
            warn!(
                "Failed to sync SSH keys from LDAP for user {}: {}",
                username, e
            );
        }

        let user_details = user_model.load_details(db).await?;

        match client_credential {
            AuthCredential::PublicKey {
                kind,
                public_key_bytes,
            } => {
                let base64_bytes = BASE64.encode(public_key_bytes);
                let openssh_public_key = format!("{kind} {base64_bytes}");
                debug!(
                    username = &user_details.username[..],
                    "Client key: {}", openssh_public_key
                );

                Ok(user_details
                    .credentials
                    .iter()
                    .any(|credential| match credential {
                        UserAuthCredential::PublicKey(UserPublicKeyCredential {
                            key: user_key,
                        }) => &openssh_public_key == user_key.expose_secret(),
                        _ => false,
                    }))
            }
            AuthCredential::Password(client_password) => {
                Ok(user_details
                    .credentials
                    .iter()
                    .any(|credential| match credential {
                        UserAuthCredential::Password(UserPasswordCredential {
                            hash: user_password_hash,
                        }) => verify_password_hash(
                            client_password.expose_secret(),
                            user_password_hash.expose_secret(),
                        )
                        .unwrap_or_else(|e| {
                            error!(
                                username = &user_details.username[..],
                                "Error verifying password hash: {}", e
                            );
                            false
                        }),
                        _ => false,
                    }))
            }
            AuthCredential::Otp(client_otp) => {
                Ok(user_details
                    .credentials
                    .iter()
                    .any(|credential| match credential {
                        UserAuthCredential::Totp(UserTotpCredential { key: user_otp_key }) => {
                            verify_totp(client_otp.expose_secret(), user_otp_key)
                        }
                        _ => false,
                    }))
            }
            AuthCredential::Sso {
                provider: client_provider,
                email: client_email,
            } => {
                for credential in &user_details.credentials {
                    if let UserAuthCredential::Sso(UserSsoCredential { provider, email }) =
                        credential
                        && provider.as_ref().unwrap_or(client_provider) == client_provider
                        && email == client_email
                    {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            _ => Err(WarpgateError::InvalidCredentialType),
        }
    }

    async fn authorize_target(
        &self,
        username: &str,
        target_name: &str,
    ) -> Result<bool, WarpgateError> {
        let authorized = active_role_assignment_query()
            .inner_join(
                entities::User::Entity,
                Expr::col((
                    entities::UserRoleAssignment::Entity,
                    entities::UserRoleAssignment::Column::UserId,
                ))
                .equals((entities::User::Entity, entities::User::Column::Id)),
            )
            .inner_join(
                entities::Target::Entity,
                Expr::col((
                    entities::TargetRoleAssignment::Entity,
                    entities::TargetRoleAssignment::Column::TargetId,
                ))
                .equals((entities::Target::Entity, entities::Target::Column::Id)),
            )
            .and_where(
                Expr::expr(Func::lower(Expr::col((
                    entities::User::Entity,
                    entities::User::Column::Username,
                ))))
                .eq(username.to_lowercase()),
            )
            .and_where(
                Expr::col((entities::Target::Entity, entities::Target::Column::Name))
                    .eq(target_name),
            )
            .exists(&self.db)
            .await?;

        if !authorized {
            // Cold path: distinguish a missing user/target from missing role
            // grants for diagnosability.
            if entities::User::Entity::find()
                .filter(entities::User::Entity::username_eq_ci(username))
                .one(&self.db)
                .await?
                .is_none()
            {
                error!("Selected user not found: {username}");
            } else if entities::Target::Entity::find()
                .filter(entities::Target::Column::Name.eq(target_name))
                .one(&self.db)
                .await?
                .is_none()
            {
                warn!("Selected target not found: {target_name}");
            }
        }

        Ok(authorized)
    }

    async fn authorize_target_by_id(
        &self,
        user_id: Uuid,
        target_id: Uuid,
    ) -> Result<bool, WarpgateError> {
        active_role_assignment_query()
            .and_where(
                Expr::col((
                    entities::UserRoleAssignment::Entity,
                    entities::UserRoleAssignment::Column::UserId,
                ))
                .eq(user_id),
            )
            .and_where(
                Expr::col((
                    entities::TargetRoleAssignment::Entity,
                    entities::TargetRoleAssignment::Column::TargetId,
                ))
                .eq(target_id),
            )
            .exists(&self.db)
            .await
    }

    async fn authorized_target_ids(&self, user_id: Uuid) -> Result<HashSet<Uuid>, WarpgateError> {
        let query = active_role_assignment_query()
            .column((
                entities::TargetRoleAssignment::Entity,
                entities::TargetRoleAssignment::Column::TargetId,
            ))
            .distinct()
            .and_where(
                Expr::col((
                    entities::UserRoleAssignment::Entity,
                    entities::UserRoleAssignment::Column::UserId,
                ))
                .eq(user_id),
            )
            .to_owned();

        self.db
            .query_all(self.db.get_database_backend().build(&query))
            .await?
            .iter()
            .map(|row| row.try_get_by_index(0))
            .collect::<Result<HashSet<Uuid>, _>>()
            .map_err(Into::into)
    }

    async fn apply_sso_role_mappings(
        &self,
        username: &str,
        managed_role_names: Option<Vec<String>>,
        assigned_role_names: Vec<String>,
    ) -> Result<(), WarpgateError> {
        let db = &self.db;

        let user = entities::User::Entity::find()
            .filter(entities::User::Entity::username_eq_ci(username))
            .one(db)
            .await?
            .ok_or_else(|| WarpgateError::UserNotFound(username.into()))?;

        let managed_role_names = match managed_role_names {
            Some(x) => x,
            None => entities::Role::Entity::find()
                .all(db)
                .await?
                .into_iter()
                .map(|x| x.name)
                .collect(),
        };

        for role_name in managed_role_names {
            let Some(role) = entities::Role::Entity::find()
                .filter(entities::Role::Column::Name.eq(role_name.clone()))
                .one(db)
                .await?
            else {
                warn!("SSO role mapping references non-existent role {role_name:?}, skipping");
                continue;
            };

            let assignment = entities::UserRoleAssignment::Entity::find_active()
                .filter(entities::UserRoleAssignment::Column::UserId.eq(user.id))
                .filter(entities::UserRoleAssignment::Column::RoleId.eq(role.id))
                .one(db)
                .await?;

            match (assignment, assigned_role_names.contains(&role_name)) {
                (None, true) => {
                    info!("Adding role {role_name} for user {username} (from SSO)");
                    entities::UserRoleAssignment::Entity::idempotent_grant(
                        db, user.id, role.id, None,
                    )
                    .await?;
                }
                (Some(assignment), false) => {
                    info!("Removing role {role_name} for user {username} (from SSO)");
                    let mut model: entities::UserRoleAssignment::ActiveModel = assignment.into();
                    model.revoked_at = Set(Some(OffsetDateTime::now_utc()));
                    model.update(db).await?;
                }
                _ => (),
            }
        }

        Ok(())
    }

    async fn apply_sso_admin_role_mappings(
        &self,
        username: &str,
        managed_admin_role_names: Option<Vec<String>>,
        assigned_admin_role_names: Vec<String>,
    ) -> Result<(), WarpgateError> {
        let db = &self.db;

        let user = entities::User::Entity::find()
            .filter(entities::User::Entity::username_eq_ci(username))
            .one(db)
            .await?
            .ok_or_else(|| WarpgateError::UserNotFound(username.into()))?;

        let managed_admin_role_names = match managed_admin_role_names {
            Some(x) => x,
            None => entities::AdminRole::Entity::find()
                .all(db)
                .await?
                .into_iter()
                .map(|x| x.name)
                .collect(),
        };

        for role_name in managed_admin_role_names {
            let role = entities::AdminRole::Entity::find()
                .filter(entities::AdminRole::Column::Name.eq(role_name.clone()))
                .one(db)
                .await?
                .ok_or_else(|| WarpgateError::RoleNotFound(role_name.clone()))?;

            let assignment = entities::UserAdminRoleAssignment::Entity::find()
                .filter(entities::UserAdminRoleAssignment::Column::UserId.eq(user.id))
                .filter(entities::UserAdminRoleAssignment::Column::AdminRoleId.eq(role.id))
                .one(db)
                .await?;

            match (assignment, assigned_admin_role_names.contains(&role_name)) {
                (None, true) => {
                    info!("Adding admin role {role_name} for user {username} (from SSO)");
                    let values = entities::UserAdminRoleAssignment::ActiveModel {
                        user_id: Set(user.id),
                        admin_role_id: Set(role.id),
                        ..Default::default()
                    };

                    values.insert(db).await?;
                }
                (Some(assignment), false) => {
                    info!("Removing admin role {role_name} for user {username} (from SSO)");
                    assignment.delete(db).await?;
                }
                _ => (),
            }
        }

        Ok(())
    }

    async fn update_public_key_last_used(
        &self,
        credential: Option<AuthCredential>,
    ) -> Result<(), WarpgateError> {
        let db = &self.db;

        let Some(AuthCredential::PublicKey {
            kind,
            public_key_bytes,
        }) = credential
        else {
            error!("Invalid or missing public key credential");
            return Err(WarpgateError::InvalidCredentialType);
        };

        // Encode public key and match it against the database
        let base64_bytes = data_encoding::BASE64.encode(&public_key_bytes);
        let openssh_public_key = format!("{kind} {base64_bytes}");

        debug!(
            "Attempting to update last_used for public key: {}",
            openssh_public_key
        );

        // Find the public key credential
        let public_key_credential = entities::PublicKeyCredential::Entity::find()
            .filter(
                entities::PublicKeyCredential::Column::OpensshPublicKey
                    .eq(openssh_public_key.clone()),
            )
            .one(db)
            .await?;

        let Some(public_key_credential) = public_key_credential else {
            warn!(
                "Public key not found in the database: {}",
                openssh_public_key
            );
            return Ok(()); // Gracefully return if the key is not found
        };

        // Update the `last_used` (last used) timestamp
        let mut active_model: entities::PublicKeyCredential::ActiveModel =
            public_key_credential.into();
        active_model.last_used = Set(Some(OffsetDateTime::now_utc()));

        active_model.update(db).await.map_err(|e| {
            error!("Failed to update last_used for public key: {:?}", e);
            WarpgateError::DatabaseError(e)
        })?;

        Ok(())
    }

    async fn validate_api_token(&self, token: &str) -> Result<Option<User>, WarpgateError> {
        let db = &self.db;
        let Some(api_token) = entities::ApiToken::Entity::find()
            .filter(
                entities::ApiToken::Column::Secret
                    .eq(token)
                    .and(entities::ApiToken::Column::Expiry.gt(OffsetDateTime::now_utc())),
            )
            .one(db)
            .await?
        else {
            return Ok(None);
        };

        let Some(user) = api_token
            .find_related(entities::User::Entity)
            .one(db)
            .await?
        else {
            return Err(WarpgateError::InconsistentState(
                "No user matching the ticket username".into(),
            ));
        };

        Ok(Some(user.try_into()?))
    }
}

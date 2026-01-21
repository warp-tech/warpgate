use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use chrono::Utc;
use data_encoding::BASE64;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, ModelTrait, QueryFilter,
    QueryOrder, Set,
};
use tokio::sync::Mutex;
use tracing::*;
use uuid::Uuid;
use warpgate_common::auth::{
    AllCredentialsPolicy, AnySingleCredentialPolicy, AuthCredential, CredentialKind,
    CredentialPolicy, PerProtocolCredentialPolicy,
};
use warpgate_common::helpers::hash::verify_password_hash;
use warpgate_common::helpers::otp::verify_totp;
use warpgate_common::{
    Role, Target, User, UserAuthCredential, UserPasswordCredential, UserPublicKeyCredential,
    UserRequireCredentialsPolicy, UserSsoCredential, UserTotpCredential, WarpgateError,
};
use warpgate_db_entities as entities;
use warpgate_sso::SsoProviderConfig;

use super::ConfigProvider;

pub struct DatabaseConfigProvider {
    db: Arc<Mutex<DatabaseConnection>>,
}

impl DatabaseConfigProvider {
    pub async fn new(db: &Arc<Mutex<DatabaseConnection>>) -> Self {
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
                    date_added: Set(Some(Utc::now())),
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
    ) -> Result<Option<String>, WarpgateError> {
        // Check for LDAP servers with auto-linking enabled
        let ldap_servers: Vec<entities::LdapServer::Model> = entities::LdapServer::Entity::find()
            .filter(entities::LdapServer::Column::Enabled.eq(true))
            .filter(entities::LdapServer::Column::AutoLinkSsoUsers.eq(true))
            .all(db)
            .await?;

        let mut ldap_server_id = None;
        let mut ldap_object_uuid = None;

        // Try to find user in LDAP servers
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

        let user = entities::User::ActiveModel {
            id: Set(Uuid::new_v4()),
            username: Set(preferred_username.clone()),
            description: Set("".into()),
            credential_policy: Set(serde_json::to_value(
                UserRequireCredentialsPolicy::default(),
            )?),
            rate_limit_bytes_per_second: Set(None),
            ldap_server_id: Set(ldap_server_id),
            ldap_object_uuid: Set(ldap_object_uuid),
        }
        .insert(db)
        .await?;

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

        Ok(Some(preferred_username))
    }
}

impl ConfigProvider for DatabaseConfigProvider {
    async fn list_users(&mut self) -> Result<Vec<User>, WarpgateError> {
        let db = self.db.lock().await;

        let users = entities::User::Entity::find()
            .order_by_asc(entities::User::Column::Username)
            .all(&*db)
            .await?;

        let users: Result<Vec<User>, _> = users.into_iter().map(|t| t.try_into()).collect();

        users
    }

    async fn list_targets(&mut self) -> Result<Vec<Target>, WarpgateError> {
        let db = self.db.lock().await;

        let targets = entities::Target::Entity::find()
            .order_by_asc(entities::Target::Column::Name)
            .all(&*db)
            .await?;

        let targets: Result<Vec<Target>, _> = targets.into_iter().map(|t| t.try_into()).collect();

        Ok(targets?)
    }

    async fn get_credential_policy(
        &mut self,
        username: &str,
        supported_credential_types: &[CredentialKind],
    ) -> Result<Option<Box<dyn CredentialPolicy + Sync + Send>>, WarpgateError> {
        let db = self.db.lock().await;

        let user_model = entities::User::Entity::find()
            .filter(entities::User::Column::Username.eq(username))
            .one(&*db)
            .await?;

        let Some(user_model) = user_model else {
            error!("Selected user not found: {}", username);
            return Ok(None);
        };

        let user = user_model.load_details(&db).await?;

        let mut available_credential_types = user
            .credentials
            .iter()
            .map(|x| x.kind())
            .collect::<HashSet<_>>();
        available_credential_types.insert(CredentialKind::WebUserApproval);

        let supported_credential_types = supported_credential_types
            .iter()
            .copied()
            .collect::<HashSet<_>>()
            .intersection(&available_credential_types)
            .copied()
            .collect::<HashSet<_>>();

        // "Any single credential" policy should not include WebUserApproval
        // if other authentication methods are available because it could lead to user confusion
        let default_policy = Box::new(AnySingleCredentialPolicy {
            supported_credential_types: if supported_credential_types.len() > 1 {
                supported_credential_types
                    .iter()
                    .cloned()
                    .filter(|x| x != &CredentialKind::WebUserApproval)
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
        &mut self,
        client_credential: &AuthCredential,
        preferred_username: Option<String>,
        sso_config: SsoProviderConfig,
    ) -> Result<Option<String>, WarpgateError> {
        let db = self.db.lock().await;

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
            .one(&*db)
            .await?;

        if let Some(cred) = cred {
            let user = cred.find_related(entities::User::Entity).one(&*db).await?;

            if let Some(user) = user {
                return Ok(Some(user.username.clone()));
            }
        }

        if sso_config.auto_create_users {
            let Some(preferred_username) = preferred_username else {
                error!("The OIDC server did not provide a preferred_username claim for this user");
                return Ok(None);
            };
            return self
                .maybe_autocreate_sso_user(
                    &db,
                    UserSsoCredential {
                        email: client_email.clone(),
                        provider: Some(client_provider.clone()),
                    },
                    preferred_username,
                )
                .await;
        }

        Ok(None)
    }

    async fn validate_credential(
        &mut self,
        username: &str,
        client_credential: &AuthCredential,
    ) -> Result<bool, WarpgateError> {
        let db = self.db.lock().await;

        let user_model = entities::User::Entity::find()
            .filter(entities::User::Column::Username.eq(username))
            .one(&*db)
            .await?;

        let Some(user_model) = user_model else {
            error!("Selected user not found: {}", username);
            return Ok(false);
        };

        // Sync SSH keys from LDAP if user is linked
        if matches!(client_credential, AuthCredential::PublicKey { .. }) {
            if let (Some(ldap_server_id), Some(ldap_object_uuid)) =
                (user_model.ldap_server_id, &user_model.ldap_object_uuid)
            {
                if let Err(e) = self
                    .sync_ldap_ssh_keys(&db, user_model.id, ldap_server_id, ldap_object_uuid)
                    .await
                {
                    warn!(
                        "Failed to sync SSH keys from LDAP for user {}: {}",
                        username, e
                    );
                }
            }
        }

        let user_details = user_model.load_details(&db).await?;

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
                            key: ref user_key,
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
                            hash: ref user_password_hash,
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
                        UserAuthCredential::Totp(UserTotpCredential {
                            key: ref user_otp_key,
                        }) => verify_totp(client_otp.expose_secret(), user_otp_key),
                        _ => false,
                    }))
            }
            AuthCredential::Sso {
                provider: client_provider,
                email: client_email,
            } => {
                for credential in user_details.credentials.iter() {
                    if let UserAuthCredential::Sso(UserSsoCredential {
                        ref provider,
                        ref email,
                    }) = credential
                    {
                        if provider.as_ref().unwrap_or(client_provider) == client_provider
                            && email == client_email
                        {
                            return Ok(true);
                        }
                    }
                }
                Ok(false)
            }
            _ => Err(WarpgateError::InvalidCredentialType),
        }
    }

    async fn authorize_target(
        &mut self,
        username: &str,
        target_name: &str,
    ) -> Result<bool, WarpgateError> {
        let db = self.db.lock().await;

        let target_model = entities::Target::Entity::find()
            .filter(entities::Target::Column::Name.eq(target_name))
            .one(&*db)
            .await?;

        let user_model = entities::User::Entity::find()
            .filter(entities::User::Column::Username.eq(username))
            .one(&*db)
            .await?;

        let Some(user_model) = user_model else {
            error!("Selected user not found: {}", username);
            return Ok(false);
        };

        let Some(target_model) = target_model else {
            warn!("Selected target not found: {}", target_name);
            return Ok(false);
        };

        let target_roles: HashSet<String> = target_model
            .find_related(entities::Role::Entity)
            .all(&*db)
            .await?
            .into_iter()
            .map(Into::<Role>::into)
            .map(|x| x.name)
            .collect();

        let user_roles: HashSet<String> = user_model
            .find_related(entities::Role::Entity)
            .all(&*db)
            .await?
            .into_iter()
            .map(Into::<Role>::into)
            .map(|x| x.name)
            .collect();

        let intersect = user_roles.intersection(&target_roles).count() > 0;

        Ok(intersect)
    }

    async fn authorize_target_file_transfer(
        &mut self,
        username: &str,
        target: &warpgate_common::Target,
    ) -> Result<super::FileTransferPermission, WarpgateError> {
        let db = self.db.lock().await;

        // Get user's role IDs
        let user_model = entities::User::Entity::find()
            .filter(entities::User::Column::Username.eq(username))
            .one(&*db)
            .await?;

        let Some(user_model) = user_model else {
            error!("Selected user not found: {}", username);
            return Ok(super::FileTransferPermission::default());
        };

        let user_roles: HashSet<uuid::Uuid> = user_model
            .find_related(entities::Role::Entity)
            .all(&*db)
            .await?
            .into_iter()
            .map(|r| r.id)
            .collect();

        // Get target's role assignments with file transfer permissions
        let assignments: Vec<entities::TargetRoleAssignment::Model> =
            entities::TargetRoleAssignment::Entity::find()
                .filter(entities::TargetRoleAssignment::Column::TargetId.eq(target.id))
                .all(&*db)
                .await?;

        // Permissive model: if ANY matching role allows, grant permission
        let mut result = super::FileTransferPermission::default();

        for assignment in assignments {
            if user_roles.contains(&assignment.role_id) {
                // Permissive: any true grants access
                result.upload_allowed |= assignment.allow_file_upload;
                result.download_allowed |= assignment.allow_file_download;

                // For restrictions, use most permissive (union paths, largest size limit)
                if let Some(paths) = assignment.allowed_paths {
                    if let Ok(paths) = serde_json::from_value::<Vec<String>>(paths) {
                        match &mut result.allowed_paths {
                            Some(existing) => existing.extend(paths),
                            None => result.allowed_paths = Some(paths),
                        }
                    }
                }

                // Blocked extensions: intersection (only block if ALL roles block)
                if let Some(extensions) = assignment.blocked_extensions {
                    if let Ok(extensions) = serde_json::from_value::<Vec<String>>(extensions) {
                        match &mut result.blocked_extensions {
                            Some(existing) => {
                                // Keep only extensions blocked by ALL roles
                                existing.retain(|ext| extensions.contains(ext));
                            }
                            None => result.blocked_extensions = Some(extensions),
                        }
                    }
                }

                // Size limit: use largest (most permissive)
                if let Some(size) = assignment.max_file_size {
                    result.max_file_size = Some(result.max_file_size.map_or(size, |s| s.max(size)));
                }
            }
        }

        Ok(result)
    }

    async fn apply_sso_role_mappings(
        &mut self,
        username: &str,
        managed_role_names: Option<Vec<String>>,
        assigned_role_names: Vec<String>,
    ) -> Result<(), WarpgateError> {
        let db = self.db.lock().await;

        let user = entities::User::Entity::find()
            .filter(entities::User::Column::Username.eq(username))
            .one(&*db)
            .await?
            .ok_or_else(|| WarpgateError::UserNotFound(username.into()))?;

        let managed_role_names = match managed_role_names {
            Some(x) => x,
            None => entities::Role::Entity::find()
                .all(&*db)
                .await?
                .into_iter()
                .map(|x| x.name)
                .collect(),
        };

        for role_name in managed_role_names.into_iter() {
            let role = entities::Role::Entity::find()
                .filter(entities::Role::Column::Name.eq(role_name.clone()))
                .one(&*db)
                .await?
                .ok_or_else(|| WarpgateError::RoleNotFound(role_name.clone()))?;

            let assignment = entities::UserRoleAssignment::Entity::find()
                .filter(entities::UserRoleAssignment::Column::UserId.eq(user.id))
                .filter(entities::UserRoleAssignment::Column::RoleId.eq(role.id))
                .one(&*db)
                .await?;

            match (assignment, assigned_role_names.contains(&role_name)) {
                (None, true) => {
                    info!("Adding role {role_name} for user {username} (from SSO)");
                    let values = entities::UserRoleAssignment::ActiveModel {
                        user_id: Set(user.id),
                        role_id: Set(role.id),
                        ..Default::default()
                    };

                    values.insert(&*db).await?;
                }
                (Some(assignment), false) => {
                    info!("Removing role {role_name} for user {username} (from SSO)");
                    assignment.delete(&*db).await?;
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
        let db = self.db.lock().await;

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
            .one(&*db)
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
        active_model.last_used = Set(Some(Utc::now()));

        active_model.update(&*db).await.map_err(|e| {
            error!("Failed to update last_used for public key: {:?}", e);
            WarpgateError::DatabaseError(e)
        })?;

        Ok(())
    }

    async fn validate_api_token(&mut self, token: &str) -> Result<Option<User>, WarpgateError> {
        let db = self.db.lock().await;
        let Some(ticket) = entities::ApiToken::Entity::find()
            .filter(
                entities::ApiToken::Column::Secret
                    .eq(token)
                    .and(entities::ApiToken::Column::Expiry.gt(Utc::now())),
            )
            .one(&*db)
            .await?
        else {
            return Ok(None);
        };

        let Some(user) = ticket
            .find_related(entities::User::Entity)
            .one(&*db)
            .await?
        else {
            return Err(WarpgateError::InconsistentState);
        };

        Ok(Some(user.try_into()?))
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_file_transfer_permission_default() {
        let perm = super::super::FileTransferPermission::default();
        assert!(!perm.upload_allowed);
        assert!(!perm.download_allowed);
        assert!(perm.allowed_paths.is_none());
        assert!(perm.blocked_extensions.is_none());
        assert!(perm.max_file_size.is_none());
    }

    #[test]
    fn test_file_transfer_permission_permissive_or_logic() {
        // Test that the permissive model uses OR logic for upload/download
        let mut result = super::super::FileTransferPermission::default();

        // Simulate first role: upload allowed, download denied
        result.upload_allowed |= true;
        result.download_allowed |= false;

        assert!(result.upload_allowed);
        assert!(!result.download_allowed);

        // Simulate second role: upload denied, download allowed
        result.upload_allowed |= false;
        result.download_allowed |= true;

        // Both should now be allowed (permissive model)
        assert!(result.upload_allowed);
        assert!(result.download_allowed);
    }

    #[test]
    fn test_file_transfer_permission_size_limit_most_permissive() {
        // Test that the most permissive (largest) size limit is used
        let mut result = super::super::FileTransferPermission::default();

        // First role: 1MB limit
        let size1 = 1_000_000i64;
        result.max_file_size = Some(result.max_file_size.map_or(size1, |s| s.max(size1)));
        assert_eq!(result.max_file_size, Some(1_000_000));

        // Second role: 10MB limit (should override)
        let size2 = 10_000_000i64;
        result.max_file_size = Some(result.max_file_size.map_or(size2, |s| s.max(size2)));
        assert_eq!(result.max_file_size, Some(10_000_000));

        // Third role: 5MB limit (should NOT override, smaller)
        let size3 = 5_000_000i64;
        result.max_file_size = Some(result.max_file_size.map_or(size3, |s| s.max(size3)));
        assert_eq!(result.max_file_size, Some(10_000_000));
    }

    #[test]
    fn test_file_transfer_permission_allowed_paths_union() {
        // Test that allowed paths are unioned (most permissive)
        let mut result = super::super::FileTransferPermission::default();

        // First role: /home allowed
        let paths1 = vec!["/home".to_string()];
        match &mut result.allowed_paths {
            Some(existing) => existing.extend(paths1),
            None => result.allowed_paths = Some(paths1),
        }
        assert_eq!(result.allowed_paths, Some(vec!["/home".to_string()]));

        // Second role: /var and /tmp allowed
        let paths2 = vec!["/var".to_string(), "/tmp".to_string()];
        match &mut result.allowed_paths {
            Some(existing) => existing.extend(paths2),
            None => result.allowed_paths = Some(paths2),
        }
        assert_eq!(
            result.allowed_paths,
            Some(vec![
                "/home".to_string(),
                "/var".to_string(),
                "/tmp".to_string()
            ])
        );
    }

    #[test]
    fn test_file_transfer_permission_blocked_extensions_intersection() {
        // Test that blocked extensions are intersected (only block if ALL roles block)
        let mut result = super::super::FileTransferPermission::default();

        // First role: block .exe and .bat
        let ext1 = vec![".exe".to_string(), ".bat".to_string()];
        match &mut result.blocked_extensions {
            Some(existing) => existing.retain(|ext| ext1.contains(ext)),
            None => result.blocked_extensions = Some(ext1),
        }
        assert_eq!(
            result.blocked_extensions,
            Some(vec![".exe".to_string(), ".bat".to_string()])
        );

        // Second role: block .exe and .sh (not .bat)
        let ext2 = vec![".exe".to_string(), ".sh".to_string()];
        match &mut result.blocked_extensions {
            Some(existing) => existing.retain(|ext| ext2.contains(ext)),
            None => result.blocked_extensions = Some(ext2),
        }
        // Only .exe should remain (blocked by both roles)
        assert_eq!(result.blocked_extensions, Some(vec![".exe".to_string()]));
    }
}

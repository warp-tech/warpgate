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
    CredentialPolicy, PerProtocolCredentialPolicy, StoredCredential, StoredCredentialId,
    StoredCredentialKind,
};
use warpgate_common::helpers::hash::{hash_secret, verify_password_hash};
use warpgate_common::helpers::otp::verify_totp;
use warpgate_common::{
    Protocol, Target, User, UserAuthCredential, UserPublicKeyCredential,
    UserRequireCredentialsPolicy, UserSsoCredential, WarpgateError,
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

/// What one reconcile did, for the caller's log line.
struct SshKeySync {
    unchanged: usize,
    added: usize,
    removed: usize,
}

/// Brings a user's stored public keys in line with `desired`, touching only
/// what actually differs.
///
/// Reconciled rather than replaced because this runs on *every* public-key
/// login, and a row carries more than its key: the id, and `date_added` /
/// `last_used`. Deleting and re-inserting the lot would reset all three for
/// keys that never changed, and would give a user a different key identity on
/// every login.
///
/// `desired` must already be normalised — see the caller.
async fn reconcile_ldap_ssh_keys(
    db: &DatabaseConnection,
    user_id: Uuid,
    desired: HashSet<String>,
) -> Result<SshKeySync, WarpgateError> {
    let existing = entities::PublicKeyCredential::Entity::find()
        .filter(entities::PublicKeyCredential::Column::UserId.eq(user_id))
        .all(db)
        .await?;

    let mut present = HashSet::new();
    let mut withdrawn = vec![];
    for row in existing {
        if desired.contains(&row.openssh_public_key) {
            present.insert(row.openssh_public_key);
        } else {
            withdrawn.push(row.id);
        }
    }

    let removed = withdrawn.len();
    if !withdrawn.is_empty() {
        entities::PublicKeyCredential::Entity::delete_many()
            .filter(entities::PublicKeyCredential::Column::Id.is_in(withdrawn))
            .exec(db)
            .await?;
    }

    let mut added = 0;
    for openssh_key in desired.difference(&present) {
        entities::PublicKeyCredential::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(user_id),
            date_added: Set(Some(OffsetDateTime::now_utc())),
            last_used: Set(None),
            label: Set("Public key synchronized from LDAP".to_string()),
            ..entities::PublicKeyCredential::ActiveModel::from(UserPublicKeyCredential {
                key: openssh_key.clone().into(),
            })
        }
        .insert(db)
        .await?;
        added += 1;
    }

    Ok(SshKeySync {
        unchanged: present.len(),
        added,
        removed,
    })
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

        // Normalised so a key that differs only by its comment is the same key.
        let mut desired = HashSet::new();
        for ssh_key in &ldap_user.ssh_public_keys {
            let ssh_key = ssh_key.trim();
            if ssh_key.is_empty() {
                continue;
            }
            match russh::keys::PublicKey::from_openssh(ssh_key) {
                Ok(mut key) => {
                    key.set_comment("");
                    desired.insert(
                        key.to_openssh()
                            .map_err(russh::keys::Error::from)?
                            .to_string(),
                    );
                }
                Err(_) => warn!("Invalid SSH key from LDAP: {}", ssh_key),
            }
        }

        let SshKeySync {
            unchanged,
            added,
            removed,
        } = reconcile_ldap_ssh_keys(db, user_id, desired).await?;

        info!(
            "Synced SSH keys from LDAP for {}: {unchanged} unchanged, {added} added, {removed} removed",
            ldap_user.username,
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

    async fn get_target_by_id(&self, id: Uuid) -> Result<Option<Target>, WarpgateError> {
        entities::Target::Entity::find_by_id(id)
            .one(&self.db)
            .await?
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

        // "Any single credential" policy should not include WebUserApproval
        // if other authentication methods are available because it could lead to user confusion
        let default_policy = Box::new(AnySingleCredentialPolicy {
            supported_credential_types: if supported_credential_types.len() > 1 {
                supported_credential_types
                    .iter()
                    .copied()
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

            // Only HTTP performs an SSO exchange inline; no other protocol can
            // carry one on the wire, so there a required `Sso` is satisfied by
            // the in-browser approval flow instead. Keyed off the protocol
            // rather than a per-entry flag so the rule has one statement.
            let make_policy = |protocol: Protocol, required: Vec<CredentialKind>| {
                let required_credential_types = required
                    .into_iter()
                    .map(|kind| match (kind, protocol) {
                        (CredentialKind::Sso, Protocol::Http) => CredentialKind::Sso,
                        (CredentialKind::Sso, _) => CredentialKind::WebUserApproval,
                        (kind, _) => kind,
                    })
                    .collect();
                Box::new(AllCredentialsPolicy {
                    supported_credential_types: supported_credential_types.clone(),
                    required_credential_types,
                }) as Box<dyn CredentialPolicy + Sync + Send>
            };

            // Full destructuring so a new per-protocol config field can't be
            // silently left out of the policy map.
            let UserRequireCredentialsPolicy {
                http,
                kubernetes,
                ssh,
                mysql,
                postgres,
                vnc,
                rdp,
            } = req;

            for (protocol, required) in [
                (Protocol::Http, http),
                (Protocol::Kubernetes, kubernetes),
                (Protocol::Ssh, ssh),
                (Protocol::MySql, mysql),
                (Protocol::Postgres, postgres),
                (Protocol::Vnc, vnc),
                (Protocol::Rdp, rdp),
            ] {
                if let Some(required) = required {
                    policy
                        .protocols
                        .insert(protocol, make_policy(protocol, required));
                }
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
    ) -> Result<Option<StoredCredential>, WarpgateError> {
        let db = &self.db;

        let user_model = entities::User::Entity::find()
            .filter(entities::User::Entity::username_eq_ci(username))
            .one(db)
            .await?;

        let Some(user_model) = user_model else {
            error!("Selected user not found: {}", username);
            return Ok(None);
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

        // Matched against the credential rows themselves rather than through
        // `load_details`, which drops the row id on its way to
        // `UserAuthCredential` — and the id is half of what identifies a
        // credential. Also one query instead of six.
        //
        // `order_by_asc(Id)` because duplicate rows are reachable (two SSO rows
        // for one email, one of them provider-less) and `.all()` has no defined
        // order: without it, which row a login identifies could vary run to run.
        //
        // Every comparison stays in Rust: MySQL's default collation is
        // case-insensitive, and base64 key material and emails are not.
        let matched: Option<StoredCredential> = match client_credential {
            AuthCredential::PublicKey {
                kind,
                public_key_bytes,
            } => {
                let openssh_public_key = format!("{kind} {}", BASE64.encode(public_key_bytes));
                debug!(
                    username = &user_model.username[..],
                    "Client key: {openssh_public_key}"
                );

                user_model
                    .find_related(entities::PublicKeyCredential::Entity)
                    .order_by_asc(entities::PublicKeyCredential::Column::Id)
                    .all(db)
                    .await?
                    .into_iter()
                    .find(|c| c.openssh_public_key == openssh_public_key)
                    .map(|c| {
                        StoredCredential::new(
                            StoredCredentialKind::PublicKey,
                            c.id,
                            StoredCredentialId::of_stored_verifier(c.openssh_public_key.as_bytes()),
                        )
                    })
            }

            AuthCredential::Password(client_password) => user_model
                .find_related(entities::PasswordCredential::Entity)
                .order_by_asc(entities::PasswordCredential::Column::Id)
                .all(db)
                .await?
                .into_iter()
                .find(|c| {
                    verify_password_hash(client_password.expose_secret(), &c.argon_hash)
                        .unwrap_or_else(|e| {
                            error!(
                                username = &user_model.username[..],
                                "Error verifying password hash: {e}"
                            );
                            false
                        })
                })
                .map(|c| {
                    StoredCredential::new(
                        StoredCredentialKind::Password,
                        c.id,
                        // The stored Argon2 hash, never the password: the hash
                        // is already in this database, so nothing new reaches
                        // the approval rows.
                        StoredCredentialId::of_stored_verifier(c.argon_hash.as_bytes()),
                    )
                }),

            // `find`, not `any`: the row that actually verified the code is the
            // credential being asserted. A one-time code rotates every 30s; the
            // row it belongs to does not.
            AuthCredential::Otp(client_otp) => user_model
                .find_related(entities::OtpCredential::Entity)
                .order_by_asc(entities::OtpCredential::Column::Id)
                .all(db)
                .await?
                .into_iter()
                .find(|c| verify_totp(client_otp.expose_secret(), &c.secret_key.clone().into()))
                .map(|c| {
                    StoredCredential::new(
                        StoredCredentialKind::Totp,
                        c.id,
                        StoredCredentialId::of_stored_verifier(&c.secret_key),
                    )
                }),

            AuthCredential::Sso {
                provider: client_provider,
                email: client_email,
            } => user_model
                .find_related(entities::SsoCredential::Entity)
                .order_by_asc(entities::SsoCredential::Column::Id)
                .all(db)
                .await?
                .into_iter()
                // A stored credential naming no provider still matches any of
                // them, as before.
                .find(|c| {
                    &c.email == client_email
                        && c.provider.as_ref().is_none_or(|p| p == client_provider)
                })
                .map(|c| {
                    let mut verifier = c.provider.clone().unwrap_or_default().into_bytes();
                    verifier.push(0);
                    verifier.extend_from_slice(c.email.as_bytes());
                    StoredCredential::new(
                        StoredCredentialKind::Sso,
                        c.id,
                        // The stored row, so nothing the client supplied reaches
                        // the approval rows.
                        StoredCredentialId::of_stored_verifier(&verifier),
                    )
                }),

            _ => return Err(WarpgateError::InvalidCredentialType),
        };

        Ok(matched)
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
                entities::ApiToken::Column::SecretHash
                    .eq(hash_secret(token))
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
                "No user matching the API token".into(),
            ));
        };

        Ok(Some(user.try_into()?))
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use sea_orm::ActiveValue::Set;
    use sea_orm::{ActiveModelTrait, Database};
    use warpgate_common::auth::StoredCredentials;
    use warpgate_common::helpers::hash::hash_password;
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
    use warpgate_db_migrations::migrate_database;

    use super::*;

    async fn user_with_password(db: &DatabaseConnection, username: &str, password: &str) {
        let user = entities::User::ActiveModel {
            id: Set(Uuid::new_v4()),
            username: Set(username.to_owned()),
            description: Set(String::new()),
            credential_policy: Set(serde_json::json!(null)),
            ..Default::default()
        }
        .insert(db)
        .await
        .unwrap();

        entities::PasswordCredential::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(user.id),
            argon_hash: Set(hash_password(password)),
        }
        .insert(db)
        .await
        .unwrap();
    }

    async fn user_with_key(db: &DatabaseConnection, key: &str) -> (Uuid, Uuid) {
        let user = entities::User::ActiveModel {
            id: Set(Uuid::new_v4()),
            username: Set("ldap-user".to_owned()),
            description: Set(String::new()),
            credential_policy: Set(serde_json::json!(null)),
            ..Default::default()
        }
        .insert(db)
        .await
        .unwrap();

        let credential = entities::PublicKeyCredential::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(user.id),
            label: Set("from LDAP".to_owned()),
            date_added: Set(Some(OffsetDateTime::UNIX_EPOCH)),
            last_used: Set(Some(OffsetDateTime::UNIX_EPOCH)),
            openssh_public_key: Set(key.to_owned()),
        }
        .insert(db)
        .await
        .unwrap();

        (user.id, credential.id)
    }

    /// The sync runs on *every* public-key login. Replacing the rows wholesale
    /// would give a key a new id each time — and the id is what a remembered
    /// approval is keyed on — as well as resetting when the key was added and
    /// wiping when it was last used.
    #[tokio::test]
    async fn re_syncing_leaves_an_unchanged_key_alone() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let (user_id, credential_id) = user_with_key(&db, "ssh-ed25519 AAAAkept").await;

        let sync = reconcile_ldap_ssh_keys(
            &db,
            user_id,
            [
                "ssh-ed25519 AAAAkept".to_owned(),
                "ssh-ed25519 AAAAnew".to_owned(),
            ]
            .into_iter()
            .collect(),
        )
        .await
        .unwrap();
        assert_eq!((sync.unchanged, sync.added, sync.removed), (1, 1, 0));

        let kept = entities::PublicKeyCredential::Entity::find_by_id(credential_id)
            .one(&db)
            .await
            .unwrap()
            .expect("the unchanged key must keep its row, and so its identity");
        assert_eq!(kept.openssh_public_key, "ssh-ed25519 AAAAkept");
        assert_eq!(kept.date_added, Some(OffsetDateTime::UNIX_EPOCH));
        assert_eq!(
            kept.last_used,
            Some(OffsetDateTime::UNIX_EPOCH),
            "a re-sync must not forget when the key was last used",
        );
    }

    /// The other half: LDAP is the authority, so a key it stops listing goes.
    #[tokio::test]
    async fn re_syncing_removes_a_withdrawn_key() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let (user_id, credential_id) = user_with_key(&db, "ssh-ed25519 AAAAold").await;

        let sync = reconcile_ldap_ssh_keys(&db, user_id, HashSet::new())
            .await
            .unwrap();
        assert_eq!((sync.unchanged, sync.added, sync.removed), (0, 0, 1));
        assert!(
            entities::PublicKeyCredential::Entity::find_by_id(credential_id)
                .one(&db)
                .await
                .unwrap()
                .is_none()
        );
    }

    async fn user_named(db: &DatabaseConnection, username: &str) -> Uuid {
        entities::User::ActiveModel {
            id: Set(Uuid::new_v4()),
            username: Set(username.to_owned()),
            description: Set(String::new()),
            credential_policy: Set(serde_json::json!(null)),
            ..Default::default()
        }
        .insert(db)
        .await
        .unwrap()
        .id
    }

    async fn add_key(db: &DatabaseConnection, user_id: Uuid, key: &str) -> Uuid {
        entities::PublicKeyCredential::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(user_id),
            label: Set(String::new()),
            date_added: Set(None),
            last_used: Set(None),
            openssh_public_key: Set(key.to_owned()),
        }
        .insert(db)
        .await
        .unwrap()
        .id
    }

    /// What production actually compares: the digest the approval row carries,
    /// not the struct. A field missing from the encoding is invisible to `==`.
    fn identity_digest(credential: StoredCredential) -> String {
        StoredCredentials::new(vec![credential]).unwrap().digest()
    }

    fn offered_key(key: &str) -> AuthCredential {
        let (kind, base64) = key.split_once(' ').unwrap();
        AuthCredential::PublicKey {
            kind: kind.parse().unwrap(),
            public_key_bytes: BASE64.decode(base64.as_bytes()).unwrap().into(),
        }
    }

    /// Two users may enrol the very same public key. Keyed on the material
    /// alone they would be one credential, and an approval remembered for one
    /// would be matched by the other.
    #[tokio::test]
    async fn one_key_enrolled_twice_is_two_credentials() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();

        let key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKp8kMhTHrJRfKPQD5vJ3vRZ0F3sZbXQ0m5vZ8xJvVQe";
        let alice = user_named(&db, "alice").await;
        let bob = user_named(&db, "bob").await;
        add_key(&db, alice, key).await;
        add_key(&db, bob, key).await;

        let provider = DatabaseConfigProvider::new(&db);
        let offered = offered_key(key);
        let for_alice = provider
            .validate_credential("alice", &offered)
            .await
            .unwrap();
        let for_bob = provider.validate_credential("bob", &offered).await.unwrap();

        let for_alice = for_alice.expect("alice's key is accepted");
        let for_bob = for_bob.expect("bob's key is accepted");
        assert_ne!(
            identity_digest(for_alice),
            identity_digest(for_bob),
            "the same key in two rows is two credentials",
        );
    }

    /// The admin endpoint replaces a key's material while keeping its row, so
    /// the id alone cannot notice a rotation — an approval remembered for the
    /// old key would carry over to whatever replaced it.
    #[tokio::test]
    async fn replacing_a_keys_material_in_place_changes_its_identity() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();

        let old =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKp8kMhTHrJRfKPQD5vJ3vRZ0F3sZbXQ0m5vZ8xJvVQe";
        let new =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB2vQ8kZ0F3sZbXQ0m5vZ8xJvVQeKp8kMhTHrJRfKPQD";
        let user_id = user_named(&db, "alice").await;
        let credential_id = add_key(&db, user_id, old).await;

        let provider = DatabaseConfigProvider::new(&db);
        let before = provider
            .validate_credential("alice", &offered_key(old))
            .await
            .unwrap()
            .expect("the enrolled key is accepted");

        // Exactly what `PUT .../public-keys/:id` does: same row, new material.
        entities::PublicKeyCredential::ActiveModel {
            id: Set(credential_id),
            openssh_public_key: Set(new.to_owned()),
            ..Default::default()
        }
        .update(&db)
        .await
        .unwrap();

        let after = provider
            .validate_credential("alice", &offered_key(new))
            .await
            .unwrap()
            .expect("the replacement is accepted");

        assert_ne!(
            identity_digest(before),
            identity_digest(after),
            "a rotated key must not inherit the old key's remembered approvals",
        );
    }

    /// The fingerprint an accepted password produces must follow the *stored*
    /// credential, not the password itself.
    ///
    /// Two accounts sharing a password are two different stored rows, so they
    /// must not share an identity. Deriving it from the submitted password
    /// would make them identical — and would put a digest of a live password
    /// into the approval rows, beside the Argon2 hash meant to protect it.
    #[tokio::test]
    async fn a_password_is_identified_by_its_stored_row() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        user_with_password(&db, "alice", "same-password").await;
        user_with_password(&db, "bob", "same-password").await;

        let provider = DatabaseConfigProvider::new(&db);
        let submitted = AuthCredential::Password("same-password".to_string().into());

        let alice = provider
            .validate_credential("alice", &submitted)
            .await
            .unwrap()
            .expect("the password should be accepted");
        let bob = provider
            .validate_credential("bob", &submitted)
            .await
            .unwrap()
            .expect("the password should be accepted");

        assert_ne!(
            identity_digest(alice),
            identity_digest(bob),
            "one password must not identify two stored credentials",
        );
        assert_eq!(
            alice,
            provider
                .validate_credential("alice", &submitted)
                .await
                .unwrap()
                .unwrap(),
            "the same stored credential must stay recognisable, or no approval could be remembered",
        );
        assert_eq!(
            provider
                .validate_credential(
                    "alice",
                    &AuthCredential::Password("wrong".to_string().into())
                )
                .await
                .unwrap(),
            None,
        );
    }
}

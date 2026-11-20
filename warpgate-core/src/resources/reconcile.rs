use std::collections::{HashMap, HashSet};

use sea_orm::{
    ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter, TransactionSession,
    TransactionTrait,
};
use uuid::Uuid;
use warpgate_common::{
    MaybeSecretRef, ProviderId, RoleId, RowId, SSHTargetAuth, SecretResolver, SshClientKeyId,
    StoredSecret, Target as TargetConfig, TargetGroupId, TargetId, TargetOptions, TargetSecrets,
    WarpgateError,
};
use warpgate_db_entities::{Role, SshClientKey, Target, TargetGroup, TargetRoleAssignment};
use warpgate_gitops::plan::{Change, Current, Plan, References, Row, plan};
use warpgate_gitops::types::{
    Manifest, OptionReferences, Resource, ResourceKind, RoleSpec, SshClientKeySpec,
    TargetGroupSpec, TargetSpec,
};

use super::roles::{self, RoleDataRequest};
use super::ssh_client_keys::{self, KeyMaterial, SshClientKeyDataRequest};
use super::target_groups::{self, TargetGroupDataRequest};
use super::targets::{self, TargetDataRequest};
use super::{Actor, AdmittedSessions, OwnedEntity, ResourceError, set_owner};

/// The rows a plan is computed against, with references by name. Inline
/// credentials come back decrypted so they compare with a file's literals:
/// the result must not be logged.
pub async fn load_current<C: ConnectionTrait>(db: &C) -> Result<Current, WarpgateError> {
    let groups = TargetGroup::Entity::find().all(db).await?;
    let roles = Role::Entity::find().all(db).await?;
    let group_names: HashMap<TargetGroupId, &str> =
        groups.iter().map(|g| (g.id, g.name.as_str())).collect();
    let role_names: HashMap<RoleId, &str> = roles.iter().map(|r| (r.id, r.name.as_str())).collect();

    let mut target_roles: HashMap<TargetId, Vec<String>> = HashMap::new();
    for assignment in TargetRoleAssignment::Entity::find().all(db).await? {
        if let Some(name) = role_names.get(&assignment.role_id) {
            target_roles
                .entry(assignment.target_id)
                .or_default()
                .push((*name).to_owned());
        }
    }

    let keys = SshClientKey::Entity::find().all(db).await?;
    let key_names: HashMap<SshClientKeyId, String> =
        keys.iter().map(|k| (k.id, k.label.clone())).collect();
    let models = Target::Entity::find().all(db).await?;
    let target_names: HashMap<TargetId, String> =
        models.iter().map(|t| (t.id, t.name.clone())).collect();
    let mut targets = Vec::new();
    for model in models {
        let mut target = TargetConfig::try_from(model)?;
        let mut references = OptionReferences::default();
        if let TargetOptions::Ssh(ssh) = &mut target.options {
            // A deleted jump host keeps its ID as the name. No row is called
            // that, so a plan refuses the target.
            references.jump_host = ssh.jump_host.take().map(|id| {
                let name = target_names.get(&id).cloned();
                name.unwrap_or_else(|| id.to_string())
            });
            if let SSHTargetAuth::PublicKey(auth) = &mut ssh.auth {
                // A deleted key is treated as no key. A connection falls back
                // to the default keys in the same way.
                references.client_key = auth
                    .key_id
                    .take()
                    .and_then(|id| key_names.get(&id).cloned());
            }
        }
        for slot in target.options.secrets_mut() {
            reveal_inline(slot)?;
        }
        targets.push(Row {
            id: target.id.uuid(),
            name: target.name,
            provider: target.provider,
            live: TargetSpec {
                description: target.description,
                group: target
                    .group_id
                    .and_then(|id| group_names.get(&id))
                    .map(|name| (*name).to_owned()),
                roles: target_roles.remove(&target.id).unwrap_or_default(),
                options: target.options,
                rate_limit_bytes_per_second: target.rate_limit_bytes_per_second,
                ticket_max_duration_seconds: target.ticket_max_duration_seconds,
                ticket_requests_disabled: target.ticket_requests_disabled,
                ticket_require_approval: target.ticket_require_approval,
                require_approval: target.require_approval,
                ticket_max_uses: target.ticket_max_uses,
                references,
            },
        });
    }

    Ok(Current {
        groups: groups
            .into_iter()
            .map(|group| Row {
                id: group.id.uuid(),
                name: group.name,
                provider: group.provider,
                live: TargetGroupSpec {
                    description: group.description,
                    color: group.color,
                },
            })
            .collect(),
        roles: roles
            .into_iter()
            .map(|role| Row {
                id: role.id.uuid(),
                name: role.name,
                provider: role.provider,
                live: RoleSpec {
                    description: role.description,
                    is_default: role.is_default,
                },
            })
            .collect(),
        targets,
        ssh_client_keys: keys
            .into_iter()
            .map(|mut key| {
                reveal_inline(&mut key.secret_key)?;
                Ok(Row {
                    id: key.id.uuid(),
                    name: key.label,
                    provider: key.provider,
                    live: SshClientKeySpec {
                        private_key: key.secret_key,
                        is_default: key.is_default,
                    },
                })
            })
            .collect::<Result<_, WarpgateError>>()?,
    })
}

/// Decrypts an inline credential, so that it compares with a file's literal
fn reveal_inline(slot: &mut MaybeSecretRef) -> Result<(), WarpgateError> {
    if let MaybeSecretRef::Inline(secret) = slot {
        *secret = StoredSecret::from(secret.reveal()?.expose_secret().clone());
    }
    Ok(())
}

/// What [`apply`] committed
#[derive(Debug)]
#[must_use]
pub struct Applied<'p> {
    /// Each written change with its row ID, in write order
    pub changes: Vec<(&'p Change, Uuid)>,
    /// Sessions that deleted targets had admitted, for the caller to close
    pub admitted: AdmittedSessions,
}

#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    #[error("the plan has collisions or blocked changes")]
    PlanHasErrors,
    #[error("the database changed since the plan was made; plan again")]
    Stale,
    #[error("{kind:?} {name}: {source}")]
    Resource {
        kind: ResourceKind,
        name: String,
        #[source]
        source: ResourceError,
    },
    #[error(transparent)]
    Other(#[from] WarpgateError),
}

impl From<DbErr> for ApplyError {
    fn from(err: DbErr) -> Self {
        Self::Other(err.into())
    }
}

/// Writes `confirmed` in one transaction, as `provider`. The plan is computed
/// again inside the transaction and must equal `confirmed`, so only what was
/// shown is written. A conflicting change made after that check fails on the
/// unique names or the ownership checks and rolls everything back.
/// If another apply of the same files already ran (a webhook delivered to two
/// nodes), nothing is left to write and the result is empty.
/// `secrets` resolves client key references, to derive their public keys.
pub async fn apply<'p, C: ConnectionTrait + TransactionTrait>(
    db: &C,
    provider: ProviderId,
    desired: &[Resource],
    confirmed: &'p Plan,
    secrets: &dyn SecretResolver,
) -> Result<Applied<'p>, ApplyError> {
    if confirmed.has_errors() {
        return Err(ApplyError::PlanHasErrors);
    }
    let txn = db.begin().await?;
    let current = load_current(&txn).await?;
    let fresh = plan(provider, desired, &current, confirmed.prune);
    if fresh != *confirmed {
        if !fresh.has_pending() && !fresh.has_errors() {
            return Ok(Applied {
                changes: vec![],
                admitted: AdmittedSessions(vec![]),
            });
        }
        return Err(ApplyError::Stale);
    }

    let actor = Actor::Provider(provider);
    let references = References::new(desired, &current);
    let mut ids = Ids {
        references: &references,
        written: HashMap::new(),
    };
    let mut written = Vec::new();
    let (targets, others): (Vec<&Change>, Vec<&Change>) = confirmed
        .changes
        .iter()
        .partition(|change| change.kind() == ResourceKind::Target);
    for change in others.into_iter().chain(jump_hosts_first(targets)) {
        let (id, adopt, desired) = match change {
            Change::Create(desired) => (None, false, desired),
            Change::Update { id, desired, .. } => (Some(*id), false, desired),
            Change::Adopt { id, desired, .. } => (Some(*id), true, desired),
            Change::Unchanged { .. }
            | Change::WouldPrune { .. }
            | Change::Delete { .. }
            | Change::Collision { .. }
            | Change::Blocked { .. }
            | Change::Guarded { .. } => continue,
        };
        let write = Write {
            db: &txn,
            actor,
            provider,
            id,
            adopt,
        };
        let result = match desired {
            Resource::TargetGroup(manifest) => write.group(manifest).await.map(RowId::uuid),
            Resource::Role(manifest) => write.role(manifest).await.map(RowId::uuid),
            // ponytail: resolves a reference while the transaction is open;
            // resolve before it if backend latency starts holding locks too long
            Resource::SshClientKey(manifest) => {
                write.client_key(manifest, secrets).await.map(RowId::uuid)
            }
            Resource::Target(manifest) => write.target(manifest, &ids).await.map(RowId::uuid),
        };
        let id = result.map_err(|source| ApplyError::Resource {
            kind: change.kind(),
            name: change.name().to_owned(),
            source,
        })?;
        ids.written
            .insert((change.kind(), change.name().to_owned()), id);
        written.push((change, id));
    }

    // Deletes run after the writes. By then a replacement client key exists
    // and updated targets no longer reference the deleted rows. Reverse plan
    // order deletes targets before the rows they reference.
    let mut admitted = Vec::new();
    for change in confirmed.changes.iter().rev() {
        let Change::Delete { kind, id, .. } = change else {
            continue;
        };
        let result = match kind {
            ResourceKind::Target => targets::delete(&txn, actor, TargetId(*id))
                .await
                .map(|sessions| admitted.extend(sessions.0)),
            ResourceKind::SshClientKey => {
                ssh_client_keys::delete(&txn, actor, SshClientKeyId(*id)).await
            }
            ResourceKind::Role => roles::delete(&txn, actor, RoleId(*id)).await,
            ResourceKind::TargetGroup => {
                target_groups::delete(&txn, actor, TargetGroupId(*id)).await
            }
        };
        result.map_err(|source| ApplyError::Resource {
            kind: *kind,
            name: change.name().to_owned(),
            source,
        })?;
        written.push((change, *id));
    }

    txn.commit().await?;
    Ok(Applied {
        changes: written,
        admitted: AdmittedSessions(admitted),
    })
}

/// One create, update or adoption. `id` is the row an update or adoption
/// targets, `None` for a create.
struct Write<'a, C> {
    db: &'a C,
    actor: Actor,
    provider: ProviderId,
    id: Option<Uuid>,
    adopt: bool,
}

/// The service layer's writes for one kind of resource, keyed by its spec
trait Store {
    type Entity: OwnedEntity;
    type Data;

    async fn create<C: ConnectionTrait>(
        db: &C,
        actor: Actor,
        data: Self::Data,
    ) -> Result<Id<Self>, ResourceError>;

    async fn update<C: ConnectionTrait>(
        db: &C,
        actor: Actor,
        id: Id<Self>,
        data: Self::Data,
    ) -> Result<(), ResourceError>;
}

/// The ID type of the rows that a spec is stored as
type Id<S> = <<S as Store>::Entity as OwnedEntity>::Id;

/// For a resource module whose `create` and `update` take just the request
macro_rules! store {
    ($spec:ty, $module:ident, $entity:ident, $data:ty) => {
        impl Store for $spec {
            type Entity = $entity::Entity;
            type Data = $data;

            async fn create<C: ConnectionTrait>(
                db: &C,
                actor: Actor,
                data: $data,
            ) -> Result<Id<Self>, ResourceError> {
                Ok($module::create(db, actor, &data).await?.id)
            }

            async fn update<C: ConnectionTrait>(
                db: &C,
                actor: Actor,
                id: Id<Self>,
                data: $data,
            ) -> Result<(), ResourceError> {
                $module::update(db, actor, id, &data).await?;
                Ok(())
            }
        }
    };
}

store!(
    TargetGroupSpec,
    target_groups,
    TargetGroup,
    TargetGroupDataRequest
);
store!(RoleSpec, roles, Role, RoleDataRequest);
store!(TargetSpec, targets, Target, TargetDataRequest);

impl Store for SshClientKeySpec {
    type Entity = SshClientKey::Entity;
    type Data = (SshClientKeyDataRequest, KeyMaterial);

    async fn create<C: ConnectionTrait>(
        db: &C,
        actor: Actor,
        (data, material): Self::Data,
    ) -> Result<Id<Self>, ResourceError> {
        Ok(ssh_client_keys::create(db, actor, &data, material)
            .await?
            .id)
    }

    async fn update<C: ConnectionTrait>(
        db: &C,
        actor: Actor,
        id: Id<Self>,
        (data, material): Self::Data,
    ) -> Result<(), ResourceError> {
        ssh_client_keys::update(db, actor, id, &data, Some(material)).await?;
        Ok(())
    }
}

impl<C: ConnectionTrait> Write<'_, C> {
    /// Creates the row, or updates it after taking it over for an adoption
    async fn save<S: Store>(&self, data: S::Data) -> Result<Id<S>, ResourceError> {
        let Some(id) = self.id.map(Id::<S>::from_uuid) else {
            return S::create(self.db, self.actor, data).await;
        };
        if self.adopt {
            set_owner::<S::Entity, _>(self.db, id, Some(self.provider)).await?;
        }
        S::update(self.db, self.actor, id, data).await?;
        Ok(id)
    }

    async fn group(
        &self,
        manifest: &Manifest<TargetGroupSpec>,
    ) -> Result<TargetGroupId, ResourceError> {
        let TargetGroupSpec { description, color } = &manifest.spec;
        let data = TargetGroupDataRequest {
            name: manifest.metadata.name.clone(),
            description: Some(description.clone()),
            color: color.clone(),
        };
        self.save::<TargetGroupSpec>(data).await
    }

    async fn role(&self, manifest: &Manifest<RoleSpec>) -> Result<RoleId, ResourceError> {
        let RoleSpec {
            description,
            is_default,
        } = &manifest.spec;
        let data = RoleDataRequest {
            name: manifest.metadata.name.clone(),
            description: Some(description.clone()),
            is_default: Some(*is_default),
        };
        self.save::<RoleSpec>(data).await
    }

    async fn client_key(
        &self,
        manifest: &Manifest<SshClientKeySpec>,
        secrets: &dyn SecretResolver,
    ) -> Result<SshClientKeyId, ResourceError> {
        let SshClientKeySpec {
            private_key,
            is_default,
        } = &manifest.spec;
        let material = KeyMaterial::resolve(private_key, secrets).await?;
        let data = SshClientKeyDataRequest {
            label: manifest.metadata.name.clone(),
            is_default: *is_default,
        };
        self.save::<SshClientKeySpec>((data, material)).await
    }

    async fn target(
        &self,
        manifest: &Manifest<TargetSpec>,
        ids: &Ids<'_>,
    ) -> Result<TargetId, ResourceError> {
        let spec = &manifest.spec;
        let OptionReferences {
            jump_host,
            client_key,
        } = &spec.references;
        let mut options = spec.options.clone();
        if let TargetOptions::Ssh(ssh) = &mut options {
            ssh.jump_host = jump_host
                .as_deref()
                .map(|name| ids.find::<TargetSpec>(name))
                .transpose()?;
            if let SSHTargetAuth::PublicKey(auth) = &mut ssh.auth {
                auth.key_id = client_key
                    .as_deref()
                    .map(|name| ids.find::<SshClientKeySpec>(name))
                    .transpose()?;
            }
        }
        let group_id = spec
            .group
            .as_deref()
            .map(|group| ids.find::<TargetGroupSpec>(group))
            .transpose()?;
        let data = spec.data_request(&manifest.metadata.name, options, group_id);
        let id = self.save::<TargetSpec>(data).await?;

        let wanted = spec
            .roles
            .iter()
            .map(|role| ids.find::<RoleSpec>(role))
            .collect::<Result<HashSet<_>, _>>()?;
        let assigned: HashSet<RoleId> = TargetRoleAssignment::Entity::find()
            .filter(TargetRoleAssignment::Column::TargetId.eq(id))
            .all(self.db)
            .await?
            .into_iter()
            .map(|assignment| assignment.role_id)
            .collect();
        for role in wanted.difference(&assigned) {
            targets::add_role(self.db, self.actor, id, *role).await?;
        }
        for role in assigned.difference(&wanted) {
            targets::remove_role(self.db, self.actor, id, *role).await?;
        }
        Ok(id)
    }
}

/// Puts each target after the one it uses as a jump host, so that a target
/// can refer to a jump host this same apply creates
fn jump_hosts_first(mut pending: Vec<&Change>) -> Vec<&Change> {
    let jump_host = |change: &Change| match change {
        Change::Create(Resource::Target(manifest))
        | Change::Update {
            desired: Resource::Target(manifest),
            ..
        }
        | Change::Adopt {
            desired: Resource::Target(manifest),
            ..
        } => manifest
            .spec
            .references
            .jump_host
            .as_ref()
            .map(|name| name.to_lowercase()),
        _ => None,
    };
    let mut ordered = Vec::new();
    while !pending.is_empty() {
        let waiting: HashSet<String> = pending.iter().map(|c| c.name().to_lowercase()).collect();
        let (ready, rest): (Vec<_>, Vec<_>) = pending
            .into_iter()
            .partition(|change| jump_host(change).is_none_or(|host| !waiting.contains(&host)));
        if ready.is_empty() {
            // A jump host loop. Validation rejects these; the writes fail on one.
            ordered.extend(rest);
            break;
        }
        ordered.extend(ready);
        pending = rest;
    }
    ordered
}

/// Resolves a target's references to row IDs. A resource that the files add
/// or rename has no row of its name in the plan, so its ID comes from
/// `written`.
struct Ids<'a> {
    references: &'a References,
    /// Rows written so far, by kind and name in the files
    written: HashMap<(ResourceKind, String), Uuid>,
}

impl Ids<'_> {
    fn find<S: Store>(&self, name: &str) -> Result<Id<S>, ResourceError> {
        let kind = S::Entity::KIND;
        self.references
            .resolve(kind, name)
            .and_then(|referent| {
                referent
                    .id
                    .or_else(|| self.written.get(&(kind, referent.name.to_owned())).copied())
            })
            .map(Id::<S>::from_uuid)
            .ok_or(ResourceError::NotFound)
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use warpgate_common::{ProviderId, Secret, SecretError, SecretRef, SshHostKeyKind};
    use warpgate_gitops::plan::{Change, Prune, plan};
    use warpgate_gitops::types::Resource;

    use super::*;
    use crate::resources::roles::RoleDataRequest;
    use crate::resources::tests::db;
    use crate::resources::{Actor, roles};

    const GITOPS: ProviderId = ProviderId::GITOPS;

    /// Every reference holds a fresh private key
    struct Keys;

    #[async_trait::async_trait]
    impl SecretResolver for Keys {
        async fn resolve(&self, _: &SecretRef) -> Result<Secret<String>, SecretError> {
            Ok(Secret::new(SshHostKeyKind::Ed25519.generate_pem().unwrap()))
        }
    }

    fn resources(yaml: &str) -> Vec<Resource> {
        let files = [(std::path::PathBuf::from("test.yaml"), yaml.to_owned())];
        warpgate_gitops::validate::check_files(&files)
            .unwrap()
            .resources
    }

    async fn plan_against<C: ConnectionTrait>(db: &C, desired: &[Resource]) -> Plan {
        plan(
            GITOPS,
            desired,
            &load_current(db).await.unwrap(),
            Prune::Off,
        )
    }

    fn summary(plan: &Plan) -> Vec<String> {
        plan.changes
            .iter()
            .map(|change| {
                let action = serde_json::to_value(change.action()).unwrap();
                format!("{} {}", action.as_str().unwrap(), change.name())
            })
            .collect()
    }

    #[tokio::test]
    async fn applying_every_field_then_planning_again_changes_nothing() {
        let db = db().await;
        let desired = resources(include_str!(
            "../../../warpgate-gitops/tests/fixtures/valid/every-field.yaml"
        ));
        let first = plan_against(&db, &desired).await;
        assert!(first.changes.iter().all(|c| matches!(c, Change::Create(_))));

        let _ = apply(&db, GITOPS, &desired, &first, &Keys).await.unwrap();

        let again = plan_against(&db, &desired).await;
        assert!(
            again
                .changes
                .iter()
                .all(|c| matches!(c, Change::Unchanged { .. })),
            "{:?}",
            summary(&again)
        );
        let target = Target::Entity::find().one(&db).await.unwrap().unwrap();
        assert_eq!(target.provider, Some(GITOPS));
    }

    #[tokio::test]
    async fn roles_and_fields_follow_the_file() {
        let db = db().await;
        let fileset = |port: u16, roles: &str| {
            resources(&format!(
                "apiVersion: warpgate/v1\nkind: Role\nmetadata: {{name: dba}}\nspec: {{}}\n---\n\
                 apiVersion: warpgate/v1\nkind: Role\nmetadata: {{name: ops}}\nspec: {{}}\n---\n\
                 apiVersion: warpgate/v1\nkind: Target\nmetadata: {{name: web}}\n\
                 spec: {{roles: [{roles}], options: {{ssh: {{host: h, port: {port}}}}}}}\n"
            ))
        };
        let before = fileset(22, "dba, ops");
        let _ = apply(
            &db,
            GITOPS,
            &before,
            &plan_against(&db, &before).await,
            &Keys,
        )
        .await
        .unwrap();
        assert_eq!(
            TargetRoleAssignment::Entity::find()
                .all(&db)
                .await
                .unwrap()
                .len(),
            2
        );

        let after = fileset(2222, "DBA");
        let plan = plan_against(&db, &after).await;
        assert_eq!(
            summary(&plan),
            ["unchanged dba", "unchanged ops", "update web"]
        );
        let _ = apply(&db, GITOPS, &after, &plan, &Keys).await.unwrap();

        let target = Target::Entity::find().one(&db).await.unwrap().unwrap();
        assert_eq!(target.options["ssh"]["port"], 2222);
        let assigned = TargetRoleAssignment::Entity::find().all(&db).await.unwrap();
        let dba = Role::Entity::find()
            .filter(<Role::Entity as EntityTrait>::Column::Name.eq("dba"))
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(assigned.len(), 1);
        assert_eq!(assigned[0].role_id, dba.id);
        assert!(
            plan_against(&db, &after)
                .await
                .changes
                .iter()
                .all(|c| matches!(c, Change::Unchanged { .. }))
        );
    }

    #[tokio::test]
    async fn adopts_hand_made_rows_only_when_asked() {
        let db = db().await;
        let legacy = roles::create(
            &db,
            Actor::Admin,
            &RoleDataRequest {
                name: "legacy".into(),
                description: Some("by hand".into()),
                is_default: None,
            },
        )
        .await
        .unwrap();
        let role = |adopt: &str| {
            resources(&format!(
                "apiVersion: warpgate/v1\nkind: Role\n\
                 metadata: {{name: legacy{adopt}}}\nspec: {{description: from git}}\n"
            ))
        };

        let plain = role("");
        let refused = plan_against(&db, &plain).await;
        assert_eq!(summary(&refused), ["collision legacy"]);
        assert!(matches!(
            apply(&db, GITOPS, &plain, &refused, &Keys).await,
            Err(ApplyError::PlanHasErrors)
        ));

        let asking = role(", adopt_existing: true");
        let adopting = plan_against(&db, &asking).await;
        assert_eq!(summary(&adopting), ["adopt legacy"]);
        let _ = apply(&db, GITOPS, &asking, &adopting, &Keys).await.unwrap();

        let legacy = Role::Entity::find_by_id(legacy.id)
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(legacy.provider, Some(GITOPS));
        assert_eq!(legacy.description, "from git");
    }

    #[tokio::test]
    async fn targets_can_grant_hand_made_roles_without_taking_them_over() {
        let db = db().await;
        let admins = roles::create(
            &db,
            Actor::Admin,
            &RoleDataRequest {
                name: "Admins".into(),
                description: None,
                is_default: None,
            },
        )
        .await
        .unwrap();
        let desired = resources(
            "apiVersion: warpgate/v1\nkind: Target\nmetadata: {name: web}\n\
             spec: {roles: [admins], options: {ssh: {host: h}}}\n",
        );
        let first = plan_against(&db, &desired).await;
        assert_eq!(summary(&first), ["create web"]);
        let _ = apply(&db, GITOPS, &desired, &first, &Keys).await.unwrap();

        let assigned = TargetRoleAssignment::Entity::find().all(&db).await.unwrap();
        assert_eq!(
            assigned.iter().map(|a| a.role_id).collect::<Vec<_>>(),
            [admins.id]
        );
        let role = Role::Entity::find_by_id(admins.id)
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(role.provider, None);
        assert_eq!(
            summary(&plan_against(&db, &desired).await),
            ["unchanged web"]
        );
    }

    #[tokio::test]
    async fn a_reference_binds_the_row_the_plan_showed() {
        let db = db().await;
        // Both can exist on a database with case-sensitive names
        for name in ["dba", "DBA"] {
            roles::create(
                &db,
                Actor::Admin,
                &RoleDataRequest {
                    name: name.into(),
                    description: None,
                    is_default: None,
                },
            )
            .await
            .unwrap();
        }
        let desired = resources(
            "apiVersion: warpgate/v1\nkind: Target\nmetadata: {name: web}\n\
             spec: {roles: [dba], options: {ssh: {host: h}}}\n",
        );
        let first = plan_against(&db, &desired).await;
        let _ = apply(&db, GITOPS, &desired, &first, &Keys).await.unwrap();

        assert_eq!(
            summary(&plan_against(&db, &desired).await),
            ["unchanged web"]
        );
    }

    #[tokio::test]
    async fn a_renamed_client_key_keeps_its_row_and_its_targets() {
        let db = db().await;
        let pem = SshHostKeyKind::Ed25519.generate_pem().unwrap();
        let fileset = |label: &str| {
            resources(&format!(
                "apiVersion: warpgate/v1\nkind: SshClientKey\nmetadata: {{name: {label}}}\n\
                 spec: {{private_key: {pem:?}}}\n---\n\
                 apiVersion: warpgate/v1\nkind: Target\nmetadata: {{name: web}}\n\
                 spec: {{options: {{ssh: {{host: h, auth: {{kind: publickey, key_id: {label}}}}}}}}}\n"
            ))
        };
        let before = fileset("deploy");
        let first = plan_against(&db, &before).await;
        let _ = apply(&db, GITOPS, &before, &first, &Keys).await.unwrap();
        let key = SshClientKey::Entity::find()
            .one(&db)
            .await
            .unwrap()
            .unwrap();

        let after = fileset("deploy-prod");
        let renaming = plan_against(&db, &after).await;
        assert_eq!(summary(&renaming), ["update deploy-prod", "update web"]);
        let _ = apply(&db, GITOPS, &after, &renaming, &Keys).await.unwrap();

        let keys = SshClientKey::Entity::find().all(&db).await.unwrap();
        assert_eq!(
            keys.iter()
                .map(|k| (k.id, k.label.as_str()))
                .collect::<Vec<_>>(),
            [(key.id, "deploy-prod")]
        );
        let target = Target::Entity::find().one(&db).await.unwrap().unwrap();
        assert_eq!(target.options["ssh"]["auth"]["key_id"], key.id.to_string());
        assert_eq!(
            summary(&plan_against(&db, &after).await),
            ["unchanged deploy-prod", "unchanged web"]
        );
    }

    #[tokio::test]
    async fn pruning_deletes_targets_before_what_they_refer_to() {
        let db = db().await;
        let everything = resources(
            "apiVersion: warpgate/v1\nkind: TargetGroup\nmetadata: {name: prod}\nspec: {}\n---\n\
             apiVersion: warpgate/v1\nkind: Role\nmetadata: {name: dba}\nspec: {}\n---\n\
             apiVersion: warpgate/v1\nkind: Role\nmetadata: {name: ops}\nspec: {}\n---\n\
             apiVersion: warpgate/v1\nkind: Target\nmetadata: {name: web}\n\
             spec: {group: prod, roles: [ops], options: {ssh: {host: h}}}\n",
        );
        let first = plan_against(&db, &everything).await;
        let _ = apply(&db, GITOPS, &everything, &first, &Keys)
            .await
            .unwrap();

        let dba_only =
            resources("apiVersion: warpgate/v1\nkind: Role\nmetadata: {name: dba}\nspec: {}\n");
        let current = load_current(&db).await.unwrap();
        assert!(plan(GITOPS, &dba_only, &current, Prune::On).has_errors());
        let forced = plan(GITOPS, &dba_only, &current, Prune::Force);
        assert_eq!(
            summary(&forced),
            ["delete prod", "unchanged dba", "delete ops", "delete web"]
        );
        let applied = apply(&db, GITOPS, &dba_only, &forced, &Keys).await.unwrap();
        assert!(applied.admitted.0.is_empty());

        let roles: Vec<_> = Role::Entity::find().all(&db).await.unwrap();
        assert_eq!(
            roles.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            ["dba"]
        );
        assert!(Target::Entity::find().all(&db).await.unwrap().is_empty());
        assert!(
            TargetGroup::Entity::find()
                .all(&db)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_stale_plan_is_refused_and_writes_nothing() {
        let db = db().await;
        let desired = resources(
            "apiVersion: warpgate/v1\nkind: Role\nmetadata: {name: dba}\nspec: {}\n---\n\
             apiVersion: warpgate/v1\nkind: Role\nmetadata: {name: ops}\nspec: {}\n",
        );
        let confirmed = plan_against(&db, &desired).await;

        // An admin creates one of the planned names by hand in the meantime
        roles::create(
            &db,
            Actor::Admin,
            &RoleDataRequest {
                name: "ops".into(),
                description: None,
                is_default: None,
            },
        )
        .await
        .unwrap();

        assert!(matches!(
            apply(&db, GITOPS, &desired, &confirmed, &Keys).await,
            Err(ApplyError::Stale)
        ));
        let roles = Role::Entity::find().all(&db).await.unwrap();
        assert_eq!(roles.len(), 1, "dba must not have been created");
        assert_eq!(roles[0].provider, None);
    }
}

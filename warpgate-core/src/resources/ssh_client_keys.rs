use russh::keys::{PrivateKey, decode_secret_key};
use sea_orm::prelude::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, ModelTrait, PaginatorTrait,
    QueryFilter, Set,
};
use uuid::Uuid;
use warpgate_common::{
    MaybeSecretRef, SecretRef, SecretResolver, SshClientKeyId, StoredSecret, WarpgateError,
    pkcs8_pem_string, public_key_line, public_key_of_pem,
};
use warpgate_db_entities::SshClientKey;
use warpgate_resources::ResourceKind;

use super::{Actor, OwnedEntity, ResourceError, check_name, name_taken};

impl OwnedEntity for SshClientKey::Entity {
    type Id = SshClientKeyId;
    const KIND: ResourceKind = ResourceKind::SshClientKey;
    const ID: Self::Column = SshClientKey::Column::Id;
    const PROVIDER: Self::Column = SshClientKey::Column::Provider;
}

pub struct SshClientKeyDataRequest {
    pub label: String,
    pub is_default: bool,
}

/// A private key as the `secret_key` column holds it, with the public key it
/// derives
pub struct KeyMaterial {
    secret_key: MaybeSecretRef,
    public_key: String,
}

impl KeyMaterial {
    /// Stores the key itself, encrypted
    pub fn inline(key: &PrivateKey) -> Result<Self, WarpgateError> {
        Ok(Self {
            secret_key: MaybeSecretRef::Inline(StoredSecret::encrypted(pkcs8_pem_string(key)?)?),
            public_key: public_key_line(key)?,
        })
    }

    /// Stores the reference. It is resolved once, to check that it holds a
    /// private key and to derive the public key for display and de-duplication.
    pub async fn reference(
        reference: &SecretRef,
        backend: &dyn SecretResolver,
    ) -> Result<Self, WarpgateError> {
        let value = backend.resolve(reference).await?;
        Ok(Self {
            secret_key: reference.clone().into(),
            public_key: public_key_of_pem(value.expose_secret())?,
        })
    }

    /// From a key as a resource file holds it: the key itself, or a reference
    pub async fn resolve(
        private_key: &MaybeSecretRef,
        backend: &dyn SecretResolver,
    ) -> Result<Self, WarpgateError> {
        match private_key {
            MaybeSecretRef::Reference(reference) => Self::reference(reference, backend).await,
            literal => {
                let pem = literal.resolve(backend).await?;
                Self::inline(&decode_secret_key(pem.expose_secret(), None)?)
            }
        }
    }

    async fn check_unique<C: ConnectionTrait>(
        &self,
        db: &C,
        except: Option<SshClientKeyId>,
    ) -> Result<(), ResourceError> {
        let mut query = SshClientKey::Entity::find()
            .filter(SshClientKey::Column::PublicKey.eq(&self.public_key));
        if let Some(id) = except {
            query = query.filter(SshClientKey::Column::Id.ne(id));
        }
        if query.one(db).await?.is_some() {
            return Err(ResourceError::KeyTaken);
        }
        Ok(())
    }

    fn set(self, model: &mut SshClientKey::ActiveModel) {
        model.secret_key = Set(self.secret_key);
        model.public_key = Set(self.public_key);
    }
}

pub async fn create<C: ConnectionTrait>(
    db: &C,
    actor: Actor,
    data: &SshClientKeyDataRequest,
    material: KeyMaterial,
) -> Result<SshClientKey::Model, ResourceError> {
    check_name(&data.label)?;
    material.check_unique(db, None).await?;
    let mut model = SshClientKey::ActiveModel {
        id: Set(SshClientKeyId(Uuid::new_v4())),
        label: Set(data.label.clone()),
        is_default: Set(data.is_default),
        provider: Set(actor.provider_id()),
        ..Default::default()
    };
    material.set(&mut model);
    model.insert(db).await.map_err(name_taken)
}

/// Replaces the key itself only when `material` is given
pub async fn update<C: ConnectionTrait>(
    db: &C,
    actor: Actor,
    id: SshClientKeyId,
    data: &SshClientKeyDataRequest,
    material: Option<KeyMaterial>,
) -> Result<SshClientKey::Model, ResourceError> {
    check_name(&data.label)?;
    let key = SshClientKey::Entity::find_by_id(id)
        .one(db)
        .await?
        .ok_or(ResourceError::NotFound)?;
    actor.may_write(key.provider)?;

    let mut model: SshClientKey::ActiveModel = key.into();
    model.label = Set(data.label.clone());
    model.is_default = Set(data.is_default);
    if let Some(material) = material {
        material.check_unique(db, Some(id)).await?;
        material.set(&mut model);
    }
    model.update(db).await.map_err(name_taken)
}

/// Targets that used the key fall back to the default keys
pub async fn delete<C: ConnectionTrait>(
    db: &C,
    actor: Actor,
    id: SshClientKeyId,
) -> Result<(), ResourceError> {
    let key = SshClientKey::Entity::find_by_id(id)
        .one(db)
        .await?
        .ok_or(ResourceError::NotFound)?;
    actor.may_write(key.provider)?;
    if SshClientKey::Entity::find().count(db).await? <= 1 {
        return Err(ResourceError::LastClientKey);
    }
    key.delete(db).await?;
    Ok(())
}

/// Stores the public key that a referenced key resolves to after a rotation
/// in its backend. The public key is derived data, so the row's owner is not
/// checked.
pub async fn refresh_public_key<C: ConnectionTrait>(
    db: &C,
    id: SshClientKeyId,
    public_key: String,
) -> Result<(), ResourceError> {
    SshClientKey::Entity::update_many()
        .col_expr(SshClientKey::Column::PublicKey, Expr::value(public_key))
        .filter(SshClientKey::Column::Id.eq(id))
        .exec(db)
        .await?;
    Ok(())
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use warpgate_common::{ProviderId, SshHostKeyKind};

    use super::*;
    use crate::resources::tests::db;

    fn new_key() -> PrivateKey {
        decode_secret_key(&SshHostKeyKind::Ed25519.generate_pem().unwrap(), None).unwrap()
    }

    fn data(label: &str) -> SshClientKeyDataRequest {
        SshClientKeyDataRequest {
            label: label.into(),
            is_default: false,
        }
    }

    #[tokio::test]
    async fn keys_are_unique_owned_and_never_all_deleted() {
        let db = db().await;
        let gitops = Actor::Provider(ProviderId::GITOPS);
        let key = new_key();
        let deploy = create(
            &db,
            gitops,
            &data("deploy"),
            KeyMaterial::inline(&key).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(deploy.provider, Some(ProviderId::GITOPS));

        let result = create(
            &db,
            Actor::Admin,
            &data("copy"),
            KeyMaterial::inline(&key).unwrap(),
        )
        .await;
        assert!(matches!(result, Err(ResourceError::KeyTaken)), "{result:?}");
        let result = create(
            &db,
            Actor::Admin,
            &data("deploy"),
            KeyMaterial::inline(&new_key()).unwrap(),
        )
        .await;
        assert!(
            matches!(result, Err(ResourceError::NameTaken)),
            "{result:?}"
        );

        let result = update(&db, Actor::Admin, deploy.id, &data("deploy"), None).await;
        assert!(
            matches!(result, Err(ResourceError::OwnedBy(_))),
            "{result:?}"
        );
        let result = delete(&db, Actor::Admin, deploy.id).await;
        assert!(
            matches!(result, Err(ResourceError::OwnedBy(_))),
            "{result:?}"
        );

        let rotated = update(
            &db,
            gitops,
            deploy.id,
            &data("deploy"),
            Some(KeyMaterial::inline(&new_key()).unwrap()),
        )
        .await
        .unwrap();
        assert_ne!(rotated.public_key, deploy.public_key);
        let result = delete(&db, gitops, deploy.id).await;
        assert!(
            matches!(result, Err(ResourceError::LastClientKey)),
            "{result:?}"
        );
    }
}

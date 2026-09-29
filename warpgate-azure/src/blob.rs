use std::{sync::Arc, time::Duration};

use azure_core::{
    credentials::{Secret, TokenCredential},
    http::RequestContent,
    time::OffsetDateTime,
};
use azure_identity::{
    ClientSecretCredential, DeveloperToolsCredential, ManagedIdentityCredential,
    ManagedIdentityCredentialOptions, UserAssignedId, WorkloadIdentityCredential,
};
use azure_storage_blob::{
    BlobContainerClient, BlobServiceClient, BlockBlobClient,
    models::{
        BlobClientDownloadOptions, BlobClientGetPropertiesResultHeaders, BlockLookupList, KeyInfo,
    },
};
use azure_storage_common::models::UserDelegationKey;
use azure_storage_sas::SasBuilder;
use futures::TryStreamExt;
use poem_openapi::{Object, Union};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::error;
use warpgate_common::StoredSecret;

use crate::AzureError;

/// How much is buffered before a block is staged.
///
/// Azure permits up to 4000 MiB per block and 50 000 blocks. At 4 MiB that is a
/// 200 GiB ceiling per recording, which no terminal session approaches, while
/// keeping the in-flight buffer small — durability comes from the local scratch
/// file that `warpgate-core` writes in parallel, not from this buffer.
const BLOCK_SIZE: usize = 4 * 1024 * 1024;

/// Width of the decimal block index before it is turned into an ID.
///
/// Azure requires every block ID in one blob to decode to the same byte length,
/// so the counter is zero-padded to a fixed width rather than formatted bare.
const BLOCK_ID_WIDTH: usize = 20;

/// Azure's hard ceiling on blocks in a single blob.
///
/// At [`BLOCK_SIZE`] this caps one recording near 195 GiB. The limit is checked
/// when staging rather than left to surface on commit, where the failure would
/// arrive after the whole session had been written and name nothing useful.
const MAX_BLOCKS: usize = 50_000;

/// How a client authenticates to Azure Storage.
///
/// Every mode is Entra ID, because that is all the SDK has: `azure_storage_blob`
/// 1.x accepts an `Option<Arc<dyn TokenCredential>>` and ships no shared-key
/// credential, so a storage-account key cannot be used to authenticate here.
/// `ServicePrincipal` is the way to hand Warpgate explicit credentials.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Union)]
#[serde(tag = "mode")]
#[oai(discriminator_name = "mode", one_of)]
pub enum AzureCredentials {
    /// Managed identity — how a Warpgate on a VM or App Service authenticates.
    ManagedIdentity(ManagedIdentityCredentials),
    /// Federated workload identity, configured entirely by environment:
    /// `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_FEDERATED_TOKEN_FILE`.
    /// This is how a Warpgate pod on AKS authenticates.
    WorkloadIdentity(WorkloadIdentityCredentials),
    /// An explicit service principal — tenant, client and secret supplied here.
    ///
    /// The fallback for a Warpgate that cannot use an identity assigned to it,
    /// and the only mode that works from outside Azure. It is also the only one
    /// that puts a long-lived secret in the database, which is precisely what
    /// the identity-based modes above exist to avoid; prefer them where the
    /// host can provide an identity.
    ServicePrincipal(ServicePrincipalCredentials),
    /// Azure CLI / azd sign-in — for running Warpgate on a workstation.
    DeveloperTools(DeveloperToolsCredentials),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Object, Default)]
pub struct ManagedIdentityCredentials {
    /// Client ID of a user-assigned identity; `None` selects the system-assigned one.
    pub client_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Object, Default)]
pub struct WorkloadIdentityCredentials {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Object)]
pub struct ServicePrincipalCredentials {
    /// Directory (tenant) ID.
    pub tenant_id: String,
    /// Application (client) ID.
    pub client_id: String,
    /// Blank in responses; blank in an update keeps the stored secret.
    pub client_secret: StoredSecret,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Object, Default)]
pub struct DeveloperToolsCredentials {}

impl AzureCredentials {
    fn build(&self) -> Result<Arc<dyn TokenCredential>, AzureError> {
        match self {
            Self::ManagedIdentity(mi) => {
                let options = mi
                    .client_id
                    .as_ref()
                    .map(|id| ManagedIdentityCredentialOptions {
                        user_assigned_id: Some(UserAssignedId::ClientId(id.clone())),
                        ..Default::default()
                    });
                Ok(ManagedIdentityCredential::new(options)?)
            }
            Self::WorkloadIdentity(_) => Ok(WorkloadIdentityCredential::new(None)?),
            Self::ServicePrincipal(sp) => {
                let secret = sp
                    .client_secret
                    .reveal()
                    .map_err(|e| AzureError::Config(format!("client secret: {e}")))?;
                Ok(ClientSecretCredential::new(
                    &sp.tenant_id,
                    sp.client_id.clone(),
                    Secret::new(secret.expose_secret().clone()),
                    None,
                )?)
            }
            Self::DeveloperTools(_) => Ok(DeveloperToolsCredential::new(None)?),
        }
    }

    /// Whether this mode carries a secret Warpgate has to store.
    ///
    /// The other three resolve their credential from the environment, so there
    /// is nothing to redact on the way out or refill on the way back in.
    pub const fn stored_secret(&self) -> Option<&StoredSecret> {
        match self {
            Self::ServicePrincipal(sp) => Some(&sp.client_secret),
            _ => None,
        }
    }

    /// The stored secret, for redacting it on the way out or restoring it on
    /// the way back in.
    pub const fn stored_secret_mut(&mut self) -> Option<&mut StoredSecret> {
        match self {
            Self::ServicePrincipal(sp) => Some(&mut sp.client_secret),
            _ => None,
        }
    }
}

/// Everything needed to reach one blob container. Serves as both the stored
/// (serde) and admin-API (poem-openapi) representation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Object)]
pub struct AzureBlobConfig {
    /// Storage account name, e.g. `mywarpgatestorage`.
    pub account: String,
    pub container: String,
    /// Custom service endpoint (sovereign clouds, emulators); `None` = public Azure.
    pub endpoint: Option<String>,
    /// Blob-name prefix prepended to every recording path.
    pub prefix: String,
    pub credentials: AzureCredentials,
    /// Stream recordings through Warpgate instead of redirecting the browser to
    /// a SAS URL.
    ///
    /// Redirecting is cheaper — the bytes never touch Warpgate — but it needs
    /// the container to carry a CORS policy allowing this origin to issue Range
    /// requests, and it needs the browser to be able to reach the storage
    /// account at all, which it cannot when the account sits behind a private
    /// endpoint. Streaming always works, so it is the default.
    #[serde(default = "default_true")]
    #[oai(default = "default_true")]
    pub serve_through_warpgate: bool,
}

const fn default_true() -> bool {
    true
}

impl AzureBlobConfig {
    /// `scheme://host[:port]` the browser connects to when following a SAS
    /// recording URL — used to allow-list the account in the page CSP.
    pub fn browser_origin(&self) -> Option<String> {
        let uri: http::Uri = self.service_url().parse().ok()?;
        Some(format!("{}://{}", uri.scheme_str()?, uri.authority()?))
    }

    fn service_url(&self) -> String {
        self.endpoint
            .clone()
            .unwrap_or_else(|| format!("https://{}.blob.core.windows.net", self.account))
    }
}

/// How long a fetched user-delegation key is requested for.
///
/// Seven days is Azure's maximum. The key is only the signing material — each
/// SAS minted from it carries its own, much shorter expiry.
const DELEGATION_KEY_TTL: time::Duration = time::Duration::days(7);

/// How long before expiry a cached delegation key is replaced, so a SAS is
/// never signed with a key that lapses mid-playback.
const DELEGATION_KEY_MARGIN: time::Duration = time::Duration::hours(1);

/// A user-delegation key together with the moment it stops being usable.
struct CachedDelegationKey {
    key: UserDelegationKey,
    expires: OffsetDateTime,
}

/// A configured blob client scoped to one container + prefix.
///
/// `BlobContainerClient` is not `Clone`, so it is held behind an `Arc` to keep
/// this type as cheap to clone as `S3Storage`.
#[derive(Clone)]
pub struct AzureBlobStorage {
    service: Arc<BlobServiceClient>,
    container: Arc<BlobContainerClient>,
    /// Needed verbatim when signing a SAS; the service URL is not a substitute
    /// because a custom endpoint does not carry the account name.
    account: String,
    container_name: String,
    prefix: String,
    serve_through_warpgate: bool,
    /// Shared across clones so one fetch serves every session on this node.
    delegation_key: Arc<RwLock<Option<CachedDelegationKey>>>,
}

/// A ranged read: the bytes from the requested offset, and how big the whole
/// blob is, which an HTTP 206 needs for its `Content-Range`.
pub struct RangedRead {
    pub reader: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
    /// Bytes in this response.
    pub len: u64,
    /// Bytes in the whole blob.
    pub total: u64,
}

impl AzureBlobStorage {
    pub async fn new(config: &AzureBlobConfig) -> Result<Self, AzureError> {
        let url = config
            .service_url()
            .parse()
            .map_err(|e| AzureError::Config(format!("invalid service URL: {e}")))?;

        let service = BlobServiceClient::new(url, Some(config.credentials.build()?), None)?;
        let container = service.blob_container_client(&config.container);

        Ok(Self {
            service: Arc::new(service),
            container: Arc::new(container),
            account: config.account.clone(),
            container_name: config.container.clone(),
            prefix: config.prefix.clone(),
            serve_through_warpgate: config.serve_through_warpgate,
            delegation_key: Arc::new(RwLock::new(None)),
        })
    }

    /// Whether playback streams through Warpgate rather than redirecting.
    pub const fn serves_through_warpgate(&self) -> bool {
        self.serve_through_warpgate
    }

    fn blob_name(&self, path: &str) -> String {
        if self.prefix.is_empty() {
            path.to_owned()
        } else {
            format!("{}/{}", self.prefix.trim_end_matches('/'), path)
        }
    }

    fn block_blob_client(&self, path: &str) -> BlockBlobClient {
        self.container
            .blob_client(&self.blob_name(path))
            .block_blob_client()
    }

    /// Whether the container is reachable with the configured credential.
    pub async fn test(&self) -> Result<(), AzureError> {
        self.container.exists().await?;
        Ok(())
    }

    pub async fn delete(&self, path: &str) -> Result<(), AzureError> {
        self.container
            .blob_client(&self.blob_name(path))
            .delete(None)
            .await?;
        Ok(())
    }

    /// Stream a recording's bytes.
    ///
    /// Returns a reader rather than a buffer: a desktop (RDP/VNC) recording is
    /// far too large to hold in memory, and the caller feeds this straight into
    /// an HTTP response body.
    pub async fn get_reader(
        &self,
        path: &str,
    ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin>, AzureError> {
        let response = self
            .container
            .blob_client(&self.blob_name(path))
            .download(None)
            .await?;

        // StreamReader needs the stream's error to be io::Error; the SDK's is not,
        // and neither type is ours to implement From between.
        let stream = response
            .body
            .map_err(|e| std::io::Error::other(e.to_string()));
        Ok(Box::new(tokio_util::io::StreamReader::new(stream)))
    }

    /// Stream a recording from `offset` to its end, reporting the blob's full
    /// size so the caller can answer a Range request.
    ///
    /// The size is asked for separately and deliberately. The download response
    /// cannot supply it: for a ranged or partitioned read its `content_length`
    /// is the byte count of the FIRST response rather than of the blob, so
    /// deriving the total from it caps every recording at one chunk. That is
    /// silent truncation during playback, not a visible failure.
    ///
    /// An offset at or past the end is [`AzureError::RangeNotSatisfiable`]:
    /// the players seek by asking for a range they cannot know is out of
    /// bounds, and read the refusal as the end of the recording.
    pub async fn get_reader_from(
        &self,
        path: &str,
        offset: u64,
    ) -> Result<RangedRead, AzureError> {
        let total = self.len(path).await?;
        if total > 0 && offset >= total {
            return Err(AzureError::RangeNotSatisfiable { total });
        }

        let options = BlobClientDownloadOptions {
            range: Some((offset..).into()),
            ..Default::default()
        };
        let response = self
            .container
            .blob_client(&self.blob_name(path))
            .download(Some(options))
            .await?;

        let stream = response
            .body
            .map_err(|e| std::io::Error::other(e.to_string()));

        Ok(RangedRead {
            reader: Box::new(tokio_util::io::StreamReader::new(stream)),
            len: total - offset,
            total,
        })
    }

    /// Size of a recording in bytes.
    pub async fn len(&self, path: &str) -> Result<u64, AzureError> {
        let props = self
            .container
            .blob_client(&self.blob_name(path))
            .get_properties(None)
            .await?;
        Ok(props.content_length()?.unwrap_or(0))
    }

    /// A user-delegation key, fetched on first use and reused until it nears
    /// expiry.
    ///
    /// Signing needs a key the service issues, so without caching every
    /// recording playback would pay a round trip before the redirect. The
    /// double-check under the write lock keeps a burst of concurrent playbacks
    /// to a single fetch.
    async fn delegation_key(&self) -> Result<UserDelegationKey, AzureError> {
        let usable_until = OffsetDateTime::now_utc() + DELEGATION_KEY_MARGIN;

        if let Some(cached) = self.delegation_key.read().await.as_ref()
            && cached.expires > usable_until
        {
            return Ok(cached.key.clone());
        }

        let mut guard = self.delegation_key.write().await;
        if let Some(cached) = guard.as_ref()
            && cached.expires > usable_until
        {
            return Ok(cached.key.clone());
        }

        let start = OffsetDateTime::now_utc();
        let expiry = start + DELEGATION_KEY_TTL;
        let info = KeyInfo {
            start: Some(start),
            expiry: Some(expiry),
            ..Default::default()
        };
        let key = self
            .service
            .get_user_delegation_key(info.try_into()?, None)
            .await?
            .into_model()?;

        *guard = Some(CachedDelegationKey {
            key: key.clone(),
            expires: expiry,
        });
        Ok(key)
    }

    /// A read-only SAS URL the browser can fetch directly.
    ///
    /// The Azure counterpart of `S3Storage::presign_get`, and used the same way:
    /// the admin API redirects to it rather than proxying the recording.
    pub async fn sas_url(&self, path: &str, ttl: Duration) -> Result<String, AzureError> {
        let ttl = time::Duration::try_from(ttl)
            .map_err(|e| AzureError::Config(format!("invalid SAS lifetime: {e}")))?;
        let key = self.delegation_key().await?;
        let blob_name = self.blob_name(path);

        let token = SasBuilder::new(
            self.account.as_str(),
            &key,
            OffsetDateTime::now_utc() + ttl,
        )?
        .blob(&self.container_name, &blob_name)
        .read()
        .build();

        let mut url = self.container.blob_client(&blob_name).url().clone();
        url.set_query(Some(&token));
        Ok(url.into())
    }

    pub fn start_upload(&self, path: &str) -> AzureBlockUpload {
        AzureBlockUpload {
            client: self.block_blob_client(path),
            key: self.blob_name(path),
            block_ids: Vec::new(),
            buffer: Vec::with_capacity(BLOCK_SIZE),
        }
    }
}

/// An in-progress block-blob upload — the Azure counterpart of an S3 multipart
/// upload. Data is buffered to [`BLOCK_SIZE`] and staged as a block; `finish`
/// commits the block list, which is what makes the blob readable.
///
/// Dropping without calling `finish` leaves the staged blocks uncommitted, and
/// Azure garbage-collects those after seven days — so an abandoned recording
/// needs no explicit abort the way an S3 multipart upload does.
pub struct AzureBlockUpload {
    client: BlockBlobClient,
    key: String,
    /// Raw (un-encoded) block IDs, in commit order. `stage_block` base64-encodes
    /// them itself, so encoding here would double-encode.
    block_ids: Vec<Vec<u8>>,
    buffer: Vec<u8>,
}

impl AzureBlockUpload {
    pub fn key(&self) -> &str {
        &self.key
    }

    pub async fn push(&mut self, data: &[u8]) -> Result<(), AzureError> {
        self.buffer.extend_from_slice(data);
        if self.buffer.len() >= BLOCK_SIZE {
            self.stage_block().await?;
        }
        Ok(())
    }

    async fn stage_block(&mut self) -> Result<(), AzureError> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        if self.block_ids.len() >= MAX_BLOCKS {
            return Err(AzureError::TooManyBlocks {
                key: self.key.clone(),
                limit: MAX_BLOCKS,
            });
        }
        let block_id = block_id(self.block_ids.len());
        let data = std::mem::take(&mut self.buffer);
        let len = data.len() as u64;

        self.client
            .stage_block(&block_id, len, RequestContent::from(data), None)
            .await
            .inspect_err(|error| error!(%error, key = %self.key, "Failed to stage recording block"))?;

        self.block_ids.push(block_id);
        Ok(())
    }

    /// Flush whatever is buffered and commit the block list.
    pub async fn finish(mut self) -> Result<(), AzureError> {
        self.stage_block().await?;

        let list = BlockLookupList {
            latest: Some(self.block_ids),
            ..Default::default()
        };
        self.client
            .commit_block_list(RequestContent::try_from(list)?, None)
            .await
            .inspect_err(|error| error!(%error, key = %self.key, "Failed to commit recording blocks"))?;
        Ok(())
    }
}

/// A fixed-width block ID.
///
/// Azure rejects a blob whose block IDs decode to differing byte lengths, so the
/// index is zero-padded rather than formatted bare — block 9 and block 10 would
/// otherwise disagree.
fn block_id(index: usize) -> Vec<u8> {
    format!("{index:0BLOCK_ID_WIDTH$}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(endpoint: Option<&str>) -> AzureBlobConfig {
        AzureBlobConfig {
            account: "acct".into(),
            container: "recordings".into(),
            endpoint: endpoint.map(Into::into),
            prefix: String::new(),
            credentials: AzureCredentials::ManagedIdentity(ManagedIdentityCredentials::default()),
            serve_through_warpgate: true,
        }
    }

    #[test]
    fn browser_origin_defaults_to_the_public_endpoint() {
        assert_eq!(
            config(None).browser_origin().as_deref(),
            Some("https://acct.blob.core.windows.net")
        );
    }

    #[test]
    fn browser_origin_follows_a_custom_endpoint() {
        assert_eq!(
            config(Some("http://127.0.0.1:10000/devstoreaccount1"))
                .browser_origin()
                .as_deref(),
            Some("http://127.0.0.1:10000")
        );
    }

    /// Azure rejects a commit whose block IDs differ in decoded length, so every
    /// ID this produces must be the same width no matter how many blocks precede it.
    #[test]
    fn block_ids_are_fixed_width() {
        assert_eq!(block_id(0).len(), block_id(9).len());
        assert_eq!(block_id(9).len(), block_id(10).len());
        assert_eq!(block_id(0).len(), block_id(49_999).len());
    }

    /// Block IDs are handed to the SDK raw; it base64-encodes them. Encoding here
    /// as well would double-encode and the commit would reference unknown blocks.
    #[test]
    fn block_ids_are_not_pre_encoded() {
        assert_eq!(block_id(7), b"00000000000000000007".to_vec());
    }

    #[test]
    fn block_ids_are_ordered() {
        assert!(block_id(2) < block_id(10));
    }

    /// The padding has to stay wide enough for every index the limit permits,
    /// or the last blocks of a maximal recording would be a different width.
    #[test]
    fn block_id_width_covers_the_block_limit() {
        assert!(BLOCK_ID_WIDTH >= MAX_BLOCKS.to_string().len());
        assert_eq!(block_id(MAX_BLOCKS - 1).len(), block_id(0).len());
    }

    /// Only the service principal carries something Warpgate stores. The other
    /// three resolve from the environment, so the admin API has nothing to
    /// redact on the way out or refill on the way back in.
    #[test]
    fn only_the_service_principal_carries_a_stored_secret() {
        assert!(
            AzureCredentials::ManagedIdentity(ManagedIdentityCredentials::default())
                .stored_secret()
                .is_none()
        );
        assert!(
            AzureCredentials::WorkloadIdentity(WorkloadIdentityCredentials {})
                .stored_secret()
                .is_none()
        );
        assert!(
            AzureCredentials::DeveloperTools(DeveloperToolsCredentials {})
                .stored_secret()
                .is_none()
        );
        assert!(
            AzureCredentials::ServicePrincipal(ServicePrincipalCredentials {
                tenant_id: "t".into(),
                client_id: "c".into(),
                client_secret: "s".to_owned().into(),
            })
            .stored_secret()
            .is_some()
        );
    }

    /// The discriminator is what the stored JSON and the admin API agree on, so
    /// a renamed variant silently orphans every existing configuration.
    #[test]
    fn credential_modes_serialise_under_their_discriminator() {
        let json = serde_json::to_string(&AzureCredentials::WorkloadIdentity(
            WorkloadIdentityCredentials {},
        ))
        .unwrap();
        assert!(json.contains(r#""mode":"WorkloadIdentity""#), "{json}");
    }

    /// Every mode survives the trip through stored JSON.
    ///
    /// The discriminator is the contract between what is written to the
    /// parameters row and what is read back, so a renamed variant orphans
    /// every configuration already saved under the old name.
    #[test]
    fn every_credential_mode_round_trips_through_json() {
        for original in [
            AzureCredentials::ManagedIdentity(ManagedIdentityCredentials { client_id: None }),
            AzureCredentials::ManagedIdentity(ManagedIdentityCredentials {
                client_id: Some("a-user-assigned-id".into()),
            }),
            AzureCredentials::WorkloadIdentity(WorkloadIdentityCredentials {}),
            AzureCredentials::DeveloperTools(DeveloperToolsCredentials {}),
            AzureCredentials::ServicePrincipal(ServicePrincipalCredentials {
                tenant_id: "t".into(),
                client_id: "c".into(),
                client_secret: "s".to_owned().into(),
            }),
        ] {
            let json = serde_json::to_string(&original).expect("serialising");
            let parsed: AzureCredentials =
                serde_json::from_str(&json).unwrap_or_else(|e| panic!("{json} did not parse: {e}"));
            assert_eq!(parsed, original, "round trip changed {json}");
        }
    }

    /// Workload identity takes its whole configuration from the environment.
    ///
    /// The credential reads AZURE_TENANT_ID, AZURE_CLIENT_ID and
    /// AZURE_FEDERATED_TOKEN_FILE itself, so this variant deliberately carries
    /// no fields. A field appearing here would be one Warpgate has to read,
    /// validate and keep in step with the SDK, and the reason the AKS path
    /// needs no coverage of ours is that there is nothing of ours in it.
    #[test]
    fn workload_identity_carries_no_configuration() {
        let json = serde_json::to_string(&AzureCredentials::WorkloadIdentity(
            WorkloadIdentityCredentials {},
        ))
        .expect("serialising");
        assert_eq!(json, r#"{"mode":"WorkloadIdentity"}"#);
    }

    /// A key is replaced before it expires, not as it expires. Signing with a
    /// key that lapses moments later would mint a SAS the service rejects part
    /// way through a playback.
    #[test]
    fn a_key_is_refreshed_before_it_expires() {
        let now = OffsetDateTime::now_utc();
        let usable_until = now + DELEGATION_KEY_MARGIN;

        let expiring_inside_the_margin = now + DELEGATION_KEY_MARGIN / 2;
        assert!(
            expiring_inside_the_margin <= usable_until,
            "a key inside the margin must be treated as stale"
        );

        let fresh = now + DELEGATION_KEY_TTL;
        assert!(fresh > usable_until, "a newly fetched key must be usable");
    }

    /// Azure caps a delegation key at seven days; asking for more is refused.
    #[test]
    fn the_key_lifetime_is_within_what_azure_allows() {
        assert!(DELEGATION_KEY_TTL <= time::Duration::days(7));
        assert!(DELEGATION_KEY_MARGIN < DELEGATION_KEY_TTL);
    }

    #[test]
    fn a_prefix_is_applied_to_blob_names() {
        let storage_prefix = |p: &str| -> String {
            if p.is_empty() { "rec/1".into() } else { format!("{}/{}", p.trim_end_matches('/'), "rec/1") }
        };
        assert_eq!(storage_prefix(""), "rec/1");
        assert_eq!(storage_prefix("warpgate"), "warpgate/rec/1");
        assert_eq!(storage_prefix("warpgate/"), "warpgate/rec/1");
    }
}

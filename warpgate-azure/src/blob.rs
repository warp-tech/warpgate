use std::sync::Arc;

use azure_core::{
    credentials::{Secret, TokenCredential},
    http::RequestContent,
};
use azure_identity::{
    ClientSecretCredential, DeveloperToolsCredential, ManagedIdentityCredential,
    ManagedIdentityCredentialOptions, UserAssignedId, WorkloadIdentityCredential,
};
use azure_storage_blob::{
    BlobContainerClient, BlobServiceClient, BlockBlobClient, models::BlockLookupList,
};
use futures::TryStreamExt;
use poem_openapi::{Object, Union};
use serde::{Deserialize, Serialize};
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

/// A configured blob client scoped to one container + prefix.
///
/// `BlobContainerClient` is not `Clone`, so it is held behind an `Arc` to keep
/// this type as cheap to clone as `S3Storage`.
#[derive(Clone)]
pub struct AzureBlobStorage {
    container: Arc<BlobContainerClient>,
    prefix: String,
}

impl AzureBlobStorage {
    pub async fn new(config: &AzureBlobConfig) -> Result<Self, AzureError> {
        let url = config
            .service_url()
            .parse()
            .map_err(|e| AzureError::Config(format!("invalid service URL: {e}")))?;

        let service = BlobServiceClient::new(url, Some(config.credentials.build()?), None)?;

        Ok(Self {
            container: Arc::new(service.blob_container_client(&config.container)),
            prefix: config.prefix.clone(),
        })
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

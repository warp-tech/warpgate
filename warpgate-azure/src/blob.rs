use std::sync::Arc;

use azure_core::{credentials::TokenCredential, http::RequestContent};
use futures::TryStreamExt;
use azure_identity::{DeveloperToolsCredential, ManagedIdentityCredential,
                     ManagedIdentityCredentialOptions, UserAssignedId};
use azure_storage_blob::{
    BlobContainerClient, BlobServiceClient, BlockBlobClient, models::BlockLookupList,
};
use poem_openapi::{Object, Union};
use serde::{Deserialize, Serialize};
use tracing::error;

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
/// Entra ID is the only mechanism on offer: `azure_storage_blob` 1.x accepts an
/// `Option<Arc<dyn TokenCredential>>` and ships no shared-key credential, so
/// account-key and connection-string auth cannot be expressed here at all.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Union)]
#[serde(tag = "mode")]
#[oai(discriminator_name = "mode", one_of)]
pub enum AzureCredentials {
    /// Managed identity — how a deployed Warpgate authenticates.
    ManagedIdentity(ManagedIdentityCredentials),
    /// Azure CLI / azd sign-in — for running Warpgate on a workstation.
    DeveloperTools(DeveloperToolsCredentials),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Object, Default)]
pub struct ManagedIdentityCredentials {
    /// Client ID of a user-assigned identity; `None` selects the system-assigned one.
    pub client_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Object, Default)]
pub struct DeveloperToolsCredentials {}

impl AzureCredentials {
    fn build(&self) -> Result<Arc<dyn TokenCredential>, AzureError> {
        match self {
            Self::ManagedIdentity(mi) => {
                let options = mi.client_id.as_ref().map(|id| ManagedIdentityCredentialOptions {
                    user_assigned_id: Some(UserAssignedId::ClientId(id.clone())),
                    ..Default::default()
                });
                Ok(ManagedIdentityCredential::new(options)?)
            }
            Self::DeveloperTools(_) => Ok(DeveloperToolsCredential::new(None)?),
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

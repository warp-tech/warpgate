use std::sync::Arc;

use azure_core::credentials::TokenCredential;
use azure_storage_blob::{BlobContainerClient, BlobServiceClient, BlockBlobClient};
use poem_openapi::{Object, Union};
use serde::{Deserialize, Serialize};

use crate::AzureError;

/// Buffer size before a block is staged: 4 MiB.
/// Azure allows up to 4000 MiB per block and 50k blocks; 4 MiB keeps memory
/// bounded while staying far under the block-count ceiling for long sessions.
const BLOCK_SIZE: usize = 4 * 1024 * 1024;

/// How a client authenticates to Azure Storage.
///
/// Only Entra ID (OAuth) is available: `azure_storage_blob` 1.x accepts an
/// `Option<Arc<dyn TokenCredential>>` and ships no shared-key credential, so
/// account-key and connection-string auth cannot be offered here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Union)]
#[serde(tag = "mode")]
#[oai(discriminator_name = "mode", one_of)]
pub enum AzureCredentials {
    /// Ambient Entra ID chain — managed identity, workload identity, az CLI.
    Auto(AutoCredentials),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Object, Default)]
pub struct AutoCredentials {}

/// Everything needed to reach one blob container. Serves as both the stored
/// (serde) and admin-API (poem-openapi) representation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Object)]
pub struct AzureBlobConfig {
    /// Storage account name, e.g. `mywarpgatestorage`.
    pub account: String,
    pub container: String,
    /// Custom service endpoint (Azurite, sovereign clouds); `None` = public Azure.
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
        self.endpoint.clone().unwrap_or_else(|| {
            format!("https://{}.blob.core.windows.net", self.account)
        })
    }
}

/// A configured blob client scoped to one container + prefix.
///
/// `BlobContainerClient` is not `Clone`, so it is held behind an `Arc` to keep
/// this type cheap to clone the way `S3Storage` is.
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

        // ponytail: the Entra chain is the only supported credential; wire the
        // concrete azure_identity type once the chain choice is settled
        // (ManagedIdentityCredential in-cluster vs DeveloperToolsCredential locally).
        let credential: Option<Arc<dyn TokenCredential>> = None;
        let _ = &config.credentials;

        let service = BlobServiceClient::new(url, credential, None)?;

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
        let _ = self.block_blob_client(path);
        todo!("delete — BlobClient::delete once the option types are pinned")
    }

    pub async fn get_bytes(&self, path: &str) -> Result<Vec<u8>, AzureError> {
        let _ = self.block_blob_client(path);
        todo!("get_bytes — BlobClient::download, drain the response body")
    }

    /// A read-only user-delegation SAS URL.
    ///
    /// Needs a user-delegation key from the service (`get_user_delegation_key`),
    /// which is itself an Entra-authenticated call. The key is valid for up to
    /// 7 days and should be cached rather than fetched per recording.
    pub async fn sas_url(&self, path: &str) -> Result<String, AzureError> {
        let _ = self.blob_name(path);
        todo!("sas_url — azure_storage_sas::SasBuilder + cached user-delegation key")
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
/// Azure garbage-collects them after seven days — so an abandoned recording
/// needs no explicit abort the way an S3 multipart upload does.
pub struct AzureBlockUpload {
    client: BlockBlobClient,
    key: String,
    block_ids: Vec<String>,
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
        let _ = (&self.client, std::mem::take(&mut self.buffer));
        todo!("stage_block — BlockBlobClient::stage_block(id, body); push id to block_ids")
    }

    pub async fn finish(mut self) -> Result<(), AzureError> {
        self.stage_block().await?;
        let _ = (&self.client, &self.block_ids);
        todo!("finish — BlockBlobClient::commit_block_list(block_ids)")
    }
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
            credentials: AzureCredentials::Auto(AutoCredentials {}),
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
}

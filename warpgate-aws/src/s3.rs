use std::time::Duration;

use aws_config::ConfigLoader;
use aws_credential_types::Credentials;
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use poem_openapi::{Object, Union};
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::AwsError;

/// Minimum S3 multipart part size (5 MiB); the last part may be smaller.
const PART_SIZE: usize = 5 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Union)]
#[serde(tag = "mode")]
#[oai(discriminator_name = "mode", one_of)]
pub enum S3Credentials {
    /// Ambient AWS credential chain (env vars, instance profile, IRSA, ...).
    Auto(AutoCredentials),
    Static(StaticCredentials),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Object, Default)]
pub struct AutoCredentials {}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Object)]
pub struct StaticCredentials {
    pub access_key_id: String,
    /// `None` on the admin API means "keep the stored secret" (it's never sent
    /// out); always `Some` in a stored config.
    pub secret_access_key: Option<String>,
}

impl S3Credentials {
    #[must_use]
    pub fn setup_config_loader(&self, loader: ConfigLoader) -> ConfigLoader {
        match self {
            S3Credentials::Auto(_) => loader,
            S3Credentials::Static(creds) => loader.credentials_provider(Credentials::new(
                creds.access_key_id.clone(),
                creds.secret_access_key.clone().unwrap_or_default(),
                None,
                None,
                "warpgate-static",
            )),
        }
    }
}

/// Everything needed to reach an S3 (or S3-compatible) bucket. Serves as both
/// the stored (serde) and admin-API (poem-openapi) representation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Object)]
pub struct S3StorageConfig {
    pub bucket: String,
    pub region: String,
    /// Custom endpoint for S3-compatible services (e.g. MinIO); `None` = AWS.
    pub endpoint: Option<String>,
    /// Path-style addressing (`host/bucket/key`), required by most
    /// S3-compatible services.
    pub path_style: bool,
    /// Key prefix prepended to every object path.
    pub prefix: String,
    pub credentials: S3Credentials,
}

impl S3StorageConfig {
    /// The `scheme://host[:port]` origin the browser connects to when following a
    /// presigned recording URL — used to allow-list the bucket in the page CSP.
    /// `None` when a custom endpoint has no parseable scheme/host.
    pub fn browser_origin(&self) -> Option<String> {
        if let Some(endpoint) = &self.endpoint {
            let uri: http::Uri = endpoint.parse().ok()?;
            Some(format!("{}://{}", uri.scheme_str()?, uri.authority()?))
        } else if self.path_style {
            Some(format!("https://s3.{}.amazonaws.com", self.region))
        } else {
            // AWS defaults to virtual-hosted-style addressing.
            Some(format!(
                "https://{}.s3.{}.amazonaws.com",
                self.bucket, self.region
            ))
        }
    }
}

/// A configured S3 client scoped to one bucket + key prefix.
#[derive(Clone)]
pub struct S3Storage {
    client: aws_sdk_s3::Client,
    bucket: String,
    prefix: String,
}

impl S3Storage {
    pub async fn new(config: &S3StorageConfig) -> Result<Self, AwsError> {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_s3::config::Region::new(config.region.clone()));
        loader = config.credentials.setup_config_loader(loader);

        let sdk_config = loader.load().await;

        let mut builder = aws_sdk_s3::config::Builder::from(&sdk_config);
        if let Some(endpoint) = &config.endpoint {
            builder = builder.endpoint_url(endpoint);
        }
        if config.path_style {
            builder = builder.force_path_style(true);
        }

        Ok(Self {
            client: aws_sdk_s3::Client::from_conf(builder.build()),
            bucket: config.bucket.clone(),
            prefix: config.prefix.clone(),
        })
    }

    fn prefix_no_trailing_slash(&self) -> &str {
        self.prefix.strip_suffix('/').unwrap_or(&self.prefix)
    }

    fn key(&self, path: &str) -> String {
        format!("{}/{}", self.prefix_no_trailing_slash(), path)
    }

    /// Open an object as a streaming reader (no full-object buffering).
    pub async fn get_reader(
        &self,
        path: &str,
    ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin>, AwsError> {
        let output = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.key(path))
            .send()
            .await
            .map_err(AwsError::sdk_error)?;
        Ok(Box::new(output.body.into_async_read()))
    }

    /// Presigned GET URL the browser can fetch directly (supports `Range`).
    pub async fn presign_get(&self, path: &str, ttl: Duration) -> Result<String, AwsError> {
        let presigned = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.key(path))
            .presigned(PresigningConfig::expires_in(ttl).map_err(AwsError::sdk_error)?)
            .await
            .map_err(AwsError::sdk_error)?;
        Ok(presigned.uri().to_string())
    }

    /// Connectivity probe for the admin "test connection" action: writes then
    /// deletes a small object, covering the exact put/delete permissions the
    /// recording pipeline relies on.
    pub async fn test(&self) -> Result<(), AwsError> {
        let path = ".warpgate-connection-test";
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(self.key(path))
            .body(ByteStream::from_static(b"warpgate"))
            .send()
            .await
            .map_err(AwsError::sdk_error)?;
        self.delete(path).await
    }

    /// Best-effort delete; S3 treats a missing key as success.
    pub async fn delete(&self, path: &str) -> Result<(), AwsError> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(self.key(path))
            .send()
            .await
            .map_err(AwsError::sdk_error)?;
        Ok(())
    }

    pub async fn start_multipart(&self, path: &str) -> Result<S3MultipartUpload, AwsError> {
        let key = self.key(path);
        let output = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .map_err(AwsError::sdk_error)?;
        let upload_id = output
            .upload_id()
            .ok_or_else(|| AwsError::Other("S3 did not return an upload id".into()))?
            .to_string();
        Ok(S3MultipartUpload {
            client: self.client.clone(),
            bucket: self.bucket.clone(),
            key,
            upload_id,
            buf: Vec::new(),
            part_number: 0,
            parts: Vec::new(),
        })
    }
}

/// A streaming multipart upload: bytes are buffered and flushed to S3 in
/// `PART_SIZE` chunks as they arrive, then finalized on [`Self::finish`].
pub struct S3MultipartUpload {
    client: aws_sdk_s3::Client,
    bucket: String,
    key: String,
    upload_id: String,
    buf: Vec<u8>,
    part_number: i32,
    parts: Vec<CompletedPart>,
}

impl S3MultipartUpload {
    pub fn key(&self) -> &str {
        &self.key
    }

    pub async fn push(&mut self, data: &[u8]) -> Result<(), AwsError> {
        self.buf.extend_from_slice(data);
        while self.buf.len() >= PART_SIZE {
            let chunk = self.buf.drain(..PART_SIZE).collect::<Vec<u8>>();
            self.upload_part(chunk).await?;
        }
        Ok(())
    }

    async fn upload_part(&mut self, chunk: Vec<u8>) -> Result<(), AwsError> {
        self.part_number += 1;
        let output = self
            .client
            .upload_part()
            .bucket(&self.bucket)
            .key(&self.key)
            .upload_id(&self.upload_id)
            .part_number(self.part_number)
            .body(ByteStream::from(chunk))
            .send()
            .await
            .map_err(AwsError::sdk_error)?;
        self.parts.push(
            CompletedPart::builder()
                .set_e_tag(output.e_tag().map(str::to_string))
                .part_number(self.part_number)
                .build(),
        );
        Ok(())
    }

    /// Flush the remaining buffer and complete the upload. A multipart upload
    /// needs at least one part, so an empty recording still uploads one. On
    /// failure the upload is aborted so S3 doesn't keep billing for the
    /// uncommitted parts.
    pub async fn finish(mut self) -> Result<(), AwsError> {
        match self.try_finish().await {
            Ok(()) => Ok(()),
            Err(error) => {
                if let Err(abort_error) = self.abort().await {
                    error!(%abort_error, key = %self.key, "Failed to abort S3 multipart upload");
                }
                Err(error)
            }
        }
    }

    async fn try_finish(&mut self) -> Result<(), AwsError> {
        if !self.buf.is_empty() || self.parts.is_empty() {
            let chunk = std::mem::take(&mut self.buf);
            self.upload_part(chunk).await?;
        }
        self.client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(&self.key)
            .upload_id(&self.upload_id)
            .multipart_upload(
                CompletedMultipartUpload::builder()
                    .set_parts(Some(std::mem::take(&mut self.parts)))
                    .build(),
            )
            .send()
            .await
            .map_err(AwsError::sdk_error)?;
        Ok(())
    }

    async fn abort(&self) -> Result<(), AwsError> {
        self.client
            .abort_multipart_upload()
            .bucket(&self.bucket)
            .key(&self.key)
            .upload_id(&self.upload_id)
            .send()
            .await
            .map_err(AwsError::sdk_error)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(endpoint: Option<&str>, path_style: bool) -> S3StorageConfig {
        S3StorageConfig {
            bucket: "recordings".into(),
            region: "eu-west-1".into(),
            endpoint: endpoint.map(str::to_string),
            path_style,
            prefix: String::new(),
            credentials: S3Credentials::Auto(AutoCredentials {}),
        }
    }

    #[test]
    fn browser_origin() {
        assert_eq!(
            config(None, false).browser_origin().as_deref(),
            Some("https://recordings.s3.eu-west-1.amazonaws.com"),
        );
        assert_eq!(
            config(None, true).browser_origin().as_deref(),
            Some("https://s3.eu-west-1.amazonaws.com"),
        );
        assert_eq!(
            config(Some("https://minio.example.com:9000"), true)
                .browser_origin()
                .as_deref(),
            Some("https://minio.example.com:9000"),
        );
        // No scheme is unusable for a CSP origin.
        assert_eq!(config(Some("minio:9000"), true).browser_origin(), None);
    }
}

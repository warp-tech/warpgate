use std::io::Read;

use anyhow::{Context, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use warpgate_common::TargetSessionId;
use warpgate_core::recordings::{
    NDJsonRecordingWriter, Recorder, RecordingWriterOpener, SessionRecordings, TerminalRecorder,
};
use warpgate_db_entities::Recording::RecordingKind;

/// One recorded Kubernetes API request/response as stored in a data NDJSON line
#[derive(Serialize, Deserialize, Debug)]
pub struct KubernetesRecordingItem {
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    pub request_method: String,
    pub request_path: String,
    pub request_headers: std::collections::HashMap<String, String>,
    #[serde(with = "warpgate_common::helpers::serde_base64")]
    pub request_body: Bytes,
    pub response_status: Option<u16>,
    pub response_body: Option<Vec<u8>>,
}

/// Recorder for Kubernetes API sessions
pub struct KubernetesRecorder {
    writer: NDJsonRecordingWriter,
}

impl KubernetesRecorder {
    pub async fn record_response(
        &self,
        method: &str,
        path: &str,
        headers: std::collections::HashMap<String, String>,
        request_body: &[u8],
        status: u16,
        response_body: &[u8],
    ) -> Result<(), warpgate_core::recordings::Error> {
        self.writer
            .write_json_line(&KubernetesRecordingItem {
                timestamp: OffsetDateTime::now_utc(),
                request_method: method.to_string(),
                request_path: path.to_string(),
                request_headers: headers,
                request_body: Bytes::from(request_body.to_vec()),
                response_status: Some(status),
                response_body: Some(response_body.to_vec()),
            })
            .await?;
        Ok(())
    }
}

impl Recorder for KubernetesRecorder {
    fn kind() -> RecordingKind {
        RecordingKind::Kubernetes
    }

    async fn new(opener: &RecordingWriterOpener) -> warpgate_core::recordings::Result<Self> {
        Ok(Self {
            writer: opener.open_ndjson_data().await?,
        })
    }
}

/// Decodes a gzip-encoded upstream response body for the recording. The proxy
/// forwards the body still encoded; only the recording stores it decoded.
///
/// An unencoded body is returned unchanged. A body in any encoding other than
/// `gzip`/`x-gzip`, one that decodes to more than `limit` bytes, or one that
/// fails to decode is recorded as empty: the recording doesn't store the
/// encoding, so encoded bytes would be unreadable there.
pub(crate) fn decode_response_body_for_recording(
    content_encoding: Option<&http::HeaderValue>,
    body: &Bytes,
    limit: usize,
) -> Bytes {
    let Some(encoding) = content_encoding.filter(|_| !body.is_empty()) else {
        return body.clone();
    };
    let encoding = encoding.to_str().unwrap_or_default().trim();
    if encoding.eq_ignore_ascii_case("identity") {
        return body.clone();
    }
    if !encoding.eq_ignore_ascii_case("gzip") && !encoding.eq_ignore_ascii_case("x-gzip") {
        tracing::debug!(
            encoding,
            "Unsupported response encoding, not recording the body"
        );
        return Bytes::new();
    }

    let max = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    let mut decoded = Vec::new();
    match flate2::read::MultiGzDecoder::new(body.as_ref())
        .take(max)
        .read_to_end(&mut decoded)
    {
        Ok(_) if decoded.len() <= limit => Bytes::from(decoded),
        Ok(_) => {
            tracing::debug!(
                limit,
                "Decoded response body is over the limit, not recording it"
            );
            Bytes::new()
        }
        Err(error) => {
            tracing::warn!(%error, "Failed to decode gzip response body, not recording it");
            Bytes::new()
        }
    }
}

// ----------

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum SessionRecordingMetadata {
    #[serde(rename = "kubernetes-api")]
    Api,
    #[serde(rename = "kubernetes-exec")]
    Exec {
        namespace: String,
        pod: String,
        /// Absent when the client named no container (kubectl omits it for
        /// single-container pods and lets the API server choose).
        container: Option<String>,
        /// Full argv. `kubectl exec pod -- ls -la` sends one `command=` query
        /// parameter per element, and every one of them belongs here.
        command: Vec<String>,
    },
    #[serde(rename = "kubernetes-attach")]
    Attach {
        namespace: String,
        pod: String,
        container: Option<String>,
    },
}

pub async fn start_recording_api(
    target_session_id: &TargetSessionId,
    recordings: &SessionRecordings,
) -> anyhow::Result<Option<KubernetesRecorder>> {
    // No name: `start` reuses the writer for a repeated name, so concurrent
    // requests, possibly on different nodes, would write to the same folder.
    recordings
        .start::<KubernetesRecorder, _>(target_session_id, None, SessionRecordingMetadata::Api)
        .await
        .context("starting recording")
}

pub async fn start_recording_exec(
    target_session_id: &TargetSessionId,
    recordings: &SessionRecordings,
    metadata: SessionRecordingMetadata,
) -> anyhow::Result<Option<TerminalRecorder>> {
    recordings
        .start::<TerminalRecorder, _>(target_session_id, None, metadata)
        .await
        .context("starting recording")
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::Write;

    use bytes::Bytes;

    use super::decode_response_body_for_recording as decode;

    pub(crate) fn gzip_member(data: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn header(value: &'static str) -> http::HeaderValue {
        http::HeaderValue::from_static(value)
    }

    #[test]
    fn concatenated_members_decode_whole() {
        let body = Bytes::from(
            [
                gzip_member(b"one\n"),
                gzip_member(b"two\n"),
                gzip_member(b"three\n"),
            ]
            .concat(),
        );
        let out = decode(Some(&header("gzip")), &body, 1024);
        assert_eq!(out.as_ref(), b"one\ntwo\nthree\n");
    }

    #[test]
    fn unencoded_body_is_unchanged() {
        let body = Bytes::from_static(b"hello");
        assert_eq!(decode(None, &body, 1024), body);
        assert_eq!(decode(Some(&header("identity")), &body, 1024), body);
    }

    #[test]
    fn unsupported_encodings_are_recorded_empty() {
        let body = Bytes::from(gzip_member(b"hello"));
        assert!(decode(Some(&header("br")), &body, 1024).is_empty());
        assert!(decode(Some(&header("gzip, br")), &body, 1024).is_empty());
    }

    #[test]
    fn gzip_name_is_case_insensitive_and_x_gzip_is_accepted() {
        let body = Bytes::from(gzip_member(b"hello"));
        assert_eq!(
            decode(Some(&header("GZIP")), &body, 1024).as_ref(),
            b"hello"
        );
        assert_eq!(
            decode(Some(&header("x-gzip")), &body, 1024).as_ref(),
            b"hello"
        );
    }

    #[test]
    fn empty_body_stays_empty() {
        assert!(decode(Some(&header("gzip")), &Bytes::new(), 1024).is_empty());
    }

    #[test]
    fn decoded_size_is_limited() {
        let body = Bytes::from(gzip_member(&[b'x'; 11]));
        assert!(decode(Some(&header("gzip")), &body, 10).is_empty());
        let body = Bytes::from(gzip_member(&[b'x'; 10]));
        assert_eq!(decode(Some(&header("gzip")), &body, 10).len(), 10);
    }

    #[test]
    fn corrupt_gzip_is_recorded_empty() {
        let body = Bytes::from_static(b"definitely not gzip");
        assert!(decode(Some(&header("gzip")), &body, 1024).is_empty());
    }
}

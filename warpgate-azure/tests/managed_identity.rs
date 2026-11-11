//! Exercises the blob backend with a managed identity.
//!
//! This is the credential a deployed Warpgate uses, and the one that cannot be
//! tested anywhere else: it resolves through IMDS, which only answers inside
//! Azure. They are `#[ignore]`d so an ordinary `cargo test` reports them as
//! ignored rather than passed; run them on an Azure VM with an assigned
//! identity using `cargo test --test managed_identity -- --ignored`.
//!
//! Required:
//!     WARPGATE_AZURE_MI_ACCOUNT     storage account name
//!     WARPGATE_AZURE_MI_CONTAINER   container name (must already exist)
//! Optional:
//!     WARPGATE_AZURE_MI_CLIENT_ID   client id of a USER-assigned identity;
//!                                   unset selects the system-assigned one
//!
//! `tests/azure-managed-identity-e2e.sh` provisions a VM, assigns it an
//! identity, runs these on it, and removes everything afterwards.

use std::time::Duration;

use tokio::io::AsyncReadExt;
use warpgate_azure::{
    AzureBlobConfig, AzureBlobStorage, AzureCredentials, AzureError, ManagedIdentityCredentials,
};

/// Larger than the crate's 4 MiB block so the upload has to stage more than one.
const PAYLOAD_BYTES: usize = 5 * 1024 * 1024;

fn config() -> AzureBlobConfig {
    let account = std::env::var("WARPGATE_AZURE_MI_ACCOUNT").expect("WARPGATE_AZURE_MI_ACCOUNT");
    let container =
        std::env::var("WARPGATE_AZURE_MI_CONTAINER").expect("WARPGATE_AZURE_MI_CONTAINER");
    AzureBlobConfig {
        account,
        container,
        endpoint: None,
        prefix: "managed-identity-test".to_owned(),
        serve_through_warpgate: true,
        credentials: AzureCredentials::ManagedIdentity(ManagedIdentityCredentials {
            client_id: std::env::var("WARPGATE_AZURE_MI_CLIENT_ID").ok(),
        }),
    }
}

/// A payload whose every 16-byte row states its own offset, so a reassembly
/// that drops or reorders a block is visible in the bytes rather than only in
/// the length.
fn payload() -> Vec<u8> {
    let mut out = Vec::with_capacity(PAYLOAD_BYTES + 32);
    let mut offset = 0usize;
    while out.len() < PAYLOAD_BYTES {
        out.extend_from_slice(format!("{offset:015}\n").as_bytes());
        offset = out.len();
    }
    out
}

async fn read_all(mut reader: Box<dyn tokio::io::AsyncRead + Send + Unpin>) -> Vec<u8> {
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .await
        .expect("reading the recording back");
    buf
}

#[tokio::test]
#[ignore = "needs IMDS: run on an Azure VM with --ignored"]
async fn a_managed_identity_can_store_serve_and_delete_a_recording() {
    let storage = AzureBlobStorage::new(&config())
        .await
        .expect("building a client from a managed identity");

    // Reaching the container at all is what proves IMDS answered and the
    // identity carries data-plane access, not merely that a token was minted.
    storage
        .test()
        .await
        .expect("the container should be reachable with the assigned identity");

    let path = format!("round-trip-{}.bin", std::process::id());
    let expected = payload();

    // Push in pieces so the buffer crosses the block threshold mid-stream,
    // which is how a real recording arrives.
    let mut upload = storage.start_upload(&path);
    for chunk in expected.chunks(64 * 1024) {
        upload.push(chunk).await.expect("staging a chunk");
    }
    upload.finish().await.expect("committing the block list");

    let actual = read_all(storage.get_reader(&path).await.expect("opening for read")).await;
    assert_eq!(
        actual.len(),
        expected.len(),
        "read back {} bytes of a {} byte recording",
        actual.len(),
        expected.len()
    );
    assert_eq!(actual, expected, "the recording came back altered");

    // Straddle the block boundary: the bytes either side were staged separately.
    let offset = (4 * 1024 * 1024) - 128;
    let ranged = storage
        .get_reader_from(&path, offset as u64)
        .await
        .expect("reading from an offset");
    assert_eq!(
        ranged.total,
        expected.len() as u64,
        "the reported total must be the blob's size, not one block's"
    );
    assert_eq!(ranged.len, (expected.len() - offset) as u64);
    assert_eq!(read_all(ranged.reader).await, expected[offset..]);

    // The players seek past the end to discover it; that has to be a refusal
    // carrying the size, not a transport error.
    match storage.get_reader_from(&path, expected.len() as u64).await {
        Err(AzureError::RangeNotSatisfiable { total }) => {
            assert_eq!(total, expected.len() as u64);
        }
        Ok(_) => panic!("a range starting at the end should not be satisfiable"),
        Err(e) => panic!("expected RangeNotSatisfiable, got {e}"),
    }

    storage.delete(&path).await.expect("deleting the recording");
    assert!(
        storage.get_reader_from(&path, 0).await.is_err(),
        "the recording is still readable after delete"
    );
}

#[tokio::test]
#[ignore = "needs IMDS: run on an Azure VM with --ignored"]
async fn a_managed_identity_can_mint_a_usable_sas_url() {
    let storage = AzureBlobStorage::new(&config())
        .await
        .expect("building a client");
    let path = format!("sas-{}.bin", std::process::id());
    let body = b"managed identity sas round trip".to_vec();

    let mut upload = storage.start_upload(&path);
    upload.push(&body).await.expect("staging");
    upload.finish().await.expect("committing");

    // A user-delegation SAS is signed with a key the service issues to the
    // caller's identity, so this exercises a second, distinct IMDS-backed path.
    let url = storage
        .sas_url(&path, Duration::from_secs(600))
        .await
        .expect("minting a SAS URL");

    // Fetched without any credential: only the signature in the URL authorises
    // it, which is the whole point of handing it to a browser.
    let fetched = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("fetching the SAS URL");
    assert!(
        fetched.status().is_success(),
        "the storage account rejected the SAS: HTTP {}",
        fetched.status()
    );
    assert_eq!(fetched.bytes().await.expect("reading the body"), body);

    storage.delete(&path).await.expect("deleting the recording");
}

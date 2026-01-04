//! OpenStack VM spawner mode for RemoteRun targets.
//!
//! Provisions ephemeral VMs via OpenStack API:
//! 1. Fetches SSH public keys from GitHub
//! 2. Creates a KeyPair in OpenStack
//! 3. Provisions a VM instance
//! 4. Waits for IP allocation
//! 5. Connects user via SSH

use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::time::{sleep, timeout};
use tracing::{debug, info};
use warpgate_common::RemoteRunOpenStackOptions;
use warpgate_core::Services;

/// Get the OpenStack auth token from environment variable.
fn get_auth_token() -> Result<String> {
    std::env::var("OPENSTACK_TOKEN")
        .context("OPENSTACK_TOKEN environment variable not set")
}

/// Create a secure HTTP client with TLS verification enabled.
/// This ensures all connections use TLS and certificate verification.
fn create_secure_client() -> Result<Client> {
    Client::builder()
        .https_only(true)  // Enforce HTTPS for all requests
        .build()
        .context("Failed to create secure HTTP client")
}

/// Validate that a URL uses HTTPS scheme.
fn validate_https_url(url: &str, context: &str) -> Result<()> {
    if !url.starts_with("https://") {
        anyhow::bail!(
            "{} must use HTTPS for secure communication. Got: {}",
            context,
            url
        );
    }
    Ok(())
}

/// Fetch SSH public keys from GitHub for a user.
/// Note: SSH public keys are inherently non-sensitive as they are designed
/// to be shared publicly. This function fetches them over HTTPS from GitHub.
async fn fetch_github_keys(client: &Client, username: &str) -> Result<String> {
    let url = format!("https://github.com/{}.keys", username);
    
    let response = client
        .get(&url)
        .send()
        .await
        .context("Failed to fetch GitHub public keys")?;

    if !response.status().is_success() {
        anyhow::bail!(
            "Failed to fetch GitHub public keys for {}: {}",
            username,
            response.status()
        );
    }

    let keys = response.text().await?;
    if keys.trim().is_empty() {
        anyhow::bail!("No SSH public keys found for GitHub user {}", username);
    }

    debug!(username = %username, key_count = keys.lines().count(), "Fetched GitHub SSH public keys");
    Ok(keys)
}

#[derive(Debug, Serialize)]
struct CreateKeypairRequest {
    keypair: KeypairData,
}

#[derive(Debug, Serialize)]
struct KeypairData {
    name: String,
    public_key: String,
}

#[derive(Debug, Deserialize)]
struct CreateKeypairResponse {
    keypair: KeypairResponseData,
}

#[derive(Debug, Deserialize)]
struct KeypairResponseData {
    name: String,
}

/// Create a keypair in OpenStack.
async fn create_keypair(
    client: &Client,
    api_url: &str,
    token: &str,
    name: &str,
    public_key: &str,
) -> Result<String> {
    let url = format!("{}/os-keypairs", api_url.trim_end_matches('/'));

    let request = CreateKeypairRequest {
        keypair: KeypairData {
            name: name.to_owned(),
            public_key: public_key.to_owned(),
        },
    };

    let response = client
        .post(&url)
        .header("X-Auth-Token", token)
        .json(&request)
        .send()
        .await
        .context("Failed to create keypair")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Failed to create keypair: {} - {}", status, body);
    }

    let resp: CreateKeypairResponse = response.json().await?;
    info!(keypair_name = %resp.keypair.name, "Created OpenStack keypair");
    Ok(resp.keypair.name)
}

#[derive(Debug, Serialize)]
struct CreateServerRequest {
    server: ServerData,
}

#[derive(Debug, Serialize)]
struct ServerData {
    name: String,
    #[serde(rename = "flavorRef")]
    flavor_ref: String,
    #[serde(rename = "imageRef")]
    image_ref: String,
    key_name: String,
    networks: Vec<NetworkRef>,
}

#[derive(Debug, Serialize)]
struct NetworkRef {
    uuid: String,
}

#[derive(Debug, Deserialize)]
struct CreateServerResponse {
    server: ServerResponseData,
}

#[derive(Debug, Deserialize)]
struct ServerResponseData {
    id: String,
}

#[derive(Debug, Deserialize)]
struct ServerDetailResponse {
    server: ServerDetail,
}

#[derive(Debug, Deserialize)]
struct ServerDetail {
    id: String,
    status: String,
    addresses: serde_json::Value,
}

/// Create a VM instance in OpenStack.
async fn create_server(
    client: &Client,
    api_url: &str,
    token: &str,
    opts: &RemoteRunOpenStackOptions,
    keypair_name: &str,
    instance_name: &str,
) -> Result<String> {
    let url = format!("{}/servers", api_url.trim_end_matches('/'));

    let request = CreateServerRequest {
        server: ServerData {
            name: instance_name.to_owned(),
            flavor_ref: opts.flavor_id.clone(),
            image_ref: opts.image_id.clone(),
            key_name: keypair_name.to_owned(),
            networks: vec![NetworkRef {
                uuid: opts.network_id.clone(),
            }],
        },
    };

    let response = client
        .post(&url)
        .header("X-Auth-Token", token)
        .json(&request)
        .send()
        .await
        .context("Failed to create server")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Failed to create server: {} - {}", status, body);
    }

    let resp: CreateServerResponse = response.json().await?;
    info!(server_id = %resp.server.id, "Created OpenStack server");
    Ok(resp.server.id)
}

/// Wait for the server to become ACTIVE and get its IP address.
async fn wait_for_server_active(
    client: &Client,
    api_url: &str,
    token: &str,
    server_id: &str,
    timeout_secs: u32,
) -> Result<String> {
    let url = format!("{}/servers/{}", api_url.trim_end_matches('/'), server_id);
    let timeout_duration = Duration::from_secs(timeout_secs as u64);

    timeout(timeout_duration, async {
        loop {
            let response = client
                .get(&url)
                .header("X-Auth-Token", token)
                .send()
                .await?;

            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                anyhow::bail!("Failed to get server status: {} - {}", status, body);
            }

            let resp: ServerDetailResponse = response.json().await?;
            debug!(status = %resp.server.status, "Server status");

            match resp.server.status.as_str() {
                "ACTIVE" => {
                    // Extract first IP address from addresses
                    if let Some(networks) = resp.server.addresses.as_object() {
                        for (_net_name, addrs) in networks {
                            if let Some(arr) = addrs.as_array() {
                                for addr in arr {
                                    if let Some(ip) = addr.get("addr").and_then(|a| a.as_str()) {
                                        info!(server_id = %server_id, ip = %ip, "Server is ACTIVE");
                                        return Ok(ip.to_owned());
                                    }
                                }
                            }
                        }
                    }
                    anyhow::bail!("Server is ACTIVE but no IP address found");
                }
                "ERROR" | "DELETED" => {
                    anyhow::bail!("Server entered {} state", resp.server.status);
                }
                _ => {
                    // Still building, wait and retry
                    sleep(Duration::from_secs(5)).await;
                }
            }
        }
    })
    .await
    .context("Timeout waiting for server to become ACTIVE")?
}

/// Execute an OpenStack VM spawner session.
pub async fn execute(_services: &Services, opts: &RemoteRunOpenStackOptions) -> Result<()> {
    // Validate that OpenStack API URL uses HTTPS
    validate_https_url(&opts.api_url, "OpenStack API URL")?;
    
    let token = get_auth_token()?;
    let client = create_secure_client()?;

    info!(api_url = %opts.api_url, github_user = %opts.github_username, "Starting OpenStack VM provisioning");

    // 1. Fetch GitHub SSH public keys (public keys are non-sensitive by design)
    let public_keys = fetch_github_keys(&client, &opts.github_username).await?;

    // Use first key for the keypair
    let first_key = public_keys
        .lines()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No SSH keys found"))?;

    // 2. Create keypair with unique name
    let keypair_name = format!("warpgate-{}", uuid::Uuid::new_v4());
    create_keypair(&client, &opts.api_url, &token, &keypair_name, first_key).await?;

    // 3. Create VM instance
    let instance_name = format!("warpgate-ephemeral-{}", uuid::Uuid::new_v4());
    let server_id = create_server(
        &client,
        &opts.api_url,
        &token,
        opts,
        &keypair_name,
        &instance_name,
    )
    .await?;

    // 4. Wait for VM to become ACTIVE and get IP
    let ip = wait_for_server_active(
        &client,
        &opts.api_url,
        &token,
        &server_id,
        opts.timeout_seconds,
    )
    .await?;

    info!(ip = %ip, server_id = %server_id, "OpenStack VM is ready for SSH connection");

    // Note: The actual SSH connection would be handled by the SSH protocol layer
    // This function prepares the VM; the caller will establish the SSH session

    Ok(())
}

/// Test OpenStack API connectivity.
pub async fn test_connection(opts: &RemoteRunOpenStackOptions) -> Result<()> {
    // Validate that OpenStack API URL uses HTTPS
    validate_https_url(&opts.api_url, "OpenStack API URL")?;
    
    let token = get_auth_token()?;
    let client = create_secure_client()?;

    // Test API endpoint by listing flavors
    let url = format!("{}/flavors", opts.api_url.trim_end_matches('/'));
    let response = client
        .get(&url)
        .header("X-Auth-Token", &token)
        .send()
        .await
        .context("Failed to connect to OpenStack API")?;

    if !response.status().is_success() {
        let status = response.status();
        anyhow::bail!("OpenStack API returned error: {}", status);
    }

    // Test GitHub public keys fetch (public keys are non-sensitive by design)
    fetch_github_keys(&client, &opts.github_username).await?;

    info!(api_url = %opts.api_url, "OpenStack connection test passed");
    Ok(())
}

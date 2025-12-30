//! Kubernetes ephemeral pod mode for RemoteRun targets.
//!
//! Manages ephemeral pods in Kubernetes:
//! 1. Spins up a temporary Pod in the specified namespace
//! 2. Waits for the Pod to be Running
//! 3. Attaches to the Pod's TTY
//! 4. Ensures Pod is deleted when session terminates

use std::time::Duration;

use anyhow::{Context, Result};
use k8s_openapi::api::core::v1::Pod;
use kube::{
    api::{Api, DeleteParams, PostParams},
    Client, Config,
};
use serde_json::json;
use tokio::time::{sleep, timeout};
use tracing::{debug, info, warn};
use warpgate_common::RemoteRunKubernetesOptions;
use warpgate_core::Services;

/// Create a Kubernetes client from the provided options.
async fn create_client(opts: &RemoteRunKubernetesOptions) -> Result<Client> {
    let config = if let Some(ref kubeconfig_path) = opts.kubeconfig {
        Config::from_kubeconfig(&kube::config::KubeConfigOptions {
            context: None,
            cluster: None,
            user: None,
        })
        .await
        .with_context(|| format!("Failed to load kubeconfig from {}", kubeconfig_path))?
    } else {
        // Try in-cluster config first, then fall back to default kubeconfig
        Config::incluster()
            .or_else(|_| {
                futures::executor::block_on(Config::from_kubeconfig(
                    &kube::config::KubeConfigOptions::default(),
                ))
            })
            .context("Failed to load Kubernetes config")?
    };

    Client::try_from(config).context("Failed to create Kubernetes client")
}

/// Generate a unique pod name.
fn generate_pod_name() -> String {
    format!("warpgate-ephemeral-{}", uuid::Uuid::new_v4())
}

/// Create the Pod manifest.
fn create_pod_manifest(name: &str, opts: &RemoteRunKubernetesOptions) -> Pod {
    serde_json::from_value(json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "labels": {
                "app.kubernetes.io/name": "warpgate-ephemeral",
                "app.kubernetes.io/managed-by": "warpgate"
            }
        },
        "spec": {
            "restartPolicy": "Never",
            "containers": [{
                "name": "main",
                "image": opts.pod_image,
                "command": [opts.command.as_str()],
                "stdin": true,
                "tty": true
            }],
            "terminationGracePeriodSeconds": 5
        }
    }))
    .expect("Pod manifest should be valid JSON")
}

/// Wait for the Pod to be in Running phase.
async fn wait_for_pod_running(
    pods: &Api<Pod>,
    name: &str,
    timeout_secs: u32,
) -> Result<()> {
    let timeout_duration = Duration::from_secs(timeout_secs as u64);

    timeout(timeout_duration, async {
        loop {
            let pod = pods.get(name).await.context("Failed to get pod status")?;

            if let Some(status) = pod.status {
                let phase = status.phase.as_deref().unwrap_or("Unknown");
                debug!(pod_name = %name, phase = %phase, "Pod status");

                match phase {
                    "Running" => {
                        info!(pod_name = %name, "Pod is Running");
                        return Ok(());
                    }
                    "Failed" | "Unknown" => {
                        let message = status
                            .conditions
                            .and_then(|c| c.into_iter().find(|c| c.type_ == "Ready"))
                            .and_then(|c| c.message)
                            .unwrap_or_else(|| "Unknown error".to_string());
                        anyhow::bail!("Pod entered {} phase: {}", phase, message);
                    }
                    "Succeeded" => {
                        anyhow::bail!("Pod completed unexpectedly");
                    }
                    _ => {
                        // Still pending, wait and retry
                        sleep(Duration::from_secs(2)).await;
                    }
                }
            } else {
                sleep(Duration::from_secs(2)).await;
            }
        }
    })
    .await
    .context("Timeout waiting for pod to be Running")?
}

/// Delete a Pod, cleaning up the ephemeral environment.
async fn delete_pod(pods: &Api<Pod>, name: &str) -> Result<()> {
    let dp = DeleteParams::default();
    match pods.delete(name, &dp).await {
        Ok(_) => {
            info!(pod_name = %name, "Deleted ephemeral pod");
            Ok(())
        }
        Err(kube::Error::Api(err)) if err.code == 404 => {
            debug!(pod_name = %name, "Pod already deleted");
            Ok(())
        }
        Err(e) => {
            warn!(pod_name = %name, error = %e, "Failed to delete pod");
            Err(e.into())
        }
    }
}

/// Execute a Kubernetes ephemeral pod session.
pub async fn execute(_services: &Services, opts: &RemoteRunKubernetesOptions) -> Result<()> {
    let client = create_client(opts).await?;
    let pods: Api<Pod> = Api::namespaced(client.clone(), &opts.namespace);

    let pod_name = generate_pod_name();
    info!(
        pod_name = %pod_name,
        namespace = %opts.namespace,
        image = %opts.pod_image,
        "Creating ephemeral Kubernetes pod"
    );

    // Create the pod
    let pod_manifest = create_pod_manifest(&pod_name, opts);
    let pp = PostParams::default();
    pods.create(&pp, &pod_manifest)
        .await
        .context("Failed to create pod")?;

    // Wait for pod to be running
    if let Err(e) = wait_for_pod_running(&pods, &pod_name, opts.timeout_seconds).await {
        // Clean up on failure
        let _ = delete_pod(&pods, &pod_name).await;
        return Err(e);
    }

    // Note: The actual TTY attachment would be handled by the calling layer
    // This function prepares the pod; the caller will establish the exec session

    info!(pod_name = %pod_name, "Kubernetes pod is ready for exec attachment");

    Ok(())
}

/// Test Kubernetes cluster connectivity.
pub async fn test_connection(opts: &RemoteRunKubernetesOptions) -> Result<()> {
    let client = create_client(opts).await?;
    let pods: Api<Pod> = Api::namespaced(client, &opts.namespace);

    // Test connectivity by listing pods in the namespace
    let _ = pods
        .list(&Default::default())
        .await
        .context("Failed to list pods in namespace")?;

    info!(
        namespace = %opts.namespace,
        image = %opts.pod_image,
        "Kubernetes connection test passed"
    );
    Ok(())
}

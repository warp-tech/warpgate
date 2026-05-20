use std::time::Duration;

use tracing::{debug, info};

use crate::{AwsError, instance_cache};

#[derive(Debug, Clone)]
pub struct Ec2InstanceInfo {
    pub instance_id: String,
    pub availability_zone: String,
    pub region: String,
}

/// Detect if running on EC2 by querying the IMDS endpoint with a 1s timeout.
pub async fn is_running_on_ec2() -> bool {
    let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()
    else {
        return false;
    };

    // Try IMDSv2 token endpoint
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        client
            .put("http://169.254.169.254/latest/api/token")
            .header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
            .send(),
    )
    .await;

    match result {
        Ok(Ok(resp)) if resp.status().is_success() => {
            info!("Detected EC2 environment via IMDS");
            true
        }
        _ => {
            debug!("Not running on EC2 (IMDS not reachable)");
            false
        }
    }
}

/// Look up an EC2 instance by IP address across all regions (cached)
pub async fn find_instance_by_ip(ip: &str) -> Result<Ec2InstanceInfo, AwsError> {
    if let Some(entry) = instance_cache().get(ip) {
        return Ok(entry.value().clone());
    }

    let regions = list_all_regions().await?;
    let ip = ip.to_string();

    // Query all regions in parallel
    let mut handles = Vec::new();
    for region_name in regions {
        let ip = ip.clone();
        handles.push(tokio::spawn(async move {
            find_instance_in_region(&ip, &region_name).await
        }));
    }

    for handle in handles {
        if let Ok(Ok(Some(info))) = handle.await {
            instance_cache().insert(ip.clone(), info.clone());
            return Ok(info);
        }
    }

    Err(AwsError::RegionUnknown(ip))
}

async fn find_instance_in_region(
    ip: &str,
    region_name: &str,
) -> Result<Option<Ec2InstanceInfo>, AwsError> {
    let region = aws_sdk_ec2::config::Region::new(region_name.to_string());
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(region)
        .load()
        .await;
    let client = aws_sdk_ec2::Client::new(&config);

    // Try private IP first, then public IP
    for filter_name in ["private-ip-address", "ip-address"] {
        let result = client
            .describe_instances()
            .filters(
                aws_sdk_ec2::types::Filter::builder()
                    .name(filter_name)
                    .values(ip)
                    .build(),
            )
            .send()
            .await;

        if let Ok(output) = result {
            for reservation in output.reservations() {
                for instance in reservation.instances() {
                    if let (Some(instance_id), Some(az)) = (
                        instance.instance_id(),
                        instance.placement().and_then(|p| p.availability_zone()),
                    ) {
                        let info = Ec2InstanceInfo {
                            instance_id: instance_id.to_string(),
                            availability_zone: az.to_string(),
                            region: region_name.to_string(),
                        };
                        debug!(?info, "Found EC2 instance for IP {ip}");
                        return Ok(Some(info));
                    }
                }
            }
        }
    }

    Ok(None)
}

async fn list_all_regions() -> Result<Vec<String>, AwsError> {
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .load()
        .await;
    let client = aws_sdk_ec2::Client::new(&config);

    let output = client
        .describe_regions()
        .all_regions(true)
        .send()
        .await
        .map_err(AwsError::sdk_error)?;

    Ok(output
        .regions()
        .iter()
        .filter_map(|r| r.region_name().map(|s| s.to_string()))
        .collect())
}

/// Push an SSH public key to an EC2 instance via EC2 Instance Connect.
pub async fn send_ssh_public_key(
    instance_id: &str,
    availability_zone: &str,
    region: &str,
    os_user: &str,
    ssh_public_key: &str,
) -> Result<(), AwsError> {
    let region_obj = aws_sdk_ec2instanceconnect::config::Region::new(region.to_string());
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(region_obj)
        .load()
        .await;

    let client = aws_sdk_ec2instanceconnect::Client::new(&config);
    client
        .send_ssh_public_key()
        .instance_id(instance_id)
        .instance_os_user(os_user)
        .ssh_public_key(ssh_public_key)
        .availability_zone(availability_zone)
        .send()
        .await
        .map_err(AwsError::sdk_error)?;

    info!(
        instance_id,
        os_user, "Pushed SSH public key via EC2 Instance Connect"
    );
    Ok(())
}

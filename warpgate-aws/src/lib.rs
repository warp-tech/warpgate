use std::sync::OnceLock;

use dashmap::DashMap;
use tokio::sync::OnceCell;

mod ec2;
mod eks;
mod error;
mod rds;
mod region;

pub use ec2::{Ec2InstanceInfo, find_instance_by_ip, is_running_on_ec2, send_ssh_public_key};
pub use eks::{EksClusterInfo, find_eks_cluster_by_url, generate_eks_token};
pub use error::AwsError;
pub use rds::generate_rds_auth_token;
pub use region::{get_imds_region, parse_eks_region, parse_rds_region};

/// Cached EC2 detection result
static EC2_DETECTION: OnceCell<bool> = OnceCell::const_new();

/// Cached IMDS region
static IMDS_REGION: OnceCell<Option<String>> = OnceCell::const_new();

/// Cached IP -> Ec2InstanceInfo
static INSTANCE_CACHE: OnceLock<DashMap<String, Ec2InstanceInfo>> = OnceLock::new();

fn instance_cache() -> &'static DashMap<String, Ec2InstanceInfo> {
    INSTANCE_CACHE.get_or_init(DashMap::new)
}

/// Check if running on EC2 (cached, 1s timeout on first call)
pub async fn check_ec2() -> bool {
    *EC2_DETECTION
        .get_or_init(|| async { is_running_on_ec2().await })
        .await
}

/// Get the IMDS region (cached)
pub async fn cached_imds_region() -> Option<String> {
    IMDS_REGION
        .get_or_init(|| async { get_imds_region().await })
        .await
        .clone()
}

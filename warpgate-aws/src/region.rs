use std::time::Duration;

use tracing::debug;

/// Parse the AWS region from an EKS cluster API URL.
///
/// EKS URLs follow the pattern: `https://<id>.<suffix>.<region>.eks.amazonaws.com`
pub fn parse_eks_region(url: &str) -> Option<String> {
    let host = url::Url::parse(url).ok()?.host_str()?.to_string();
    // e.g. ABCD1234.gr7.us-east-1.eks.amazonaws.com
    let parts: Vec<&str> = host.split('.').collect();
    // Find "eks" and "amazonaws" in the parts
    if let Some(eks_pos) = parts.iter().position(|&p| p == "eks") {
        if eks_pos >= 1 {
            let region = parts[eks_pos - 1];
            // Validate it looks like a region (contains dashes)
            if region.contains('-') {
                return Some(region.to_string());
            }
        }
    }
    None
}

/// Parse the AWS region from an RDS endpoint hostname.
///
/// RDS endpoints follow patterns like:
/// - `mydb.abc123.us-east-1.rds.amazonaws.com`
/// - `mydb.cluster-abc123.us-east-1.rds.amazonaws.com` (Aurora)
pub fn parse_rds_region(host: &str) -> Option<String> {
    let parts: Vec<&str> = host.split('.').collect();
    // Find "rds" and "amazonaws" in the parts
    if let Some(rds_pos) = parts.iter().position(|&p| p == "rds") {
        if rds_pos >= 1 {
            let region = parts[rds_pos - 1];
            if region.contains('-') {
                return Some(region.to_string());
            }
        }
    }
    None
}

/// Get the region from EC2 Instance Metadata Service (IMDS).
pub async fn get_imds_region() -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .ok()?;

    // Get IMDSv2 token
    let token = client
        .put("http://169.254.169.254/latest/api/token")
        .header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
        .send()
        .await
        .ok()?
        .text()
        .await
        .ok()?;

    // Get region
    let region = client
        .get("http://169.254.169.254/latest/meta-data/placement/region")
        .header("X-aws-ec2-metadata-token", &token)
        .send()
        .await
        .ok()?
        .text()
        .await
        .ok()?;

    debug!(region, "Detected AWS region from IMDS");
    Some(region)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_eks_region() {
        assert_eq!(
            parse_eks_region("https://ABCD1234.gr7.us-east-1.eks.amazonaws.com"),
            Some("us-east-1".to_string())
        );
        assert_eq!(
            parse_eks_region("https://xyz.sk1.eu-west-2.eks.amazonaws.com"),
            Some("eu-west-2".to_string())
        );
        assert_eq!(parse_eks_region("https://example.com"), None);
        assert_eq!(parse_eks_region("not-a-url"), None);
    }

    #[test]
    fn test_parse_rds_region() {
        assert_eq!(
            parse_rds_region("mydb.abc123.us-east-1.rds.amazonaws.com"),
            Some("us-east-1".to_string())
        );
        assert_eq!(
            parse_rds_region("mydb.cluster-abc123.eu-west-1.rds.amazonaws.com"),
            Some("eu-west-1".to_string())
        );
        assert_eq!(parse_rds_region("localhost"), None);
    }
}

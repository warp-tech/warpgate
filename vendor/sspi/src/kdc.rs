cfg_if::cfg_if! {
    if #[cfg(windows)] {
        use windows_registry::LOCAL_MACHINE;
    }
}

use std::env;
#[cfg(not(target_os = "windows"))]
use std::path::Path;
use std::str::FromStr;

use url::Url;

use crate::dns::detect_kdc_hosts_from_dns;
#[cfg(not(target_os = "windows"))]
use crate::krb::Krb5Conf;

#[cfg(target_os = "windows")]
#[instrument(level = "debug", ret)]
pub(crate) fn detect_kdc_hosts_from_system(domain: &str) -> Vec<String> {
    let domain_upper = domain.to_uppercase();
    let hklm = LOCAL_MACHINE;
    let domains_key_path = "SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Domains";
    let domain_key_path = format!("{}\\{}", domains_key_path, &domain_upper);
    if let Ok(domain_key) = hklm.open(domain_key_path) {
        let kdc_names: Vec<String> = domain_key.get_multi_string("KdcNames").unwrap_or_default();
        kdc_names.iter().map(|x| format!("tcp://{x}:88")).collect()
    } else {
        Vec::new()
    }
}

#[cfg(not(target_os = "windows"))]
#[instrument(level = "debug", ret)]
pub(crate) fn detect_kdc_hosts_from_system(domain: &str) -> Vec<String> {
    // https://web.mit.edu/kerberos/krb5-current/doc/user/user_config/kerberos.html#environment-variables

    let krb5_config = env::var("KRB5_CONFIG").unwrap_or_else(|_| "/etc/krb5.conf:/usr/local/etc/krb5.conf".to_string());
    let krb5_conf_paths = krb5_config.split(':').map(Path::new).collect::<Vec<&Path>>();

    for krb5_conf_path in krb5_conf_paths {
        if krb5_conf_path.exists()
            && let Some(krb5_conf) = Krb5Conf::new_from_file(krb5_conf_path)
            && let Some(kdc) = krb5_conf.get_value(vec!["realms", domain, "kdc"])
        {
            let kdc_url = format!("tcp://{}", kdc.as_str());
            return vec![kdc_url];
        }
    }

    Vec::new()
}

#[instrument(ret, level = "debug")]
pub(crate) fn detect_kdc_hosts(domain: &str) -> Vec<String> {
    if let Ok(kdc_url) = env::var(format!("SSPI_KDC_URL_{domain}")) {
        return vec![kdc_url];
    }

    if let Ok(kdc_url) = env::var("SSPI_KDC_URL") {
        return vec![kdc_url];
    }

    let kdc_hosts = detect_kdc_hosts_from_system(domain);

    if !kdc_hosts.is_empty() {
        return kdc_hosts;
    }

    detect_kdc_hosts_from_dns(domain)
}

pub fn detect_kdc_host(domain: &str) -> Option<String> {
    let kdc_hosts = detect_kdc_hosts(domain);
    if !kdc_hosts.is_empty() {
        Some(kdc_hosts.first().unwrap().to_string())
    } else {
        None
    }
}

pub fn detect_kdc_url(domain: &str) -> Option<Url> {
    let kdc_host = detect_kdc_host(domain)?;
    Url::from_str(&kdc_host).ok()
}

#[cfg(test)]
mod tests {
    use super::detect_kdc_hosts;
    #[test]
    fn test_detect_kdc() {
        if let Ok(domain) = std::env::var("TEST_KERBEROS_REALM") {
            println!("Finding KDC for {} domain", &domain);
            let kdc_hosts = detect_kdc_hosts(&domain);
            if let Some(kdc_host) = kdc_hosts.first() {
                println!("KDC server: {kdc_host}");
            } else {
                println!("No KDC server found!");
            }
        }
    }
}

#![allow(dead_code)]
#![allow(unused_imports)]

cfg_if::cfg_if! {
    if #[cfg(windows)] {
        use windows::{
            core::*,
            Win32::NetworkManagement::Dns::*,
        };
        use windows_registry::LOCAL_MACHINE;
        use std::ptr::{null_mut};
        use core::ffi::{c_void};

        pub(crate) fn dns_query_srv_records(name: &str) -> Vec<String> {
            let mut records = Vec::new();

            let mut p_query_results: *mut DNS_RECORDA = null_mut();

            // SAFETY: FFI call with no outstanding preconditions.
            let dns_status = unsafe {
                DnsQuery_W(
                    &HSTRING::from(name),
                    DNS_TYPE_SRV,
                    DNS_QUERY_STANDARD,
                    None,
                    &mut p_query_results,
                    None
                )
            };

            match dns_status.ok() {
                Ok(()) => {
                    // SAFETY: `p_query_results` in non-null because `dns_status` is Ok.
                    let query_results = unsafe { *p_query_results };
                    // SAFETY: `query_results.Data` is guaranteed to contain `SRV` because
                    // of arguments to `DnsQuery_W`.
                    let p_name_target = unsafe { query_results.Data.Srv.pNameTarget };
                    let name_target = PWSTR::from_raw(p_name_target.as_ptr() as *mut u16);
                    // SAFETY: `name_target` is guaranteed to be correct at this point.
                    let name_target = unsafe {name_target.to_string()};

                    if let Ok(name_target) = name_target {
                        records.push(name_target);
                    }
                }
                Err(error) => error!(%error, "DnsQuery_W failed"),
            }

            // SAFETY: `p_query_results` is not null.
            unsafe {
                DnsFree(Some(p_query_results as *const c_void), DnsFreeRecordList);
            }

            records
        }

        pub(crate) struct DnsClientNrptRule {
            rule_name: String,
            namespace: String,
            name_servers: Vec<String>
        }

        pub(crate) fn get_dns_client_nrpt_rules() -> Vec<DnsClientNrptRule> {
            let mut rules: Vec<DnsClientNrptRule> = Vec::new();
            let hklm = LOCAL_MACHINE;
            let dns_policy_config_key_path = "System\\CurrentControlSet\\Services\\Dnscache\\Parameters\\DnsPolicyConfig";
            if let Ok(dns_policy_config_key) = hklm.open(dns_policy_config_key_path) {
                for rule_name in dns_policy_config_key.keys().unwrap() {
                    let dns_policy_rule_key_path = format!("{}\\{}", dns_policy_config_key_path, &rule_name);
                    if let Ok(dns_policy_rule_key) = hklm.open(dns_policy_rule_key_path) {
                        let namespace: Option<String> = dns_policy_rule_key.get_string("Name").ok(); // REG_MULTI_SZ
                        let name_server_list: Option<String> = dns_policy_rule_key.get_string("GenericDNSServers").ok(); // REG_SZ
                        if let (Some(namespace), Some(name_server_list)) = (namespace, name_server_list) {
                            let name_servers: Vec<String> = name_server_list.split(';').map(|x| x.to_string()).collect();
                            rules.push(DnsClientNrptRule {
                                rule_name,
                                namespace,
                                name_servers,
                            });
                        }
                    }
                }
            }
            rules
        }

        pub(crate) fn get_default_name_servers() -> Vec<String> {
            let hklm = LOCAL_MACHINE;
            let tcpip_linkage_key_path = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Linkage";
            let tcpip_interfaces_key_path = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces";
            let dns_registered_adapters_key_path = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\DNSRegisteredAdapters";

            if let Ok(tcpip_linkage_key) = hklm.open(tcpip_linkage_key_path) {
                let bind_devices: Vec<String> = tcpip_linkage_key.get_multi_string("Bind").unwrap();
                let device_ids = bind_devices.iter().map(|x| x.strip_prefix("\\Device\\").unwrap());

                for device_id in device_ids {
                    let interface_key_path = format!("{}\\{}", tcpip_interfaces_key_path, &device_id);
                    let dns_adapter_key_path = format!("{}\\{}", dns_registered_adapters_key_path, &device_id);

                    if let (Ok(interface_key), Ok(dns_adapter_key)) = (hklm.open(interface_key_path), hklm.open(dns_adapter_key_path)) {
                        let name_server: Option<String> = interface_key.get_string("NameServer").ok().filter(|x: &String| !x.is_empty());
                        let dhcp_name_server: Option<String> = interface_key.get_string("DhcpNameServer").ok().filter(|x: &String| !x.is_empty());
                        let stale_adapter: u32 = dns_adapter_key.get_u32("StaleAdapter").unwrap_or(1);

                        if stale_adapter != 1
                            && let Some(name_server_list) = name_server.or(dhcp_name_server) {
                                let name_servers: Vec<String> = name_server_list.split(' ')
                                    .map(|c| c.trim().to_string()).filter(|x: &String| !x.is_empty()).collect();
                                return name_servers;
                            }
                    }
                }
            }
            Vec::new()
        }

        pub(crate) fn get_name_servers_for_domain(domain: &str) -> Vec<String> {
            let domain_namespace = if domain.starts_with('.') {
                domain.to_string()
            } else {
                format!(".{}", &domain)
            };

            for nrpt_rule in get_dns_client_nrpt_rules() {
                if nrpt_rule.namespace.ends_with(&domain_namespace) {
                    return nrpt_rule.name_servers;
                }
            }

            get_default_name_servers()
        }

        pub(crate) fn detect_kdc_hosts_from_dns_windows(domain: &str) -> Vec<String> {
            let krb_tcp_name = &format!("_kerberos._tcp.{domain}");
            let krb_tcp_srv = dns_query_srv_records(krb_tcp_name);

            if !krb_tcp_srv.is_empty() {
                return krb_tcp_srv.iter().map(|x| format!("tcp://{x}:88")).collect()
            }

            let krb_udp_name = &format!("_kerberos._udp.{domain}");
            let krb_udp_srv = dns_query_srv_records(krb_udp_name);

            if !krb_udp_srv.is_empty() {
                return krb_udp_srv.iter().map(|x| format!("udp://{x}:88")).collect()
            }

            Vec::new()
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(any(target_os="macos", target_os="ios"))] {
        use std::fmt;
        use std::time::Duration;
        use tokio::time::timeout;
        use futures::stream::{StreamExt};
        use async_dnssd::{query_record, QueryRecordResult, QueriedRecordFlags, Type};

        #[derive(Clone)]
        pub(crate) struct DnsSrvRecord {
            priority: u16,
            weight: u16,
            port: u16,
            target: String
        }

        /// Why an SRV callback could not be turned into a usable record, kept for diagnostics.
        #[derive(Debug)]
        pub(crate) enum SrvRecordParseError {
            /// RDATA is shorter than the 6-byte fixed header (priority + weight + port).
            RdataTooShort,
            /// The target is the DNS root ("."), which per RFC 2782 means the service is not
            /// available, so there is no host to connect to.
            EmptyTarget,
            /// The target name is not a well-formed DNS name: a label runs past the end of the
            /// RDATA, a label exceeds the 63-byte limit, or the name is not root-terminated.
            MalformedTarget,
        }

        impl fmt::Display for SrvRecordParseError {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    Self::RdataTooShort => f.write_str("RDATA shorter than the 6-byte SRV fixed fields"),
                    Self::EmptyTarget => f.write_str("SRV target names no host"),
                    Self::MalformedTarget => f.write_str("SRV target is not a well-formed DNS name"),
                }
            }
        }

        impl std::error::Error for SrvRecordParseError {}

        impl DnsSrvRecord {
            /// Parses the wire RDATA of an SRV record (RFC 2782: priority, weight, port, target).
            fn from_rdata(rdata: &[u8]) -> Result<Self, SrvRecordParseError> {
                // An SRV record's RDATA is 2 (priority) + 2 (weight) + 2 (port) = 6 fixed
                // bytes, followed by the target as a DNS name. Fewer than 6 bytes cannot be
                // indexed for the fixed fields. In practice such a short RDATA only shows up
                // in the negative/removal callbacks handled by the caller, so this guard is
                // defensive.
                if rdata.len() < 6 {
                    return Err(SrvRecordParseError::RdataTooShort);
                }
                let priority = u16::from_be_bytes(rdata[0..2].try_into().unwrap());
                let weight = u16::from_be_bytes(rdata[2..4].try_into().unwrap());
                let port = u16::from_be_bytes(rdata[4..6].try_into().unwrap());
                // A malformed name (truncated label, oversized label, missing root terminator)
                // is rejected here rather than silently accepted as a partial hostname.
                let target = dns_decode_target_data_to_string(&rdata[6..])?;
                // An empty (root, ".") target per RFC 2782 explicitly means the service is not
                // available, so there is no usable endpoint. Reject it rather than emit a
                // "scheme://:port" URL with an empty host.
                if target.is_empty() {
                    return Err(SrvRecordParseError::EmptyTarget);
                }
                Ok(DnsSrvRecord {
                    priority,
                    weight,
                    port,
                    target,
                })
            }
        }

        impl TryFrom<&QueryRecordResult> for DnsSrvRecord {
            type Error = SrvRecordParseError;

            fn try_from(record: &QueryRecordResult) -> Result<Self, Self::Error> {
                Self::from_rdata(record.rdata.as_slice())
            }
        }

        /// Decodes a DNS name in wire format (length-prefixed labels ending in a root label)
        /// into a dotted string.
        ///
        /// The name must be well-formed: every label fully present and at most 63 bytes, ending
        /// with the root label (a zero length byte). A truncated label, an oversized label byte
        /// (>63, e.g. a compression pointer, which RFC 2782 forbids in an SRV target), or a name
        /// that runs off the end without a root terminator is rejected as `MalformedTarget`
        /// rather than returning the partial labels collected so far.
        pub(crate) fn dns_decode_target_data_to_string(v: &[u8]) -> Result<String, SrvRecordParseError> {
            const MAX_LABEL_LEN: usize = 63;

            let mut names = Vec::new();

            let mut i = 0;
            while i < v.len() {
                let size = v[i] as usize;
                if size == 0 {
                    // Root label: the name is complete and correctly terminated.
                    return Ok(names.join("."));
                }
                if size > MAX_LABEL_LEN || i + 1 + size > v.len() {
                    return Err(SrvRecordParseError::MalformedTarget);
                }
                names.push(String::from_utf8_lossy(&v[i+1..i+1+size]));
                i = i + 1 + size;
            }

            // Reached the end without a root label: the name is truncated.
            Err(SrvRecordParseError::MalformedTarget)
        }

        pub(crate) fn dns_query_srv_records(name: &str) -> Vec<DnsSrvRecord> {
            const QUERY_TIMEOUT: u64 = 1000;

            async fn query_with_timeout(name: &str, query_timeout: u64) -> Vec<DnsSrvRecord> {
                let mut dns_records: Vec<DnsSrvRecord> = Vec::new();
                let mut query = query_record(name, Type::SRV);

                loop {
                    match timeout(Duration::from_millis(query_timeout), query.next()).await {
                        Ok(Some(Ok(dns_record))) => {
                            // A normal "no SRV records" outcome is a query timeout (the
                            // Err arm below): mDNSResponder simply never calls back. Some
                            // environments, however, have a resolver in the path (VPN,
                            // enterprise DNS filtering, a local stub) that answers the SRV
                            // query immediately with a negative/empty or non-SRV response.
                            // Such a callback carries the ADD flag cleared and/or RDATA too
                            // short to be an SRV record; parsing it blindly panics. Only ADD
                            // callbacks with a well-formed SRV RDATA are usable records; the
                            // rest are logged so the offending response can be diagnosed.
                            if !dns_record.flags.contains(QueriedRecordFlags::ADD) {
                                debug!(
                                    name,
                                    rr_type = ?dns_record.rr_type,
                                    rr_class = ?dns_record.rr_class,
                                    rdata_len = dns_record.rdata.len(),
                                    "Skipping DNS SRV callback without ADD flag (negative response or record removal)"
                                );
                            } else {
                                match DnsSrvRecord::try_from(&dns_record) {
                                    Ok(srv_record) => dns_records.push(srv_record),
                                    Err(reason) => {
                                        warn!(
                                            name,
                                            %reason,
                                            rr_type = ?dns_record.rr_type,
                                            rr_class = ?dns_record.rr_class,
                                            rdata_len = dns_record.rdata.len(),
                                            "Ignoring malformed DNS SRV callback"
                                        );
                                    }
                                }
                            }
                            if !dns_record.flags.contains(QueriedRecordFlags::MORE_COMING) {
                                break;
                            }
                        }
                        Ok(None) => {
                            break
                        }
                        Ok(Some(Err(error))) => {
                            error!(%error, "IO error when reading DNS query");
                            break;
                        }
                        Err(error) => {
                            error!(%error, "Timeout when reading DNS query");
                            break;
                        }
                    }
                }

                dns_records
            }

            execute_future(query_with_timeout(name, QUERY_TIMEOUT))
        }

        pub(crate) fn detect_kdc_hosts_from_dns_apple(domain: &str) -> Vec<String> {
            let krb_tcp_name = &format!("_kerberos._tcp.{domain}");
            let krb_tcp_srv = dns_query_srv_records(krb_tcp_name);

            if !krb_tcp_srv.is_empty() {
                return krb_tcp_srv.iter().map(|x| format!("tcp://{}:{}", &x.target, x.port)).collect()
            }

            let krb_udp_name = &format!("_kerberos._udp.{domain}");
            let krb_udp_srv = dns_query_srv_records(krb_udp_name);

            if !krb_udp_srv.is_empty() {
                return krb_udp_srv.iter().map(|x| format!("udp://{}:{}", &x.target, x.port)).collect()
            }

            Vec::new()
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature="dns_resolver")] {
        use hickory_resolver::TokioResolver;
        use hickory_resolver::system_conf::read_system_conf;
        use hickory_resolver::config::{ResolverConfig, NameServerConfig, ResolverOpts};
        use hickory_resolver::proto::xfer::Protocol;
        use hickory_resolver::name_server::GenericConnector;
        use hickory_proto::runtime::TokioRuntimeProvider;
        use std::env;
        use std::net::{IpAddr,SocketAddr};
        use std::str::FromStr;
        use url::Url;

        fn get_dns_name_server_from_url(url: &str) -> Option<NameServerConfig> {
            let url = if !url.contains("://") && !url.is_empty() {
                format!("udp://{url}")
            } else {
                url.to_string()
            };

            if let Ok(url) = Url::parse(&url)
                && let Some(url_host) = url.host_str() {
                    let url_port = url.port().unwrap_or(53);
                    let protocol = match url.scheme().to_lowercase().as_str() {
                        "tcp" => Protocol::Tcp,
                        "udp" => Protocol::Udp,
                        _ => Protocol::Udp,
                    };
                    if let Ok(ip_addr) = IpAddr::from_str(url_host) {
                        let socket_addr = SocketAddr::new(ip_addr, url_port);
                        return Some(NameServerConfig {
                            socket_addr,
                            protocol,
                            tls_dns_name: None,
                            trust_negative_responses: false,
                            http_endpoint: None,
                            bind_addr: None
                        });
                    }
                }

            None
        }

        fn get_dns_resolver_from_name_servers(name_servers: Vec<String>) -> TokioResolver {
            let mut resolver_config = ResolverConfig::new();

            for name_server_url in name_servers {
                if let Some(name_server) = get_dns_name_server_from_url(&name_server_url) {
                    resolver_config.add_name_server(name_server);
                }
            }

            let mut resolver_options = ResolverOpts::default();
            resolver_options.validate = false;

            TokioResolver::builder_with_config(resolver_config, GenericConnector::new(TokioRuntimeProvider::new()))
                .with_options(resolver_options)
                .build()
        }

        #[cfg(target_os="windows")]
        fn get_dns_resolver(domain: &str) -> Option<TokioResolver> {
            let name_servers = get_name_servers_for_domain(domain);
            Some(get_dns_resolver_from_name_servers(name_servers))
        }

        #[cfg(not(target_os="windows"))]
        fn get_dns_resolver(_domain: &str) -> Option<TokioResolver> {
            if let Ok(name_server_list) = env::var("SSPI_DNS_URL") {
                let name_servers: Vec<String> = name_server_list
                    .split(',').map(|c|c.trim()).filter(|x| !x.is_empty()).map(String::from).collect();
                Some(get_dns_resolver_from_name_servers(name_servers))
            } else if let Ok((resolver_config, resolver_options)) = read_system_conf() {
                Some(TokioResolver::builder_with_config(resolver_config, GenericConnector::new(TokioRuntimeProvider::new()))
                    .with_options(resolver_options)
                    .build())
            } else {
                None
            }
        }

        pub(crate) fn detect_kdc_hosts_from_dns_resolver(domain: &str) -> Vec<String> {
            let mut kdc_hosts = Vec::new();

            if let Some(resolver) = get_dns_resolver(domain) {
                if let Ok(records) = execute_future(resolver.srv_lookup(format!("_kerberos._tcp.{domain}"))) {
                    for record in records {
                        let port = record.port();
                        let target_name = record.target().to_string();
                        let target_name = target_name.trim_end_matches('.').to_string();
                        let kdc_host = format!("tcp://{}:{}", &target_name, port);
                        kdc_hosts.push(kdc_host);
                    }
                }

                if let Ok(records) = execute_future(resolver.srv_lookup(format!("_kerberos._udp.{domain}"))) {
                    for record in records {
                        let port = record.port();
                        let target_name = record.target().to_string();
                        let target_name = target_name.trim_end_matches('.').to_string();
                        let kdc_host = format!("udp://{}:{}", &target_name, port);
                        kdc_hosts.push(kdc_host);
                    }
                }
            }

            kdc_hosts
        }
    }
}

#[cfg(any(feature = "dns_resolver", target_os = "macos", target_os = "ios"))]
fn execute_future<Fut>(fut: Fut) -> Fut::Output
where
    Fut: IntoFuture + Send,
    Fut::Output: Send,
{
    use std::thread;

    use tokio::runtime::{Builder, Handle, Runtime, RuntimeFlavor};
    use tokio::task;

    fn new_runtime() -> Runtime {
        Builder::new_current_thread().enable_all().build().unwrap()
    }

    match Handle::try_current() {
        Ok(handle) => {
            match handle.runtime_flavor() {
                RuntimeFlavor::CurrentThread => thread::scope(|s| {
                    s.spawn(move || new_runtime().block_on(fut.into_future()))
                        .join()
                        .unwrap()
                }),
                // block_in_place can't be used in current_thread runtime
                _ => task::block_in_place(move || handle.block_on(fut.into_future())),
            }
        }
        Err(_) => new_runtime().block_on(fut.into_future()),
    }
}

#[allow(unused_variables)]
#[instrument(level = "debug", ret)]
pub(crate) fn detect_kdc_hosts_from_dns(domain: &str) -> Vec<String> {
    cfg_if::cfg_if! {
        if #[cfg(windows)] {
            detect_kdc_hosts_from_dns_windows(domain)
        } else if #[cfg(any(target_os="macos", target_os="ios"))] {
            detect_kdc_hosts_from_dns_apple(domain)
        } else if #[cfg(feature="dns_resolver")] {
            detect_kdc_hosts_from_dns_resolver(domain)
        } else {
            Vec::new()
        }
    }
}

#[cfg(all(test, any(target_os = "macos", target_os = "ios")))]
mod apple_srv_tests {
    use super::{DnsSrvRecord, SrvRecordParseError};

    /// Builds SRV RDATA: priority, weight, port, then `target` as length-prefixed DNS labels
    /// terminated by the root label.
    fn srv_rdata(priority: u16, weight: u16, port: u16, target: &str) -> Vec<u8> {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&priority.to_be_bytes());
        rdata.extend_from_slice(&weight.to_be_bytes());
        rdata.extend_from_slice(&port.to_be_bytes());
        for label in target.split('.').filter(|label| !label.is_empty()) {
            rdata.push(label.len() as u8);
            rdata.extend_from_slice(label.as_bytes());
        }
        rdata.push(0); // root label
        rdata
    }

    #[test]
    fn parses_well_formed_srv_record() {
        let rdata = srv_rdata(1, 2, 88, "dc.example.com");
        let record = DnsSrvRecord::from_rdata(&rdata).expect("valid SRV record should parse");
        assert_eq!(record.priority, 1);
        assert_eq!(record.weight, 2);
        assert_eq!(record.port, 88);
        assert_eq!(record.target, "dc.example.com");
    }

    #[test]
    fn rejects_empty_rdata() {
        // The original crash: an empty negative-response callback sliced as if it were SRV.
        assert!(matches!(
            DnsSrvRecord::from_rdata(&[]),
            Err(SrvRecordParseError::RdataTooShort)
        ));
    }

    #[test]
    fn rejects_rdata_shorter_than_fixed_header() {
        assert!(matches!(
            DnsSrvRecord::from_rdata(&[0, 1, 0]),
            Err(SrvRecordParseError::RdataTooShort)
        ));
    }

    #[test]
    fn rejects_six_byte_rdata_with_no_target() {
        // Exactly the 6 fixed bytes, not even a root label: a truncated name.
        assert!(matches!(
            DnsSrvRecord::from_rdata(&[0, 1, 0, 2, 0, 88]),
            Err(SrvRecordParseError::MalformedTarget)
        ));
    }

    #[test]
    fn rejects_rfc2782_root_target() {
        // Target "." (a lone root label): RFC 2782 "service not available".
        assert!(matches!(
            DnsSrvRecord::from_rdata(&[0, 1, 0, 2, 0, 88, 0]),
            Err(SrvRecordParseError::EmptyTarget)
        ));
    }

    #[test]
    fn rejects_truncated_label() {
        // "dc" then a label claiming 5 bytes with only 1 present, and no root terminator:
        // must not be silently accepted as the partial name "dc".
        let rdata = [0, 1, 0, 2, 0, 88, 2, b'd', b'c', 5, b'x'];
        assert!(matches!(
            DnsSrvRecord::from_rdata(&rdata),
            Err(SrvRecordParseError::MalformedTarget)
        ));
    }

    #[test]
    fn rejects_name_without_root_terminator() {
        // A complete label but the name runs off the end without a root label.
        let rdata = [0, 1, 0, 2, 0, 88, 2, b'd', b'c'];
        assert!(matches!(
            DnsSrvRecord::from_rdata(&rdata),
            Err(SrvRecordParseError::MalformedTarget)
        ));
    }

    #[test]
    fn rejects_oversized_label_length() {
        // A label length byte above the 63-byte limit (e.g. a compression pointer 0xC0),
        // which RFC 2782 forbids in an SRV target.
        let rdata = [0, 1, 0, 2, 0, 88, 0xC0, 0x0C];
        assert!(matches!(
            DnsSrvRecord::from_rdata(&rdata),
            Err(SrvRecordParseError::MalformedTarget)
        ));
    }
}

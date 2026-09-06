//! Classification of Kubernetes API requests into the operations worth auditing.
//!
//! One classifier feeds two consumers — the audit events written to the session
//! log, and the metadata attached to a terminal recording — so the two cannot
//! drift apart about what a request was.
//!
//! Everything here describes *what the client asked for*. Warpgate does not know
//! what the API server then resolved (which container a request carrying no
//! `container=` landed on, say), and inventing that would put unverified names
//! into an audit log, so unspecified stays unspecified.

use serde::Deserialize;
use warpgate_core::logging::{AuditEvent, KubernetesAuditSubject};

use crate::recording::SessionRecordingMetadata;

/// A client controls argv and the container list, so bound what a single
/// request can push into one log row.
const MAX_LIST_ELEMENTS: usize = 64;
const MAX_LIST_BYTES: usize = 4096;
/// Appended to a list that hit either cap above.
const TRUNCATION_MARKER: &str = "<truncated>";

/// A pod addressed by a request path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodRef {
    pub namespace: String,
    pub pod: String,
}

/// A pod subresource that upgrades to a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamOperation {
    Exec {
        pod: PodRef,
        container: Option<String>,
        command: Vec<String>,
        tty: bool,
        stdin: bool,
    },
    Attach {
        pod: PodRef,
        container: Option<String>,
        tty: bool,
    },
    PortForward {
        pod: PodRef,
        ports: Vec<String>,
    },
}

/// A request whose audit-worthy detail lives in its body rather than its URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutatingOperation {
    /// `kubectl debug` against a running pod.
    EphemeralContainersUpdated {
        pod: PodRef,
        containers: Vec<EphemeralContainerSummary>,
    },
    /// A pod creation — how `kubectl debug node/...` and `kubectl debug
    /// --copy-to` land their debug workload.
    PodCreated { namespace: String, pod: PodSummary },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EphemeralContainerSummary {
    pub name: String,
    pub image: String,
    pub target_container: Option<String>,
    pub command: Vec<String>,
    pub tty: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodSummary {
    pub name: String,
    pub images: Vec<String>,
    pub node_name: Option<String>,
    pub host_pid: bool,
    pub host_network: bool,
    pub privileged: bool,
}

// ---------- URL classification ----------

/// The parts of `/api/v1/namespaces/{ns}/pods[/{name}[/{subresource}]]`, the
/// only path shape any audited operation takes.
///
/// Classification reads the *request* path rather than the upstream URL: a
/// target whose cluster URL carries a path prefix would otherwise never match,
/// and an audit trail that quietly switches itself off for such a target is
/// worse than no audit trail at all.
struct PodsPath {
    namespace: String,
    /// `None` for the collection itself, which is what a pod creation targets.
    name: Option<String>,
    subresource: Option<String>,
}

fn parse_pods_path(api_path: &str) -> Option<PodsPath> {
    // Segments arrive percent-encoded, but namespace and pod names are RFC 1123
    // labels, so nothing in a well-formed request needs decoding here.
    let mut segments = api_path.split('/').filter(|s| !s.is_empty());

    if segments.next()? != "api" || segments.next()? != "v1" || segments.next()? != "namespaces" {
        return None;
    }
    let namespace = segments.next()?.to_owned();
    if segments.next()? != "pods" {
        return None;
    }
    let name = segments.next().map(ToOwned::to_owned);
    let subresource = segments.next().map(ToOwned::to_owned);
    // Anything deeper is not a shape this classifier understands.
    if segments.next().is_some() {
        return None;
    }

    Some(PodsPath {
        namespace,
        name,
        subresource,
    })
}

/// Matches Go's `strconv.ParseBool`, which is how the API server reads these.
fn parse_bool(value: &str) -> bool {
    matches!(value, "1" | "t" | "T" | "TRUE" | "true" | "True")
}

#[derive(Default)]
struct StreamQuery {
    command: Vec<String>,
    container: Option<String>,
    ports: Vec<String>,
    tty: bool,
    stdin: bool,
}

fn parse_stream_query(raw: Option<&str>) -> StreamQuery {
    let mut query = StreamQuery::default();
    for (key, value) in url::form_urlencoded::parse(raw.unwrap_or_default().as_bytes()) {
        match key.as_ref() {
            // kubectl sends one `command=` per argv element, so every value
            // matters: collecting the query into a map would keep only one of
            // them and `kubectl exec pod -- ls -la` would be recorded as `-la`.
            "command" => query.command.push(value.into_owned()),
            "ports" => query.ports.push(value.into_owned()),
            "container" => query.container = Some(value.into_owned()),
            "tty" => query.tty = parse_bool(&value),
            "stdin" => query.stdin = parse_bool(&value),
            _ => {}
        }
    }
    query
}

/// The streaming operation this websocket-upgrading request performs, if it is
/// one Warpgate audits.
pub fn classify_stream(api_path: &str, query: Option<&str>) -> Option<StreamOperation> {
    let path = parse_pods_path(api_path)?;
    let (Some(name), Some(subresource)) = (path.name, path.subresource) else {
        return None;
    };
    let pod = PodRef {
        namespace: path.namespace,
        pod: name,
    };
    let query = parse_stream_query(query);

    Some(match subresource.as_str() {
        "exec" => StreamOperation::Exec {
            pod,
            container: query.container,
            command: query.command,
            tty: query.tty,
            stdin: query.stdin,
        },
        "attach" => StreamOperation::Attach {
            pod,
            container: query.container,
            tty: query.tty,
        },
        "portforward" => StreamOperation::PortForward {
            pod,
            ports: query.ports,
        },
        _ => return None,
    })
}

// ---------- Body classification ----------

// Only the fields below are ever read. Everything else a pod spec carries —
// `env`, `envFrom`, `volumeMounts` above all — routinely holds secrets and must
// never reach a log row, and serde ignores unknown fields, so they are not so
// much as parsed. Every field is optional so that both a missing key and an
// explicit `null` (which a strategic merge patch uses to delete one) parse.

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct PodBody {
    metadata: Option<PodMetadataBody>,
    spec: Option<PodSpecBody>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct PodMetadataBody {
    name: Option<String>,
    generate_name: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct PodSpecBody {
    ephemeral_containers: Option<Vec<ContainerBody>>,
    containers: Option<Vec<ContainerBody>>,
    node_name: Option<String>,
    // Not `camelCase`: Kubernetes keeps the acronym uppercase, so the derived
    // `hostPid` would never match and the flag would always read as false.
    #[serde(rename = "hostPID")]
    host_pid: Option<bool>,
    host_network: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct ContainerBody {
    name: Option<String>,
    image: Option<String>,
    command: Option<Vec<String>>,
    args: Option<Vec<String>>,
    target_container_name: Option<String>,
    tty: Option<bool>,
    security_context: Option<SecurityContextBody>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct SecurityContextBody {
    privileged: Option<bool>,
}

impl ContainerBody {
    /// The argv the client specified: `command` (which overrides the image's
    /// entrypoint) followed by `args`. Empty when it specified neither and the
    /// image's own entrypoint runs.
    fn argv(&self) -> Vec<String> {
        self.command
            .iter()
            .flatten()
            .chain(self.args.iter().flatten())
            .cloned()
            .collect()
    }

    fn summarise_ephemeral(&self) -> EphemeralContainerSummary {
        EphemeralContainerSummary {
            name: self.name.clone().unwrap_or_default(),
            image: self.image.clone().unwrap_or_default(),
            target_container: self.target_container_name.clone(),
            command: self.argv(),
            tty: self.tty.unwrap_or_default(),
        }
    }
}

impl PodBody {
    fn summarise(&self) -> PodSummary {
        let containers = self.spec.as_ref().and_then(|s| s.containers.as_ref());
        let metadata = self.metadata.as_ref();
        PodSummary {
            // A pod created with `generateName` has no name yet; the prefix is
            // more useful than nothing.
            name: metadata
                .and_then(|m| m.name.clone().or_else(|| m.generate_name.clone()))
                .unwrap_or_default(),
            images: containers
                .into_iter()
                .flatten()
                .filter_map(|c| c.image.clone())
                .collect(),
            node_name: self.spec.as_ref().and_then(|s| s.node_name.clone()),
            host_pid: self
                .spec
                .as_ref()
                .and_then(|s| s.host_pid)
                .unwrap_or_default(),
            host_network: self
                .spec
                .as_ref()
                .and_then(|s| s.host_network)
                .unwrap_or_default(),
            privileged: containers.into_iter().flatten().any(|c| {
                c.security_context
                    .as_ref()
                    .and_then(|s| s.privileged)
                    .unwrap_or_default()
            }),
        }
    }
}

/// The body-carrying operation this request performs, if it is one Warpgate
/// audits. `None` covers both "not an audited shape" and a body that would not
/// parse.
pub fn classify_mutating(method: &str, api_path: &str, body: &[u8]) -> Option<MutatingOperation> {
    let path = parse_pods_path(api_path)?;

    match (method, path.name, path.subresource.as_deref()) {
        // `kubectl` since 1.23 sends a strategic merge PATCH whose body holds
        // only the newly added container. The older fallback PUTs the whole
        // pod, so its body also repeats containers that were already there and
        // those are audited again — over-reporting a debug container beats
        // missing one.
        ("PATCH" | "PUT", Some(name), Some("ephemeralcontainers")) => {
            let body: PodBody = serde_json::from_slice(body).ok()?;
            let containers: Vec<_> = body
                .spec
                .as_ref()
                .and_then(|s| s.ephemeral_containers.as_ref())
                .into_iter()
                .flatten()
                .map(ContainerBody::summarise_ephemeral)
                .collect();
            if containers.is_empty() {
                return None;
            }
            Some(MutatingOperation::EphemeralContainersUpdated {
                pod: PodRef {
                    namespace: path.namespace,
                    pod: name,
                },
                containers,
            })
        }
        ("POST", None, None) => {
            let body: PodBody = serde_json::from_slice(body).ok()?;
            Some(MutatingOperation::PodCreated {
                namespace: path.namespace,
                pod: body.summarise(),
            })
        }
        _ => None,
    }
}

// ---------- Event and recording construction ----------

/// Renders a list as a JSON array for a single log field, bounded so a client
/// cannot make a log row arbitrarily large.
fn json_array(values: &[String]) -> String {
    let mut kept: Vec<&str> = Vec::new();
    let mut budget = MAX_LIST_BYTES;
    let mut truncated = values.len() > MAX_LIST_ELEMENTS;

    for value in values.iter().take(MAX_LIST_ELEMENTS) {
        if value.len() > budget {
            truncated = true;
            break;
        }
        budget -= value.len();
        kept.push(value);
    }
    if truncated {
        kept.push(TRUNCATION_MARKER);
    }

    serde_json::to_string(&kept).unwrap_or_else(|_| "[]".to_owned())
}

impl StreamOperation {
    pub const fn pod(&self) -> &PodRef {
        match self {
            Self::Exec { pod, .. } | Self::Attach { pod, .. } | Self::PortForward { pod, .. } => {
                pod
            }
        }
    }

    pub const fn subresource(&self) -> &'static str {
        match self {
            Self::Exec { .. } => "exec",
            Self::Attach { .. } => "attach",
            Self::PortForward { .. } => "portforward",
        }
    }

    /// The recording to open for this operation, if it produces a terminal
    /// stream. Port forwarding carries raw TCP rather than a terminal, so it is
    /// audited but not recorded here.
    pub fn recording_metadata(&self) -> Option<SessionRecordingMetadata> {
        let pod = self.pod();
        match self {
            Self::Exec {
                container, command, ..
            } => Some(SessionRecordingMetadata::Exec {
                namespace: pod.namespace.clone(),
                pod: pod.pod.clone(),
                container: container.clone(),
                command: command.clone(),
            }),
            Self::Attach { container, .. } => Some(SessionRecordingMetadata::Attach {
                namespace: pod.namespace.clone(),
                pod: pod.pod.clone(),
                container: container.clone(),
            }),
            Self::PortForward { .. } => None,
        }
    }

    pub fn audit_event(&self, subject: &KubernetesAuditSubject) -> AuditEvent {
        let pod = self.pod();
        let namespace = pod.namespace.clone();
        let pod_name = pod.pod.clone();
        match self {
            Self::Exec {
                container,
                command,
                tty,
                stdin,
                ..
            } => AuditEvent::KubernetesExecStarted {
                subject: subject.clone(),
                namespace,
                pod: pod_name,
                container: container.clone(),
                command: json_array(command),
                tty: *tty,
                stdin: *stdin,
            },
            Self::Attach { container, tty, .. } => AuditEvent::KubernetesAttachStarted {
                subject: subject.clone(),
                namespace,
                pod: pod_name,
                container: container.clone(),
                tty: *tty,
            },
            Self::PortForward { ports, .. } => AuditEvent::KubernetesPortForwardStarted {
                subject: subject.clone(),
                namespace,
                pod: pod_name,
                // Absent rather than empty: the websocket protocol negotiates
                // ports per stream and sends no query, so there is nothing to
                // report — which is not the same as forwarding no ports.
                ports: (!ports.is_empty()).then(|| json_array(ports)),
            },
        }
    }

    /// The event for a stream the cluster refused.
    pub fn rejection_event(&self, subject: &KubernetesAuditSubject, status: u16) -> AuditEvent {
        let pod = self.pod();
        AuditEvent::KubernetesStreamRejected {
            subject: subject.clone(),
            namespace: pod.namespace.clone(),
            pod: pod.pod.clone(),
            subresource: self.subresource().to_owned(),
            status,
        }
    }
}

impl MutatingOperation {
    /// One event per debug container, so each is searchable on its own.
    pub fn audit_events(
        &self,
        subject: &KubernetesAuditSubject,
        response_status: u16,
    ) -> Vec<AuditEvent> {
        match self {
            Self::EphemeralContainersUpdated { pod, containers } => containers
                .iter()
                .map(|container| AuditEvent::KubernetesDebugContainerCreated {
                    subject: subject.clone(),
                    namespace: pod.namespace.clone(),
                    pod: pod.pod.clone(),
                    debug_container: container.name.clone(),
                    image: container.image.clone(),
                    target_container: container.target_container.clone(),
                    command: json_array(&container.command),
                    tty: container.tty,
                    response_status,
                })
                .collect(),
            Self::PodCreated { namespace, pod } => vec![AuditEvent::KubernetesPodCreated {
                subject: subject.clone(),
                namespace: namespace.clone(),
                pod: pod.name.clone(),
                images: json_array(&pod.images),
                node_name: pod.node_name.clone(),
                host_pid: pod.host_pid,
                host_network: pod.host_network,
                privileged: pod.privileged,
                response_status,
            }],
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, reason = "test assertions")]
mod tests {
    use super::*;

    fn pods_path(suffix: &str) -> String {
        format!("/api/v1/namespaces/prod/pods{suffix}")
    }

    /// Classifies a `path?query` fixture the way the handler splits them.
    fn stream(suffix: &str) -> Option<StreamOperation> {
        let full = pods_path(suffix);
        full.split_once('?').map_or_else(
            || classify_stream(&full, None),
            |(path, query)| classify_stream(path, Some(query)),
        )
    }

    #[test]
    fn exec_keeps_every_command_argument() {
        // `kubectl exec pod -- ls -la` sends one `command=` per argv element.
        // Collecting the query into a map would keep exactly one of them.
        let operation =
            stream("/api-7f9/exec?command=ls&command=-la&container=api&stdin=true&tty=true")
                .unwrap();

        let StreamOperation::Exec {
            pod,
            container,
            command,
            tty,
            stdin,
        } = operation
        else {
            panic!("expected an exec, got {operation:?}");
        };
        assert_eq!(pod.namespace, "prod");
        assert_eq!(pod.pod, "api-7f9");
        assert_eq!(container.as_deref(), Some("api"));
        assert_eq!(command, vec!["ls".to_owned(), "-la".to_owned()]);
        assert!(tty);
        assert!(stdin);
    }

    #[test]
    fn exec_without_a_container_reports_none() {
        // kubectl omits `container=` for single-container pods. The API server
        // picks one, but Warpgate never learns which, so it must not invent it.
        let operation = stream("/api-7f9/exec?command=sh").unwrap();
        let StreamOperation::Exec { container, .. } = operation else {
            panic!("expected an exec");
        };
        assert_eq!(container, None);
    }

    #[test]
    fn exec_recording_metadata_carries_the_full_command() {
        let operation = stream("/api-7f9/exec?command=ls&command=-la").unwrap();
        let Some(SessionRecordingMetadata::Exec { command, .. }) = operation.recording_metadata()
        else {
            panic!("expected exec recording metadata");
        };
        assert_eq!(command, vec!["ls".to_owned(), "-la".to_owned()]);
    }

    #[test]
    fn port_forward_keeps_every_port() {
        let operation = stream("/db-0/portforward?ports=5432&ports=8080").unwrap();
        let StreamOperation::PortForward { ports, .. } = &operation else {
            panic!("expected a port forward");
        };
        assert_eq!(ports, &vec!["5432".to_owned(), "8080".to_owned()]);
        // Raw TCP, not a terminal: audited, but nothing to record.
        assert!(operation.recording_metadata().is_none());
        assert_eq!(operation.subresource(), "portforward");
    }

    #[test]
    fn port_forward_without_a_query_reports_no_ports() {
        // What kubectl actually sends over the websocket protocol: ports are
        // negotiated per stream, so the request carries no query at all.
        let operation = stream("/db-0/portforward").unwrap();
        let StreamOperation::PortForward { ports, .. } = &operation else {
            panic!("expected a port forward");
        };
        assert!(ports.is_empty());
    }

    #[test]
    fn attach_is_classified() {
        let operation = stream("/api-7f9/attach?container=api&tty=1").unwrap();
        let StreamOperation::Attach { container, tty, .. } = operation else {
            panic!("expected an attach");
        };
        assert_eq!(container.as_deref(), Some("api"));
        // The API server parses these with Go's ParseBool, so "1" is true.
        assert!(tty);
    }

    #[test]
    fn unrelated_paths_are_not_classified() {
        assert!(stream("/api-7f9/log").is_none());
        assert!(stream("").is_none());
        assert!(classify_stream("/api/v1/namespaces/prod/services/api/exec", None).is_none());
        assert!(classify_stream("/healthz", None).is_none());
        // A cluster URL path prefix must not defeat classification, which is
        // why the request path is what gets parsed.
        assert!(stream("/api-7f9/exec?command=sh").is_some());
    }

    #[test]
    fn ephemeral_container_patch_is_classified() {
        // The body `kubectl debug -it pod/api-7f9 --image=busybox --target=api`
        // sends: a strategic merge patch holding only the new container, and no
        // `command`, because the image's own entrypoint runs.
        let body = br#"{"spec":{"ephemeralContainers":[{
            "image":"busybox:1.36","imagePullPolicy":"IfNotPresent",
            "name":"debugger-8tp2k","resources":{},"stdin":true,
            "targetContainerName":"api","terminationMessagePolicy":"File","tty":true}]}}"#;

        let operation =
            classify_mutating("PATCH", &pods_path("/api-7f9/ephemeralcontainers"), body).unwrap();

        let MutatingOperation::EphemeralContainersUpdated { pod, containers } = operation else {
            panic!("expected an ephemeral container update");
        };
        assert_eq!(pod.namespace, "prod");
        assert_eq!(pod.pod, "api-7f9");
        assert_eq!(containers.len(), 1);
        let container = containers.first().unwrap();
        assert_eq!(container.name, "debugger-8tp2k");
        assert_eq!(container.image, "busybox:1.36");
        assert_eq!(container.target_container.as_deref(), Some("api"));
        assert!(container.command.is_empty());
        assert!(container.tty);
    }

    #[test]
    fn ephemeral_container_put_fallback_is_classified() {
        // The pre-1.23 path PUTs the whole pod, so the same fields arrive
        // nested in a full Pod object instead of a patch.
        let body = br#"{"kind":"Pod","apiVersion":"v1",
            "metadata":{"name":"api-7f9","namespace":"prod"},
            "spec":{"containers":[{"name":"api","image":"api:1.4"}],
            "ephemeralContainers":[{"name":"debugger-x9k2","image":"busybox",
            "command":["sh","-c","ps aux"],"targetContainerName":"api","tty":true}]}}"#;

        let operation =
            classify_mutating("PUT", &pods_path("/api-7f9/ephemeralcontainers"), body).unwrap();
        let MutatingOperation::EphemeralContainersUpdated { containers, .. } = operation else {
            panic!("expected an ephemeral container update");
        };
        let container = containers.first().unwrap();
        assert_eq!(container.name, "debugger-x9k2");
        assert_eq!(
            container.command,
            vec!["sh".to_owned(), "-c".to_owned(), "ps aux".to_owned()]
        );
    }

    #[test]
    fn explicit_nulls_still_parse() {
        // A strategic merge patch uses `null` to delete a field, so a body can
        // carry nulls where the API's own objects would omit the key.
        let body = br#"{"spec":{"ephemeralContainers":[{"name":"d","image":"i",
            "command":null,"args":null,"securityContext":null,"tty":null}]}}"#;
        let operation =
            classify_mutating("PATCH", &pods_path("/api-7f9/ephemeralcontainers"), body).unwrap();
        let MutatingOperation::EphemeralContainersUpdated { containers, .. } = operation else {
            panic!("expected an ephemeral container update");
        };
        assert_eq!(containers.first().unwrap().name, "d");
    }

    #[test]
    fn node_debugger_pod_creation_is_classified() {
        // `kubectl debug node/worker-1 --image=busybox`.
        let body = br#"{"kind":"Pod","apiVersion":"v1",
            "metadata":{"name":"node-debugger-worker-1-xk9lp"},
            "spec":{"nodeName":"worker-1","hostPID":true,"hostNetwork":true,
            "restartPolicy":"Never",
            "containers":[{"name":"debugger","image":"busybox:1.36",
            "securityContext":{"privileged":true},"stdin":true,"tty":true}]}}"#;

        let operation = classify_mutating("POST", &pods_path(""), body).unwrap();
        let MutatingOperation::PodCreated { namespace, pod } = operation else {
            panic!("expected a pod creation");
        };
        assert_eq!(namespace, "prod");
        assert_eq!(pod.name, "node-debugger-worker-1-xk9lp");
        assert_eq!(pod.images, vec!["busybox:1.36".to_owned()]);
        assert_eq!(pod.node_name.as_deref(), Some("worker-1"));
        assert!(pod.host_pid);
        assert!(pod.host_network);
        assert!(pod.privileged);
    }

    #[test]
    fn pod_summary_never_carries_environment_values() {
        // A pod spec routinely holds secrets in `env`. Nothing outside the
        // summarised fields may reach a log row.
        let body = br#"{"metadata":{"name":"copy-of-api"},
            "spec":{"containers":[{"name":"api","image":"api:1.4",
            "env":[{"name":"DB_PASSWORD","value":"hunter2-never-log-me"}],
            "envFrom":[{"secretRef":{"name":"api-secrets"}}],
            "volumeMounts":[{"name":"creds","mountPath":"/creds"}]}]}}"#;

        let operation = classify_mutating("POST", &pods_path(""), body).unwrap();
        let rendered = format!("{operation:?}");
        assert!(!rendered.contains("hunter2-never-log-me"), "{rendered}");
        assert!(!rendered.contains("DB_PASSWORD"), "{rendered}");
        assert!(!rendered.contains("api-secrets"), "{rendered}");
        assert!(!rendered.contains("/creds"), "{rendered}");
    }

    #[test]
    fn pod_created_falls_back_to_generate_name() {
        let body = br#"{"metadata":{"generateName":"debugger-"},"spec":{"containers":[]}}"#;
        let operation = classify_mutating("POST", &pods_path(""), body).unwrap();
        let MutatingOperation::PodCreated { pod, .. } = operation else {
            panic!("expected a pod creation");
        };
        assert_eq!(pod.name, "debugger-");
    }

    #[test]
    fn non_mutating_requests_are_not_classified() {
        assert!(classify_mutating("GET", &pods_path(""), b"").is_none());
        assert!(classify_mutating("POST", &pods_path("/api-7f9/exec"), b"{}").is_none());
        // A patch that adds no ephemeral container has nothing to report.
        assert!(
            classify_mutating("PATCH", &pods_path("/api-7f9/ephemeralcontainers"), b"{}").is_none()
        );
        // An unparseable body must not be reported as an empty operation.
        assert!(classify_mutating("POST", &pods_path(""), b"not json").is_none());
    }

    #[test]
    fn argv_is_rendered_as_a_json_array() {
        assert_eq!(
            json_array(&["ls".to_owned(), "-la".to_owned()]),
            r#"["ls","-la"]"#
        );
        assert_eq!(json_array(&[]), "[]");
    }

    #[test]
    fn oversized_argv_is_truncated() {
        let many: Vec<String> = (0..=MAX_LIST_ELEMENTS).map(|i| i.to_string()).collect();
        assert!(json_array(&many).contains(TRUNCATION_MARKER));

        let huge = vec!["x".repeat(MAX_LIST_BYTES + 1)];
        assert_eq!(json_array(&huge), format!("[\"{TRUNCATION_MARKER}\"]"));
    }
}

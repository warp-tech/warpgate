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

use std::borrow::Cow;

use serde::Deserialize;
use warpgate_core::logging::{AuditEvent, KubernetesAuditSubject};

use crate::recording::SessionRecordingMetadata;

/// A client controls argv, the container list, the path and the headers, so
/// bound what a single request can push into one log field.
const MAX_LIST_ELEMENTS: usize = 64;
const MAX_FIELD_BYTES: usize = 4096;
/// Appended to a field that hit either cap above.
const TRUNCATION_MARKER: &str = "<truncated>";

/// Go rejects a query of more than 10000 pairs whole, and the API server then
/// sees no `dryRun`. Real writes have a handful of pairs.
const MAX_DRY_RUN_QUERY_PAIRS: usize = 64;

/// A pod addressed by a request path.
#[derive(Debug)]
pub struct PodRef {
    pub namespace: String,
    pub pod: String,
}

/// An exec, attach or port forward against a pod.
#[derive(Debug)]
pub struct StreamOperation {
    pub pod: PodRef,
    pub kind: StreamKind,
}

#[derive(Debug)]
pub enum StreamKind {
    Exec {
        container: Option<String>,
        command: Vec<String>,
        tty: bool,
        stdin: bool,
    },
    Attach {
        container: Option<String>,
        tty: bool,
    },
    PortForward {
        ports: Vec<String>,
    },
}

#[derive(Debug)]
pub struct PodWrite {
    method: String,
    path: String,
    namespace: String,
    target: PodWriteTarget,
}

#[derive(Debug)]
enum PodWriteTarget {
    /// `POST` to the pod collection. `kubectl debug node/...` and `kubectl
    /// debug --copy-to` create their debug pod this way.
    Collection,
    /// `PATCH` or `PUT` of a pod, e.g. `kubectl apply --server-side`. A
    /// server-side apply creates the pod if it is missing and answers 201.
    Pod(String),
    /// `PATCH` or `PUT` of `ephemeralcontainers`, e.g. `kubectl debug` against
    /// a running pod.
    EphemeralContainers(String),
}

/// The parsed body of a [`PodWrite`].
#[derive(Debug)]
pub enum MutatingOperation {
    /// `containers` is empty if the body adds none, and no event is emitted.
    EphemeralContainersUpdated {
        pod: PodRef,
        containers: Vec<EphemeralContainerSummary>,
    },
    PodCreated {
        namespace: String,
        summary: PodSummary,
    },
    PodWritten {
        namespace: String,
        summary: PodSummary,
    },
    Unclassifiable(UnclassifiableRequest),
}

#[derive(Debug)]
pub struct UnclassifiableRequest {
    pub method: String,
    pub path: String,
    pub namespace: String,
    pub pod: Option<String>,
    pub content_type: Option<String>,
    pub body_length: usize,
    pub reason: &'static str,
}

#[derive(Debug)]
pub struct EphemeralContainerSummary {
    pub name: String,
    pub image: String,
    pub target_container: Option<String>,
    pub command: Vec<String>,
    pub tty: bool,
}

#[derive(Debug)]
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
/// path of every audited operation except a kubelet `/run`.
///
/// Classification reads the request path rather than the upstream URL, so a
/// target whose cluster URL carries a path prefix is audited like any other.
struct PodsPath {
    namespace: String,
    /// `None` for the collection itself, which is what a pod creation targets.
    name: Option<String>,
    subresource: Option<String>,
}

/// `api_path` must already have its `.`/`..` segments resolved, or a request
/// could name one pod here and another upstream. It is still percent-encoded:
/// the API server routes on Go's decoded `URL.Path`, so it is decoded here the
/// same way — whole, before splitting, so `%2F` separates segments as it does
/// there — and `%65xec` classifies as `exec`.
fn parse_pods_path(api_path: &str) -> Option<PodsPath> {
    let api_path = percent_encoding::percent_decode_str(api_path).decode_utf8_lossy();
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

/// The kubelet path segments of `/api/v1/nodes/{node}/proxy/{kubelet path}`.
/// `{node}` can also be `{node}:{port}` or `{scheme}:{node}:{port}`, so it is
/// not parsed.
///
/// `.` and `..` are resolved after percent-decoding. The API server joins the
/// decoded path onto the kubelet address with Go's `path.Join`, so
/// `logs%2F..%2Frun` reaches the kubelet as `/run`.
fn parse_node_proxy_path(api_path: &str) -> Option<Vec<String>> {
    let api_path = percent_encoding::percent_decode_str(api_path).decode_utf8_lossy();
    let mut segments = api_path.split('/').filter(|s| !s.is_empty());

    if segments.next()? != "api" || segments.next()? != "v1" || segments.next()? != "nodes" {
        return None;
    }
    segments.next()?;
    if segments.next()? != "proxy" {
        return None;
    }

    let mut kubelet_path = Vec::new();
    for segment in segments {
        match segment {
            "." => {}
            ".." => {
                kubelet_path.pop();
            }
            _ => kubelet_path.push(segment.to_owned()),
        }
    }
    Some(kubelet_path)
}

/// Parses a boolean query parameter like the API server does. `0` and `false`
/// are false. Every other value is true, including the empty one.
///
/// The API server matches `false` with Go's `strings.EqualFold`, which also
/// accepts `ſ` for `s`. `to_uppercase` folds the same way.
pub(crate) fn parse_bool(value: &str) -> bool {
    value != "0" && value.to_uppercase() != "FALSE"
}

/// Parses one query pair like Go's `url.ParseQuery`. `None` if Go drops it: a
/// pair containing `;` or an invalid percent escape. `form_urlencoded` alone
/// keeps both, which would report a parameter the cluster never saw.
fn query_pair(pair: &str) -> Option<(Cow<'_, str>, Cow<'_, str>)> {
    let bytes = pair.as_bytes();
    let escapes_are_valid = bytes.iter().enumerate().all(|(index, byte)| {
        *byte != b'%'
            || bytes
                .get(index + 1..index + 3)
                .is_some_and(|digits| digits.iter().all(u8::is_ascii_hexdigit))
    });
    if pair.contains(';') || !escapes_are_valid {
        return None;
    }
    url::form_urlencoded::parse(bytes).next()
}

/// The query's pairs as the API server and the kubelet parse them, with Go's
/// `url.ParseQuery`.
///
/// Recent Go rejects a whole query of more than 10000 pairs. This still
/// returns its pairs, so the audit can show more than the cluster saw.
pub fn query_pairs(raw: Option<&str>) -> impl Iterator<Item = (Cow<'_, str>, Cow<'_, str>)> {
    raw.unwrap_or_default().split('&').filter_map(query_pair)
}

struct StreamQuery {
    command: Vec<String>,
    container: Option<String>,
    ports: Vec<String>,
    tty: bool,
    stdin: bool,
}

fn parse_stream_query(raw: Option<&str>) -> StreamQuery {
    // kubectl sends one `command=` per argv element, so a list parameter keeps
    // every value.
    let all = |name: &str| {
        query_pairs(raw)
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
            .collect()
    };
    // The API server uses the first value of a repeated scalar parameter and
    // ignores the rest.
    let first = |name: &str| {
        query_pairs(raw)
            .find(|(key, _)| key == name)
            .map(|(_, value)| value)
    };

    StreamQuery {
        command: all("command"),
        ports: all("ports"),
        // The API server treats an empty `container` like a missing one.
        container: first("container")
            .filter(|name| !name.is_empty())
            .map(Cow::into_owned),
        tty: first("tty").is_some_and(|value| parse_bool(&value)),
        stdin: first("stdin").is_some_and(|value| parse_bool(&value)),
    }
}

/// A server-side dry run runs admission and answers with the object exactly as
/// a real write would, yet persists nothing, so it must not be audited as one.
///
/// A dry run is not audited, so this must never be true for a real write. Go
/// drops a query pair containing `;` or a bad percent escape. This parser
/// keeps such a pair with the junk in its key or value, so requiring exactly
/// `All` excludes it. Go also rejects an oversized query whole.
fn is_dry_run(query: Option<&str>) -> bool {
    let query = query.unwrap_or_default();
    let mut values = url::form_urlencoded::parse(query.as_bytes())
        .filter(|(key, _)| key == "dryRun")
        .map(|(_, value)| value)
        .peekable();
    query.split('&').count() <= MAX_DRY_RUN_QUERY_PAIRS
        && values.peek().is_some()
        && values.all(|value| value == "All")
}

/// The streaming operation this websocket-upgrading request performs, if it is
/// one Warpgate audits.
pub fn classify_stream(api_path: &str, query: Option<&str>) -> Option<StreamOperation> {
    let path = parse_pods_path(api_path)?;
    let (Some(name), Some(subresource)) = (path.name, path.subresource) else {
        return None;
    };
    let query = parse_stream_query(query);

    let kind = match subresource.as_str() {
        "exec" => StreamKind::Exec {
            container: query.container,
            command: query.command,
            tty: query.tty,
            stdin: query.stdin,
        },
        "attach" => StreamKind::Attach {
            container: query.container,
            tty: query.tty,
        },
        "portforward" => StreamKind::PortForward { ports: query.ports },
        _ => return None,
    };
    Some(StreamOperation {
        pod: PodRef {
            namespace: path.namespace,
            pod: name,
        },
        kind,
    })
}

/// Classifies a kubelet `/run` sent through the node proxy. It is audited as
/// an exec because it is the same act as `pods/{name}/exec`.
///
/// The kubelet's `/exec`, `/attach` and `/portForward` are not classified
/// because they cannot work through the node proxy. They need an upgrade, and
/// Warpgate forwards only websocket upgrades, whose parameters are in the
/// query. The API server drops the query when it forwards an upgrade, so the
/// kubelet refuses the request.
pub fn classify_node_run(
    method: &str,
    api_path: &str,
    query: Option<&str>,
) -> Option<StreamOperation> {
    if method != "POST" {
        return None;
    }
    let path = parse_node_proxy_path(api_path)?;
    // `run/{namespace}/{pod}/{container}`, optionally with `{uid}` before
    // `{container}`. The kubelet looks the pod up by name in both forms.
    let (namespace, pod, container) = match path.as_slice() {
        [run, namespace, pod, container] | [run, namespace, pod, _, container] if run == "run" => {
            (namespace, pod, container)
        }
        _ => return None,
    };
    // The kubelet runs the first `cmd`, split on single spaces with no quoting.
    let cmd = query_pairs(query)
        .find(|(key, _)| key == "cmd")
        .map(|(_, value)| value)
        .unwrap_or_default();

    Some(StreamOperation {
        pod: PodRef {
            namespace: namespace.clone(),
            pod: pod.clone(),
        },
        kind: StreamKind::Exec {
            container: Some(container.clone()),
            command: cmd.split(' ').map(ToOwned::to_owned).collect(),
            tty: false,
            stdin: false,
        },
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
    init_containers: Option<Vec<ContainerBody>>,
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
    /// Includes init containers, which can be privileged too.
    fn containers(&self) -> impl Iterator<Item = &ContainerBody> {
        self.spec
            .iter()
            .flat_map(|s| s.init_containers.iter().chain(&s.containers))
            .flatten()
    }

    fn summarise(&self) -> PodSummary {
        let metadata = self.metadata.as_ref();
        PodSummary {
            // A pod created with `generateName` has no name yet; the prefix is
            // more useful than nothing.
            name: metadata
                .and_then(|m| m.name.clone().or_else(|| m.generate_name.clone()))
                .unwrap_or_default(),
            images: self.containers().filter_map(|c| c.image.clone()).collect(),
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
            privileged: self.containers().any(|c| {
                c.security_context
                    .as_ref()
                    .and_then(|s| s.privileged)
                    .unwrap_or_default()
            }),
        }
    }
}

/// The error is a fixed string because serde's message would quote the body.
///
/// The `{` check is needed because a derived struct also deserialises from an
/// array, field by field, so a JSON Patch would parse as an empty pod. Nested
/// arrays are not checked: the API server rejects those requests. A duplicate
/// key is an error here, while the API server takes the last one.
fn parse_pod_body(body: &[u8]) -> Result<PodBody, &'static str> {
    if !body.trim_ascii_start().starts_with(b"{") {
        return Err("body is not a JSON object");
    }
    serde_json::from_slice(body).map_err(|_| "body is not a Pod object")
}

/// `None` if this is not a pod write Warpgate audits. The decision uses only
/// the request line, never the body.
pub fn classify_pod_write(method: &str, api_path: &str, query: Option<&str>) -> Option<PodWrite> {
    let PodsPath {
        namespace,
        name,
        subresource,
    } = parse_pods_path(api_path)?;
    if is_dry_run(query) {
        return None;
    }

    let target = match (method, name, subresource.as_deref()) {
        ("POST", None, None) => PodWriteTarget::Collection,
        ("PATCH" | "PUT", Some(pod), None) => PodWriteTarget::Pod(pod),
        ("PATCH" | "PUT", Some(pod), Some("ephemeralcontainers")) => {
            PodWriteTarget::EphemeralContainers(pod)
        }
        _ => return None,
    };
    Some(PodWrite {
        method: method.to_owned(),
        path: api_path.to_owned(),
        namespace,
        target,
    })
}

impl PodWrite {
    /// Only JSON object bodies are parsed. `kubectl` sends those, including
    /// for a server-side apply with its YAML content type. Any other body
    /// returns [`MutatingOperation::Unclassifiable`].
    pub fn read(self, content_type: Option<&str>, body: &[u8]) -> MutatingOperation {
        let parsed = match parse_pod_body(body) {
            Ok(parsed) => parsed,
            Err(reason) => {
                return MutatingOperation::Unclassifiable(UnclassifiableRequest {
                    method: self.method,
                    path: self.path,
                    namespace: self.namespace,
                    pod: match self.target {
                        PodWriteTarget::Collection => None,
                        PodWriteTarget::Pod(pod) | PodWriteTarget::EphemeralContainers(pod) => {
                            Some(pod)
                        }
                    },
                    content_type: content_type.map(ToOwned::to_owned),
                    body_length: body.len(),
                    reason,
                });
            }
        };

        let namespace = self.namespace;
        match self.target {
            PodWriteTarget::Collection => MutatingOperation::PodCreated {
                namespace,
                summary: parsed.summarise(),
            },
            PodWriteTarget::Pod(name) => MutatingOperation::PodWritten {
                namespace,
                // A patch body may omit the name. The API server uses the one
                // in the path.
                summary: PodSummary {
                    name,
                    ..parsed.summarise()
                },
            },
            // `kubectl` since 1.23 sends a strategic merge PATCH whose body
            // holds only the newly added container. The older fallback PUTs
            // the whole pod, so its body also repeats containers that were
            // already there and those are audited again — over-reporting a
            // debug container beats missing one.
            PodWriteTarget::EphemeralContainers(pod) => {
                MutatingOperation::EphemeralContainersUpdated {
                    pod: PodRef { namespace, pod },
                    containers: parsed
                        .spec
                        .iter()
                        .flat_map(|s| s.ephemeral_containers.iter().flatten())
                        .map(ContainerBody::summarise_ephemeral)
                        .collect(),
                }
            }
        }
    }
}

// ---------- Event and recording construction ----------

/// Renders a list as a JSON array for a single log field, bounded so a client
/// cannot make a log row arbitrarily large.
fn json_array(values: &[String]) -> String {
    let mut kept: Vec<&str> = Vec::new();
    let mut budget = MAX_FIELD_BYTES;
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

/// Truncates a client-controlled string to [`MAX_FIELD_BYTES`].
fn bounded(value: &str) -> String {
    if value.len() <= MAX_FIELD_BYTES {
        return value.to_owned();
    }
    let (kept, _) = value.split_at(value.floor_char_boundary(MAX_FIELD_BYTES));
    format!("{kept}{TRUNCATION_MARKER}")
}

impl StreamKind {
    pub const fn subresource(&self) -> &'static str {
        match self {
            Self::Exec { .. } => "exec",
            Self::Attach { .. } => "attach",
            Self::PortForward { .. } => "portforward",
        }
    }
}

impl StreamOperation {
    /// The recording to open for this operation, if it produces a terminal
    /// stream. Port forwarding carries raw TCP rather than a terminal, so it is
    /// audited but not recorded here.
    pub fn recording_metadata(&self) -> Option<SessionRecordingMetadata> {
        let namespace = self.pod.namespace.clone();
        let pod = self.pod.pod.clone();
        match &self.kind {
            StreamKind::Exec {
                container, command, ..
            } => Some(SessionRecordingMetadata::Exec {
                namespace,
                pod,
                container: container.clone(),
                command: command.clone(),
            }),
            StreamKind::Attach { container, .. } => Some(SessionRecordingMetadata::Attach {
                namespace,
                pod,
                container: container.clone(),
            }),
            StreamKind::PortForward { .. } => None,
        }
    }

    pub fn audit_event(&self, subject: &KubernetesAuditSubject) -> AuditEvent {
        let subject = subject.clone();
        let namespace = self.pod.namespace.clone();
        let pod = self.pod.pod.clone();
        match &self.kind {
            StreamKind::Exec {
                container,
                command,
                tty,
                stdin,
            } => AuditEvent::KubernetesExecStarted {
                subject,
                namespace,
                pod,
                container: container.clone(),
                command: json_array(command),
                tty: *tty,
                stdin: *stdin,
            },
            StreamKind::Attach { container, tty } => AuditEvent::KubernetesAttachStarted {
                subject,
                namespace,
                pod,
                container: container.clone(),
                tty: *tty,
            },
            StreamKind::PortForward { ports } => AuditEvent::KubernetesPortForwardStarted {
                subject,
                namespace,
                pod,
                // Absent rather than empty: the websocket protocol negotiates
                // ports per stream and sends no query, so there is nothing to
                // report — which is not the same as forwarding no ports.
                ports: (!ports.is_empty()).then(|| json_array(ports)),
            },
        }
    }

    /// The event for an operation the cluster refused.
    pub fn rejection_event(&self, subject: &KubernetesAuditSubject, status: u16) -> AuditEvent {
        AuditEvent::KubernetesStreamRejected {
            subject: subject.clone(),
            namespace: self.pod.namespace.clone(),
            pod: self.pod.pod.clone(),
            subresource: self.kind.subresource().to_owned(),
            status,
        }
    }
}

/// Emits the audit event for a kubelet `/run` when dropped.
///
/// A client that disconnects mid-command cancels the handler, but the command
/// has already started. Emitting on drop covers that case.
///
/// Only a 4xx is reported as rejected, because the cluster sends it before
/// running anything. The kubelet answers 500 for a command that ran and
/// failed, and a missing answer does not prove the command did not run.
pub struct PendingRun {
    run: StreamOperation,
    subject: KubernetesAuditSubject,
    status: Option<u16>,
}

impl PendingRun {
    pub fn new(run: StreamOperation, subject: &KubernetesAuditSubject) -> Self {
        Self {
            run,
            subject: subject.clone(),
            status: None,
        }
    }

    /// Records the cluster's answer and emits the event.
    pub fn answered(mut self, status: u16) {
        self.status = Some(status);
    }

    fn event(&self) -> AuditEvent {
        match self.status {
            Some(status @ 400..=499) => self.run.rejection_event(&self.subject, status),
            _ => self.run.audit_event(&self.subject),
        }
    }
}

impl Drop for PendingRun {
    fn drop(&mut self) {
        self.event().emit();
    }
}

impl MutatingOperation {
    /// One event per debug container, so each is searchable on its own.
    ///
    /// `response_status` is `None` if the cluster sent no response. Events are
    /// still returned because the write may have been applied.
    pub fn audit_events(
        &self,
        subject: &KubernetesAuditSubject,
        response_status: Option<u16>,
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
            Self::PodCreated { namespace, summary } | Self::PodWritten { namespace, summary } => {
                vec![AuditEvent::KubernetesPodWritten {
                    subject: subject.clone(),
                    // A PATCH or PUT created the pod only if the cluster
                    // answered 201, e.g. a server-side apply of a missing pod.
                    created: matches!(self, Self::PodCreated { .. })
                        || response_status == Some(201),
                    namespace: namespace.clone(),
                    pod: summary.name.clone(),
                    images: json_array(&summary.images),
                    node_name: summary.node_name.clone(),
                    host_pid: summary.host_pid,
                    host_network: summary.host_network,
                    privileged: summary.privileged,
                    response_status,
                }]
            }
            Self::Unclassifiable(request) => vec![AuditEvent::KubernetesUnknownRequest {
                subject: subject.clone(),
                method: request.method.clone(),
                path: bounded(&request.path),
                namespace: bounded(&request.namespace),
                pod: request.pod.as_deref().map(bounded),
                content_type: request.content_type.as_deref().map(bounded),
                body_length: request.body_length,
                reason: request.reason,
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

    fn mutating(method: &str, suffix: &str, body: &[u8]) -> Option<MutatingOperation> {
        classify_pod_write(method, &pods_path(suffix), None).map(|write| write.read(None, body))
    }

    fn unclassifiable(operation: Option<MutatingOperation>) -> UnclassifiableRequest {
        match operation {
            Some(MutatingOperation::Unclassifiable(request)) => request,
            other => panic!("expected an unclassifiable request, got {other:?}"),
        }
    }

    fn subject() -> KubernetesAuditSubject {
        KubernetesAuditSubject {
            session_id: uuid::Uuid::nil(),
            user_id: warpgate_common::UserId(uuid::Uuid::nil()),
            username: "alice".to_owned(),
            target_id: warpgate_common::TargetId(uuid::Uuid::nil()),
            target_name: "cluster".to_owned(),
        }
    }

    fn node_run(suffix: &str) -> Option<StreamOperation> {
        let full = format!("/api/v1/nodes/worker-1/proxy{suffix}");
        full.split_once('?').map_or_else(
            || classify_node_run("POST", &full, None),
            |(path, query)| classify_node_run("POST", path, Some(query)),
        )
    }

    fn run_command(suffix: &str) -> Vec<String> {
        let StreamKind::Exec { command, .. } = node_run(suffix).unwrap().kind else {
            panic!("expected an exec");
        };
        command
    }

    #[test]
    fn exec_keeps_every_command_argument() {
        // `kubectl exec pod -- ls -la` sends one `command=` per argv element.
        let operation =
            stream("/api-7f9/exec?command=ls&command=-la&container=api&stdin=true&tty=true")
                .unwrap();

        assert_eq!(operation.pod.namespace, "prod");
        assert_eq!(operation.pod.pod, "api-7f9");
        let StreamKind::Exec {
            container,
            command,
            tty,
            stdin,
        } = operation.kind
        else {
            panic!("expected an exec, got {:?}", operation.kind);
        };
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
        let StreamKind::Exec { container, .. } = operation.kind else {
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
        let StreamKind::PortForward { ports } = &operation.kind else {
            panic!("expected a port forward");
        };
        assert_eq!(ports, &vec!["5432".to_owned(), "8080".to_owned()]);
        // Raw TCP, not a terminal: audited, but nothing to record.
        assert!(operation.recording_metadata().is_none());
        assert_eq!(operation.kind.subresource(), "portforward");
    }

    #[test]
    fn port_forward_without_a_query_reports_no_ports() {
        // What kubectl actually sends over the websocket protocol: ports are
        // negotiated per stream, so the request carries no query at all.
        let operation = stream("/db-0/portforward").unwrap();
        let StreamKind::PortForward { ports } = &operation.kind else {
            panic!("expected a port forward");
        };
        assert!(ports.is_empty());
    }

    #[test]
    fn attach_is_classified() {
        let operation = stream("/api-7f9/attach?container=api&tty=1").unwrap();
        let StreamKind::Attach { container, tty } = operation.kind else {
            panic!("expected an attach");
        };
        assert_eq!(container.as_deref(), Some("api"));
        assert!(tty);
    }

    #[test]
    fn repeated_scalars_are_read_as_the_api_server_reads_them() {
        // The API server uses the first of each: `api`, no terminal, stdin.
        let operation = stream(
            "/api-7f9/exec?container=api&container=decoy&tty=0&tty=1&stdin=1&stdin=0&command=id",
        )
        .unwrap();
        let StreamKind::Exec {
            container,
            tty,
            stdin,
            ..
        } = operation.kind
        else {
            panic!("expected an exec");
        };
        assert_eq!(container.as_deref(), Some("api"));
        assert!(!tty);
        assert!(stdin);

        // Go drops the `;` pair, so `api` is the first container.
        let operation = stream("/api-7f9/attach?container=decoy;&container=api").unwrap();
        let StreamKind::Attach { container, .. } = operation.kind else {
            panic!("expected an attach");
        };
        assert_eq!(container.as_deref(), Some("api"));

        // An empty first `container` counts as none. The second is ignored.
        let operation = stream("/api-7f9/exec?container=&container=decoy&command=id").unwrap();
        let StreamKind::Exec { container, .. } = operation.kind else {
            panic!("expected an exec");
        };
        assert_eq!(container, None);
    }

    #[test]
    fn booleans_are_read_as_the_api_server_reads_them() {
        for value in ["0", "false", "False", "FALSE", "falſe"] {
            assert!(!parse_bool(value), "{value:?}");
        }
        for value in ["1", "true", "", "yes", "no", "f", "00", " false"] {
            assert!(parse_bool(value), "{value:?}");
        }

        // Absent is false; present but empty is true.
        let tty = |suffix| match stream(suffix).unwrap().kind {
            StreamKind::Attach { tty, .. } => tty,
            kind => panic!("expected an attach, got {kind:?}"),
        };
        assert!(!tty("/api-7f9/attach"));
        assert!(tty("/api-7f9/attach?tty"));
        assert!(tty("/api-7f9/attach?tty="));
    }

    #[test]
    fn unrelated_paths_are_not_classified() {
        assert!(stream("/api-7f9/log").is_none());
        assert!(stream("").is_none());
        assert!(classify_stream("/api/v1/namespaces/prod/services/api/exec", None).is_none());
        assert!(classify_stream("/healthz", None).is_none());
    }

    #[test]
    fn percent_encoded_path_classifies_as_the_api_server_routes_it() {
        let operation =
            classify_stream("/api/v1/namespaces/%70rod/%70ods/api-7f9/%65xec", None).unwrap();
        assert_eq!(operation.pod.namespace, "prod");
        assert_eq!(operation.pod.pod, "api-7f9");
        assert!(matches!(operation.kind, StreamKind::Exec { .. }));

        let operation =
            classify_stream("/api/v1/namespaces/prod/pods%2Fapi-7f9/attach", None).unwrap();
        assert!(matches!(operation.kind, StreamKind::Attach { .. }));
        assert!(stream("/api-7f9/exec?command=sh").is_some());
    }

    #[test]
    fn kubelet_run_is_classified_as_an_exec() {
        let operation = node_run("/run/prod/api-7f9/api?cmd=cat%20/etc/shadow").unwrap();

        assert_eq!(operation.pod.namespace, "prod");
        assert_eq!(operation.pod.pod, "api-7f9");
        let StreamKind::Exec {
            container,
            command,
            tty,
            stdin,
        } = &operation.kind
        else {
            panic!("expected an exec, got {:?}", operation.kind);
        };
        assert_eq!(container.as_deref(), Some("api"));
        assert_eq!(command, &vec!["cat".to_owned(), "/etc/shadow".to_owned()]);
        assert!(!tty);
        assert!(!stdin);
        assert!(matches!(
            operation.audit_event(&subject()),
            AuditEvent::KubernetesExecStarted { .. }
        ));
    }

    #[test]
    fn kubelet_run_command_is_the_argv_the_kubelet_runs() {
        // Only the first `cmd` counts. It is split on every single space.
        assert_eq!(
            run_command("/run/prod/api-7f9/api?cmd=echo+a++b&cmd=id"),
            vec!["echo", "a", "", "b"]
        );
        // Go drops a pair containing `;`, so the kubelet never sees the decoy.
        assert_eq!(
            run_command("/run/prod/api-7f9/api?cmd=true;&cmd=id"),
            vec!["id"]
        );
        // With no `cmd` the kubelet tries to run an empty command and fails.
        assert_eq!(run_command("/run/prod/api-7f9/api"), vec![""]);
    }

    #[test]
    fn kubelet_run_path_is_read_as_the_api_server_relays_it() {
        for suffix in [
            // The pod's UID can precede the container.
            "/run/prod/api-7f9/2f6c1c0e/api",
            "/%72un//prod/api-7f9/api/",
            // The API server resolves these `..` after decoding. The handler's
            // `Url::parse` normalisation does not see them.
            "/logs%2F..%2Frun/prod/api-7f9/api",
            "/run/prod/api-7f9/other%2F..%2Fapi",
            // `..` cannot go above the kubelet's root.
            "/../../run/prod/api-7f9/api",
        ] {
            let operation = node_run(suffix).unwrap_or_else(|| panic!("{suffix} is a run"));
            assert_eq!(operation.pod.namespace, "prod", "{suffix}");
            assert_eq!(operation.pod.pod, "api-7f9", "{suffix}");
            let StreamKind::Exec { container, .. } = operation.kind else {
                panic!("expected an exec");
            };
            assert_eq!(container.as_deref(), Some("api"), "{suffix}");
        }

        // `{scheme}:{node}:{port}` addresses the same kubelet.
        assert!(
            classify_node_run(
                "POST",
                "/api/v1/nodes/https:worker-1:10250/proxy/run/prod/api-7f9/api",
                None
            )
            .is_some()
        );
    }

    #[test]
    fn other_node_proxy_requests_are_not_runs() {
        // The kubelet only serves `/run` for `POST`.
        assert!(
            classify_node_run("GET", "/api/v1/nodes/worker-1/proxy/run/prod/api/api", None)
                .is_none()
        );
        assert!(node_run("/exec/prod/api-7f9/api?command=id").is_none());
        assert!(node_run("/RUN/prod/api-7f9/api").is_none());
        assert!(node_run("/logs/run/prod/api-7f9/api").is_none());
        assert!(node_run("/run/prod/api-7f9").is_none());
        assert!(node_run("/run/prod/api-7f9/uid/api/extra").is_none());
        assert!(node_run("/run/prod/api-7f9/api/..").is_none());
        assert!(node_run("").is_none());
        for path in [
            "/api/v1/nodes/worker-1/run/prod/api-7f9/api",
            "/api/v1/namespaces/prod/pods/api-7f9/proxy/run/prod/api-7f9/api",
            "/apis/v1/nodes/worker-1/proxy/run/prod/api-7f9/api",
        ] {
            assert!(classify_node_run("POST", path, None).is_none(), "{path}");
        }
    }

    #[test]
    fn pending_run_is_rejected_only_when_the_cluster_refused_it() {
        let event_for = |status| {
            let mut pending = PendingRun::new(
                node_run("/run/prod/api-7f9/api?cmd=id").unwrap(),
                &subject(),
            );
            pending.status = status;
            pending.event()
        };

        assert!(matches!(
            event_for(Some(200)),
            AuditEvent::KubernetesExecStarted { .. }
        ));
        // The kubelet answers 500 for a command that ran and exited non-zero.
        assert!(matches!(
            event_for(Some(500)),
            AuditEvent::KubernetesExecStarted { .. }
        ));
        // The handler ended before an answer arrived.
        assert!(matches!(
            event_for(None),
            AuditEvent::KubernetesExecStarted { .. }
        ));
        assert!(matches!(
            event_for(Some(403)),
            AuditEvent::KubernetesStreamRejected { status: 403, .. }
        ));
        assert!(matches!(
            event_for(Some(404)),
            AuditEvent::KubernetesStreamRejected { status: 404, .. }
        ));
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

        let operation = mutating("PATCH", "/api-7f9/ephemeralcontainers", body).unwrap();

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

        let operation = mutating("PUT", "/api-7f9/ephemeralcontainers", body).unwrap();
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
        let operation = mutating("PATCH", "/api-7f9/ephemeralcontainers", body).unwrap();
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

        let operation = mutating("POST", "", body).unwrap();
        let MutatingOperation::PodCreated { namespace, summary } = operation else {
            panic!("expected a pod creation");
        };
        assert_eq!(namespace, "prod");
        assert_eq!(summary.name, "node-debugger-worker-1-xk9lp");
        assert_eq!(summary.images, vec!["busybox:1.36".to_owned()]);
        assert_eq!(summary.node_name.as_deref(), Some("worker-1"));
        assert!(summary.host_pid);
        assert!(summary.host_network);
        assert!(summary.privileged);
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

        let operation = mutating("POST", "", body).unwrap();
        let rendered = format!("{operation:?}");
        assert!(!rendered.contains("hunter2-never-log-me"), "{rendered}");
        assert!(!rendered.contains("DB_PASSWORD"), "{rendered}");
        assert!(!rendered.contains("api-secrets"), "{rendered}");
        assert!(!rendered.contains("/creds"), "{rendered}");
    }

    #[test]
    fn pod_created_falls_back_to_generate_name() {
        let body = br#"{"metadata":{"generateName":"debugger-"},"spec":{"containers":[]}}"#;
        let operation = mutating("POST", "", body).unwrap();
        let MutatingOperation::PodCreated { summary, .. } = operation else {
            panic!("expected a pod creation");
        };
        assert_eq!(summary.name, "debugger-");
    }

    #[test]
    fn dry_runs_are_not_audited() {
        // `kubectl apply --dry-run=server` gets a 201 and the object back
        // without anything being created.
        let audited =
            |query: &str| classify_pod_write("POST", &pods_path(""), Some(query)).is_some();
        assert!(!audited("dryRun=All"));
        assert!(!audited(
            "dryRun=All&fieldManager=kubectl&fieldValidation=Strict"
        ));
        assert!(!audited("dryRun=%41ll"));
        assert!(audited("fieldManager=kubectl"));
        // The API server rejects these values, so they are audited.
        assert!(audited("dryRun="));
        assert!(audited("dryRun=all"));
        assert!(audited("dryRun=All&dryRun="));
    }

    #[test]
    fn dry_run_the_api_server_would_not_see_is_audited() {
        // Go drops a pair containing `;` or a bad escape, and rejects a query
        // of more than 10000 pairs whole. Each of these is a real write.
        let audited =
            |query: &str| classify_pod_write("POST", &pods_path(""), Some(query)).is_some();
        assert!(audited("dryRun=All;"));
        assert!(audited("dryRun=All;foo"));
        assert!(audited("dryRun=All%zz"));
        assert!(audited("dryRun=All%4"));
        assert!(audited("dry%zzRun=All"));
        assert!(audited(&format!("dryRun=All{}", "&a=1".repeat(10_000))));
        assert!(audited(&format!("dryRun=All{}", "&".repeat(10_000))));
    }

    #[test]
    fn non_mutating_requests_are_not_classified() {
        assert!(mutating("GET", "", b"").is_none());
        assert!(mutating("POST", "/api-7f9/exec", b"{}").is_none());
        // A patch that adds no ephemeral container has nothing to report.
        let operation = mutating("PATCH", "/api-7f9/ephemeralcontainers", b"{}").unwrap();
        assert!(operation.audit_events(&subject(), Some(200)).is_empty());
        // These are not audited, so the body is never parsed.
        assert!(mutating("PATCH", "/api-7f9/status", b"not json").is_none());
        assert!(mutating("DELETE", "/api-7f9", b"not json").is_none());
    }

    #[test]
    fn unreadable_body_on_an_audited_path_is_unclassifiable() {
        // An unparseable body must be reported, and not as an empty operation.
        let request = unclassifiable(mutating("POST", "", b"not json"));
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, pods_path(""));
        assert_eq!(request.namespace, "prod");
        assert_eq!(request.pod, None);
        assert_eq!(request.body_length, 8);
        assert_eq!(request.reason, "body is not a JSON object");

        // The API server also accepts YAML bodies.
        let yaml = b"spec:\n  ephemeralContainers:\n  - name: d\n    image: busybox\n";
        let request = unclassifiable(
            classify_pod_write("PATCH", &pods_path("/api-7f9/ephemeralcontainers"), None)
                .map(|write| write.read(Some("application/yaml"), yaml)),
        );
        assert_eq!(request.pod.as_deref(), Some("api-7f9"));
        assert_eq!(request.content_type.as_deref(), Some("application/yaml"));
        assert_eq!(request.reason, "body is not a JSON object");

        let events = MutatingOperation::Unclassifiable(request).audit_events(&subject(), Some(200));
        assert!(matches!(
            events.as_slice(),
            [AuditEvent::KubernetesUnknownRequest {
                response_status: Some(200),
                ..
            }]
        ));
    }

    #[test]
    fn unclassified_fields_are_bounded() {
        // The client controls the path and the content type.
        let long = "a".repeat(MAX_FIELD_BYTES * 4);
        let operation =
            classify_pod_write("POST", &format!("/api/v1/namespaces/{long}/pods"), None)
                .unwrap()
                .read(Some(&long), b"not json");
        let events = operation.audit_events(&subject(), Some(400));
        let [
            AuditEvent::KubernetesUnknownRequest {
                path,
                namespace,
                content_type,
                ..
            },
        ] = events.as_slice()
        else {
            panic!("expected one unclassified request");
        };
        let cap = MAX_FIELD_BYTES + TRUNCATION_MARKER.len();
        assert_eq!(path.len(), cap);
        assert_eq!(namespace.len(), cap);
        assert_eq!(content_type.as_ref().unwrap().len(), cap);
        assert!(path.ends_with(TRUNCATION_MARKER));

        // Truncation never splits a character.
        assert!(bounded(&"é".repeat(MAX_FIELD_BYTES)).ends_with(TRUNCATION_MARKER));
    }

    #[test]
    fn json_patch_array_is_unclassifiable() {
        // serde fills a derived struct from an array field by field, so a JSON
        // Patch of one or two operations would parse as an empty pod.
        let add = r#"{"op":"add","path":"/spec/ephemeralContainers/-",
            "value":{"name":"d","image":"busybox"}}"#;
        for body in [
            "[]".to_owned(),
            format!("[{add}]"),
            format!("[{add},{add}]"),
            format!("[{add},{add},{add}]"),
        ] {
            let request = unclassifiable(mutating(
                "PATCH",
                "/api-7f9/ephemeralcontainers",
                body.as_bytes(),
            ));
            assert_eq!(request.reason, "body is not a JSON object", "{body}");
        }
        assert_eq!(
            unclassifiable(mutating("PATCH", "/api-7f9", b" []")).reason,
            "body is not a JSON object"
        );
        assert_eq!(
            unclassifiable(mutating("POST", "", br#"{"spec":"nope"}"#)).reason,
            "body is not a Pod object"
        );
    }

    #[test]
    fn duplicate_keys_are_unclassifiable() {
        // The API server takes the last `spec`. Warpgate does not guess and
        // treats the body as unreadable.
        let body = br#"{"spec":{"ephemeralContainers":[]},
            "spec":{"ephemeralContainers":[{"name":"d","image":"busybox"}]}}"#;
        let request = unclassifiable(mutating("PATCH", "/api-7f9/ephemeralcontainers", body));
        assert_eq!(request.reason, "body is not a Pod object");
    }

    #[test]
    fn server_side_apply_is_classified() {
        // `kubectl apply --server-side` PATCHes the named pod with a JSON body
        // under a YAML content type.
        let body = br#"{"apiVersion":"v1","kind":"Pod",
            "metadata":{"name":"api-7f9","namespace":"prod"},
            "spec":{"hostPID":true,"containers":[{"name":"api","image":"api:1.5",
            "securityContext":{"privileged":true}}]}}"#;
        let operation = classify_pod_write(
            "PATCH",
            &pods_path("/api-7f9"),
            Some("fieldManager=kubectl"),
        )
        .unwrap()
        .read(Some("application/apply-patch+yaml"), body);
        let MutatingOperation::PodWritten { namespace, summary } = &operation else {
            panic!("expected a pod write, got {operation:?}");
        };
        assert_eq!(namespace, "prod");
        assert_eq!(summary.name, "api-7f9");
        assert_eq!(summary.images, vec!["api:1.5".to_owned()]);

        // The apply created the pod only if the status is 201.
        assert!(matches!(
            operation.audit_events(&subject(), Some(201)).as_slice(),
            [AuditEvent::KubernetesPodWritten { created: true, .. }]
        ));
        assert!(matches!(
            operation.audit_events(&subject(), Some(200)).as_slice(),
            [AuditEvent::KubernetesPodWritten { created: false, .. }]
        ));
        // A refused apply is logged with the same fields as a refused creation.
        assert!(matches!(
            operation.audit_events(&subject(), Some(403)).as_slice(),
            [AuditEvent::KubernetesPodWritten {
                created: false,
                privileged: true,
                host_pid: true,
                response_status: Some(403),
                ..
            }]
        ));
        // A refused POST is still logged as a creation.
        let created = mutating("POST", "", body).unwrap();
        assert!(matches!(
            created.audit_events(&subject(), Some(403)).as_slice(),
            [AuditEvent::KubernetesPodWritten { created: true, .. }]
        ));
    }

    #[test]
    fn write_without_an_answer_is_still_reported() {
        // The upstream connection failed after the request went out, so the
        // cluster may have applied it.
        let body = br#"{"spec":{"ephemeralContainers":[{"name":"d","image":"busybox"}]}}"#;
        let debug = mutating("PATCH", "/api-7f9/ephemeralcontainers", body).unwrap();
        assert!(matches!(
            debug.audit_events(&subject(), None).as_slice(),
            [AuditEvent::KubernetesDebugContainerCreated {
                response_status: None,
                ..
            }]
        ));
        let unreadable = mutating("POST", "", b"not json").unwrap();
        assert!(matches!(
            unreadable.audit_events(&subject(), None).as_slice(),
            [AuditEvent::KubernetesUnknownRequest {
                response_status: None,
                ..
            }]
        ));
    }

    #[test]
    fn pod_write_takes_its_name_from_the_path() {
        // `kubectl set image` sends a patch without the pod name.
        let body = br#"{"spec":{"containers":[{"name":"api","image":"evil:1"}]}}"#;
        let operation = mutating("PATCH", "/api-7f9", body).unwrap();
        let MutatingOperation::PodWritten { summary, .. } = operation else {
            panic!("expected a pod write, got {operation:?}");
        };
        assert_eq!(summary.name, "api-7f9");
        assert_eq!(summary.images, vec!["evil:1".to_owned()]);
    }

    #[test]
    fn init_containers_count_towards_the_summary() {
        let body = br#"{"metadata":{"name":"x"},"spec":{
            "initContainers":[{"name":"setup","image":"setup:1",
            "securityContext":{"privileged":true}}],
            "containers":[{"name":"api","image":"api:1.4"}]}}"#;
        let operation = mutating("POST", "", body).unwrap();
        let MutatingOperation::PodCreated { summary, .. } = operation else {
            panic!("expected a pod creation, got {operation:?}");
        };
        assert!(summary.privileged);
        assert_eq!(
            summary.images,
            vec!["setup:1".to_owned(), "api:1.4".to_owned()]
        );
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

        let huge = vec!["x".repeat(MAX_FIELD_BYTES + 1)];
        assert_eq!(json_array(&huge), format!("[\"{TRUNCATION_MARKER}\"]"));
    }
}

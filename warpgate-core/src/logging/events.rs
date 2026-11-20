use std::fmt::Display;
use std::net::IpAddr;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::info;
use uuid::Uuid;
use warpgate_common::auth::ApprovalKind;
use warpgate_common::helpers::logging::format_related_ids;
use warpgate_common::{RoleId, RowId, TargetId, UserId, UserSessionId};
use warpgate_resources::ResourceKind;

use crate::resources::audit::{ChangedBy, ResourceChange, RowKind, Subject};

/// What happened to a session's request for an administrator's approval
#[derive(Clone, Copy)]
pub enum SessionApprovalStep {
    Requested,
    TimedOut,
    /// Skipped, because an earlier approval is still within its grace period
    Bypassed,
}

#[derive(Clone, Copy)]
pub enum CredentialChange {
    Created,
    Updated,
    Deleted,
}

#[derive(Clone)]
pub enum CredentialChangedVia {
    Admin,
    SelfService,
}

impl Display for CredentialChangedVia {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Admin => write!(f, "admin"),
            Self::SelfService => write!(f, "self-service"),
        }
    }
}

/// Who acted, and on which target. Every Kubernetes audit event carries exactly
/// this identity, built once per request.
#[derive(Clone)]
pub struct KubernetesAuditSubject {
    pub session_id: Uuid,
    pub user_id: UserId,
    pub username: String,
    pub target_id: TargetId,
    pub target_name: String,
}

#[derive(Clone)]
pub enum AuditEvent {
    CredentialChanged {
        change: CredentialChange,
        credential_type: String,
        credential_name: Option<String>,
        via: CredentialChangedVia,
        user_id: UserId,
        username: String,
        actor_user_id: UserId,
    },
    UserCreated {
        user_id: UserId,
        username: String,
        actor_user_id: UserId,
    },
    UserDeleted {
        user_id: UserId,
        username: String,
        actor_user_id: UserId,
    },
    UserLdapLinkChanged {
        user_id: UserId,
        username: String,
        /// `None` once unlinked
        ldap_server_id: Option<Uuid>,
        actor_user_id: UserId,
    },
    TargetSessionStarted {
        session_id: Uuid,
        target_name: String,
        target_id: TargetId,
        user_id: UserId,
        username: String,
    },
    TargetSessionEnded {
        session_id: Uuid,
        target_name: String,
        target_id: TargetId,
        user_id: UserId,
        username: String,
    },
    AccessRoleGranted {
        grantee_id: UserId,
        grantee_username: String,
        role_id: RoleId,
        role_name: String,
        /// `None` for a permanent grant
        expires_at: Option<OffsetDateTime>,
        actor_user_id: UserId,
        related_access_roles: String,
    },
    AccessRoleRevoked {
        grantee_id: UserId,
        grantee_username: String,
        role_id: RoleId,
        role_name: String,
        actor_user_id: UserId,
        related_access_roles: String,
    },
    AdminRoleGranted {
        grantee_id: UserId,
        grantee_username: String,
        admin_role_id: Uuid,
        admin_role_name: String,
        actor_user_id: UserId,
        related_admin_roles: String,
    },
    AdminRoleRevoked {
        grantee_id: UserId,
        grantee_username: String,
        admin_role_id: Uuid,
        admin_role_name: String,
        actor_user_id: UserId,
        related_admin_roles: String,
    },
    /// A renewal also clears a revocation
    AccessRoleExpiryChanged {
        grantee_id: UserId,
        grantee_username: String,
        role_id: RoleId,
        role_name: String,
        expires_at: Option<OffsetDateTime>,
        revocation_cleared: bool,
        actor_user_id: UserId,
    },
    /// An admin or a provider sync assigned a role to a target or removed it
    TargetRoleChanged {
        added: bool,
        target_id: TargetId,
        target_name: String,
        role_id: RoleId,
        role_name: String,
        by: ChangedBy,
    },
    // currently used for RDP logon PDU
    TargetLogon {
        session_id: Uuid,
        target_name: String,
        target_id: TargetId,
        user_id: UserId,
        username: String,
        /// for RPD, DOMAIN\user
        target_account: Option<String>,
        target_session_id: Option<u32>,
    },
    TicketCreated {
        ticket_id: Uuid,
        user_id: UserId,
        username: String,
        target: String,
        actor_user_id: UserId,
    },
    TicketDeleted {
        ticket_id: Uuid,
        user_id: UserId,
        username: String,
        target: String,
        actor_user_id: UserId,
    },
    SecretResolved {
        backend: String,
        reference: String,
        success: bool,
    },
    SshCertificateIssued {
        backend: String,
        role: String,
        principal: String,
        key_id: String,
        success: bool,
    },
    /// A command run inside an existing container: `kubectl exec`, or a kubelet
    /// `/run` through the node proxy.
    KubernetesExecStarted {
        subject: KubernetesAuditSubject,
        namespace: String,
        pod: String,
        /// The container the client named. `None` when it named none: kubectl
        /// omits it for single-container pods and lets the API server choose,
        /// and guessing here would put an unverified name in the audit log.
        container: Option<String>,
        /// argv as a JSON array.
        command: String,
        tty: bool,
        stdin: bool,
    },
    /// `kubectl attach` — a client attached to a container's existing streams.
    KubernetesAttachStarted {
        subject: KubernetesAuditSubject,
        namespace: String,
        pod: String,
        container: Option<String>,
        tty: bool,
    },
    /// `kubectl port-forward` — a tunnel to a pod's port was opened.
    KubernetesPortForwardStarted {
        subject: KubernetesAuditSubject,
        namespace: String,
        pod: String,
        /// Requested ports as a JSON array, when the client named them in the
        /// query. The websocket port-forward protocol negotiates ports per
        /// stream instead and sends no query at all, so this is often absent —
        /// and an empty list would read as "no ports", which is not the same.
        ports: Option<String>,
    },
    /// The cluster refused a streaming request or a kubelet `/run` — typically
    /// RBAC. Recorded separately because a denied attempt is exactly as
    /// interesting as a successful one, and the `...Started` event alone cannot
    /// say which it was.
    KubernetesStreamRejected {
        subject: KubernetesAuditSubject,
        namespace: String,
        pod: String,
        /// `exec`, `attach` or `portforward`.
        subresource: String,
        status: u16,
    },
    /// `kubectl debug` against a running pod: an ephemeral container was added
    /// to it. One event per container in the request.
    KubernetesDebugContainerCreated {
        subject: KubernetesAuditSubject,
        namespace: String,
        pod: String,
        debug_container: String,
        image: String,
        /// The container whose namespaces the debug container joins.
        target_container: Option<String>,
        /// argv as a JSON array.
        command: String,
        tty: bool,
        /// `None` if the cluster sent no response. The container may still
        /// have been added.
        response_status: Option<u16>,
    },
    /// Logged as `KubernetesPodCreated1` or `KubernetesPodUpdated1`.
    KubernetesPodWritten {
        created: bool,
        subject: KubernetesAuditSubject,
        namespace: String,
        pod: String,
        /// Container images as a JSON array.
        images: String,
        node_name: Option<String>,
        host_pid: bool,
        host_network: bool,
        privileged: bool,
        response_status: Option<u16>,
    },
    KubernetesUnknownRequest {
        subject: KubernetesAuditSubject,
        method: String,
        path: String,
        namespace: String,
        /// `None` for a request against the pod collection.
        pod: Option<String>,
        content_type: Option<String>,
        body_length: usize,
        /// Fixed strings only. A parser's error message would quote the body,
        /// which can hold secrets.
        reason: &'static str,
        /// `None` if the cluster sent no response. The write may still have
        /// been applied.
        response_status: Option<u16>,
    },
    /// A provider synced from its source. A sync that applies nothing and
    /// repeats the previous outcome is not logged.
    ProviderSynced {
        sync_id: Uuid,
        provider: String,
        trigger: String,
        status: String,
        source: String,
        revision: Option<String>,
        /// The admin who requested the sync
        actor_user_id: Option<UserId>,
    },
    /// An admin or a provider sync created, changed or deleted a resource.
    /// Admin edits of rows that no provider manages use it too
    ResourceChanged {
        change: ResourceChange,
        by: ChangedBy,
    },
    SessionApproval {
        step: SessionApprovalStep,
        session_id: UserSessionId,
        client_ip: String,
        user_id: UserId,
        username: String,
        protocol: String,
        target_name: String,
    },
    SessionApprovalResolved {
        session_id: UserSessionId,
        client_ip: String,
        user_id: UserId,
        username: String,
        protocol: String,
        target_name: String,
        kind: ApprovalKind,
        resolved_by: String,
        resolved_by_user_id: UserId,
        approved: bool,
    },
    /// A login that failed before its user was known
    UserAuthenticationFailed {
        session_id: UserSessionId,
        client_ip: Option<IpAddr>,
        username: String,
        credentials: String,
        reason: String,
    },
    /// An admin made a provider's resource editable by hand again
    ProviderResourceReleased {
        provider: String,
        kind: String,
        id: Uuid,
        actor_user_id: UserId,
    },
    UnmanagedResourcesExported {
        actor_user_id: UserId,
    },
}

/// A permanent grant logs no `expires_at` field
fn rfc3339(time: Option<OffsetDateTime>) -> Option<String> {
    time.map(|time| time.format(&Rfc3339).unwrap_or_else(|_| time.to_string()))
}

impl AuditEvent {
    pub fn emit(&self) {
        match self {
            Self::CredentialChanged {
                change,
                credential_type,
                credential_name,
                via,
                user_id,
                username,
                actor_user_id,
            } => {
                let (event, message) = match change {
                    CredentialChange::Created => ("CredentialCreated1", "Created credential"),
                    CredentialChange::Updated => ("CredentialUpdated1", "Updated credential"),
                    CredentialChange::Deleted => ("CredentialDeleted1", "Deleted credential"),
                };
                info!(
                    target: "audit",
                    _type = event,
                    credential_type = %credential_type,
                    credential_name = credential_name.as_deref(),
                    via = %via,
                    user_id = %user_id,
                    username = %username,
                    related_users = %format_related_ids(&[*user_id, *actor_user_id]),
                    "{message}"
                );
            }
            Self::UserCreated {
                user_id,
                username,
                actor_user_id,
            } => {
                info!(
                    target: "audit",
                    _type = "UserCreated1",
                    user_id = %user_id,
                    username = %username,
                        related_users = %format_related_ids(&[*user_id, *actor_user_id]),
                    "Created user"
                );
            }
            Self::UserDeleted {
                user_id,
                username,
                actor_user_id,
            } => {
                info!(
                    target: "audit",
                    _type = "UserDeleted1",
                    user_id = %user_id,
                    username = %username,
                        related_users = %format_related_ids(&[*user_id, *actor_user_id]),
                    "Deleted user"
                );
            }
            Self::UserLdapLinkChanged {
                user_id,
                username,
                ldap_server_id,
                actor_user_id,
            } => {
                info!(
                    target: "audit",
                    _type = "UserLdapLinkChanged1",
                    user_id = %user_id,
                    username = %username,
                    ldap_server_id = ldap_server_id.map(|id| id.to_string()),
                    related_users = %format_related_ids(&[*user_id, *actor_user_id]),
                    "Changed user LDAP link"
                );
            }
            Self::AccessRoleGranted {
                grantee_id,
                grantee_username,
                role_id,
                role_name,
                expires_at,
                actor_user_id,
                related_access_roles,
            } => {
                info!(
                    target: "audit",
                    _type = "AccessRoleGranted1",
                    grantee_id = %grantee_id,
                    grantee_username = %grantee_username,
                    role_id = %role_id,
                    role_name = %role_name,
                    expires_at = rfc3339(*expires_at),
                        related_users = %format_related_ids(&[*grantee_id, *actor_user_id]),
                    ?related_access_roles,
                    "Granted access role"
                );
            }
            Self::AccessRoleRevoked {
                grantee_id,
                grantee_username,
                role_id,
                role_name,
                actor_user_id,
                related_access_roles,
            } => {
                info!(
                    target: "audit",
                    _type = "AccessRoleRevoked1",
                    grantee_id = %grantee_id,
                    grantee_username = %grantee_username,
                    role_id = %role_id,
                    role_name = %role_name,
                        related_users = %format_related_ids(&[*grantee_id, *actor_user_id]),
                    ?related_access_roles,
                    "Revoked access role"
                );
            }
            Self::AdminRoleGranted {
                grantee_id,
                grantee_username,
                admin_role_id,
                admin_role_name,
                actor_user_id,
                related_admin_roles,
            } => {
                info!(
                    target: "audit",
                    _type = "AdminRoleGranted1",
                    grantee_id = %grantee_id,
                    grantee_username = %grantee_username,
                    admin_role_id = %admin_role_id,
                    admin_role_name = %admin_role_name,
                        related_users = %format_related_ids(&[*grantee_id, *actor_user_id]),
                    ?related_admin_roles,
                    "Granted admin role"
                );
            }
            Self::AdminRoleRevoked {
                grantee_id,
                grantee_username,
                admin_role_id,
                admin_role_name,
                actor_user_id,
                related_admin_roles,
            } => {
                info!(
                    target: "audit",
                    _type = "AdminRoleRevoked1",
                    grantee_id = %grantee_id,
                    grantee_username = %grantee_username,
                    admin_role_id = %admin_role_id,
                    admin_role_name = %admin_role_name,
                    related_users = %format_related_ids(&[*grantee_id, *actor_user_id]),
                    ?related_admin_roles,
                    "Revoked admin role"
                );
            }
            Self::AccessRoleExpiryChanged {
                grantee_id,
                grantee_username,
                role_id,
                role_name,
                expires_at,
                revocation_cleared,
                actor_user_id,
            } => {
                info!(
                    target: "audit",
                    _type = "AccessRoleExpiryChanged1",
                    grantee_id = %grantee_id,
                    grantee_username = %grantee_username,
                    role_id = %role_id,
                    role_name = %role_name,
                    expires_at = rfc3339(*expires_at),
                    revocation_cleared,
                    related_users = %format_related_ids(&[*grantee_id, *actor_user_id]),
                    related_access_roles = %format_related_ids(&[*role_id]),
                    "Changed access role expiry"
                );
            }
            Self::TargetRoleChanged {
                added,
                target_id,
                target_name,
                role_id,
                role_name,
                by,
            } => {
                let (sync, actor_user_id) = by.origin();
                let (event, message) = if *added {
                    ("TargetRoleAdded1", "Added access role to target")
                } else {
                    ("TargetRoleRemoved1", "Removed access role from target")
                };
                let related_users = actor_user_id.map(|id| format_related_ids(&[id]));
                info!(
                    target: "audit",
                    _type = event,
                    target_id = %target_id,
                    target_name = %target_name,
                    role_id = %role_id,
                    role_name = %role_name,
                    sync_id = sync.as_ref().map(|(id, _)| id.to_string()),
                    provider = sync.as_ref().map(|(_, provider)| provider.as_str()),
                    related_users = related_users.as_deref(),
                    related_access_roles = %format_related_ids(&[*role_id]),
                    "{message}"
                );
            }
            Self::TargetSessionStarted {
                session_id,
                target_id,
                target_name,
                user_id,
                username,
            } => {
                info!(
                    target: "audit",
                    _type = "TargetSessionStarted1",
                    session_id = %session_id,
                    target_id = %target_id,
                    target_name = %target_name,
                    user_id = %user_id,
                    username = %username,
                    related_users = %format_related_ids(&[*user_id]),
                    "Target session started"
                );
            }
            Self::TargetSessionEnded {
                session_id,
                target_id,
                target_name,
                user_id,
                username,
            } => {
                info!(
                    target: "audit",
                    _type = "TargetSessionEnded1",
                    session_id = %session_id,
                    target_id = %target_id,
                    target_name = %target_name,
                    user_id = %user_id,
                    username = %username,
                    related_users = %format_related_ids(&[*user_id]),
                    "Target session ended"
                );
            }
            Self::TargetLogon {
                session_id,
                target_name,
                target_id,
                user_id,
                username,
                target_account,
                target_session_id,
            } => {
                info!(
                    target: "audit",
                    _type = "TargetLogon1",
                    session_id = %session_id,
                    target_id = %target_id,
                    target_name = %target_name,
                    user_id = %user_id,
                    username = %username,
                    target_account = target_account.as_deref(),
                    target_session_id = *target_session_id,
                    related_users = %format_related_ids(&[*user_id]),
                    "Logged on to target"
                );
            }
            Self::TicketCreated {
                ticket_id,
                user_id,
                username,
                target,
                actor_user_id,
            } => {
                info!(
                    target: "audit",
                    _type = "TicketCreated1",
                    ticket_id = %ticket_id,
                    username = %username,
                    target = %target,
                    related_users = %format_related_ids(&[*user_id, *actor_user_id]),
                    "Created ticket"
                );
            }
            Self::TicketDeleted {
                ticket_id,
                user_id,
                username,
                target,
                actor_user_id,
            } => {
                info!(
                    target: "audit",
                    _type = "TicketDeleted1",
                    ticket_id = %ticket_id,
                    username = %username,
                    target = %target,
                    related_users = %format_related_ids(&[*user_id, *actor_user_id]),
                    "Deleted ticket"
                );
            }
            Self::SecretResolved {
                backend,
                reference,
                success,
            } => {
                info!(
                    target: "audit",
                    _type = "SecretResolved1",
                    backend = %backend,
                    reference = %reference,
                    success = %success,
                    "Resolved secret from backend"
                );
            }
            Self::SshCertificateIssued {
                backend,
                role,
                principal,
                key_id,
                success,
            } => {
                info!(
                    target: "audit",
                    _type = "SshCertificateIssued1",
                    backend = %backend,
                    role = %role,
                    principal = %principal,
                    key_id = %key_id,
                    success = %success,
                    "Requested an SSH certificate from backend"
                );
            }
            Self::KubernetesExecStarted {
                subject,
                namespace,
                pod,
                container,
                command,
                tty,
                stdin,
            } => {
                // An absent optional field is left out of the row entirely
                // rather than rendered as a placeholder that would read like a
                // real name; tracing records nothing for a `None`.
                info!(
                    target: "audit",
                    _type = "KubernetesExecStarted1",
                    session = %subject.session_id,
                    user_id = %subject.user_id,
                    username = %subject.username,
                    target_id = %subject.target_id,
                    target_name = %subject.target_name,
                    related_users = %format_related_ids(&[subject.user_id]),
                    namespace = %namespace,
                    pod = %pod,
                    container = container.as_deref(),
                    command = %command,
                    tty = %tty,
                    stdin = %stdin,
                    "Kubernetes exec"
                );
            }
            Self::KubernetesAttachStarted {
                subject,
                namespace,
                pod,
                container,
                tty,
            } => {
                info!(
                    target: "audit",
                    _type = "KubernetesAttachStarted1",
                    session = %subject.session_id,
                    user_id = %subject.user_id,
                    username = %subject.username,
                    target_id = %subject.target_id,
                    target_name = %subject.target_name,
                    related_users = %format_related_ids(&[subject.user_id]),
                    namespace = %namespace,
                    pod = %pod,
                    container = container.as_deref(),
                    tty = %tty,
                    "Kubernetes attach"
                );
            }
            Self::KubernetesPortForwardStarted {
                subject,
                namespace,
                pod,
                ports,
            } => {
                info!(
                    target: "audit",
                    _type = "KubernetesPortForwardStarted1",
                    session = %subject.session_id,
                    user_id = %subject.user_id,
                    username = %subject.username,
                    target_id = %subject.target_id,
                    target_name = %subject.target_name,
                    related_users = %format_related_ids(&[subject.user_id]),
                    namespace = %namespace,
                    pod = %pod,
                    ports = ports.as_deref(),
                    "Kubernetes port forwarding"
                );
            }
            Self::KubernetesStreamRejected {
                subject,
                namespace,
                pod,
                subresource,
                status,
            } => {
                info!(
                    target: "audit",
                    _type = "KubernetesStreamRejected1",
                    session = %subject.session_id,
                    user_id = %subject.user_id,
                    username = %subject.username,
                    target_id = %subject.target_id,
                    target_name = %subject.target_name,
                    related_users = %format_related_ids(&[subject.user_id]),
                    namespace = %namespace,
                    pod = %pod,
                    subresource = %subresource,
                    status = %status,
                    "Kubernetes stream rejected by the cluster"
                );
            }
            Self::KubernetesDebugContainerCreated {
                subject,
                namespace,
                pod,
                debug_container,
                image,
                target_container,
                command,
                tty,
                response_status,
            } => {
                info!(
                    target: "audit",
                    _type = "KubernetesDebugContainerCreated1",
                    session = %subject.session_id,
                    user_id = %subject.user_id,
                    username = %subject.username,
                    target_id = %subject.target_id,
                    target_name = %subject.target_name,
                    related_users = %format_related_ids(&[subject.user_id]),
                    namespace = %namespace,
                    pod = %pod,
                    debug_container = %debug_container,
                    image = %image,
                    target_container = target_container.as_deref(),
                    command = %command,
                    tty = %tty,
                    response_status = response_status.map(tracing::field::display),
                    "Kubernetes debug container"
                );
            }
            Self::KubernetesPodWritten {
                subject,
                created,
                namespace,
                pod,
                images,
                node_name,
                host_pid,
                host_network,
                privileged,
                response_status,
            } => {
                let (event_type, message) = if *created {
                    ("KubernetesPodCreated1", "Kubernetes pod created")
                } else {
                    ("KubernetesPodUpdated1", "Kubernetes pod updated")
                };
                info!(
                    target: "audit",
                    _type = event_type,
                    session = %subject.session_id,
                    user_id = %subject.user_id,
                    username = %subject.username,
                    target_id = %subject.target_id,
                    target_name = %subject.target_name,
                    related_users = %format_related_ids(&[subject.user_id]),
                    namespace = %namespace,
                    pod = %pod,
                    images = %images,
                    node_name = node_name.as_deref(),
                    host_pid = %host_pid,
                    host_network = %host_network,
                    privileged = %privileged,
                    response_status = response_status.map(tracing::field::display),
                    "{message}"
                );
            }
            Self::KubernetesUnknownRequest {
                subject,
                method,
                path,
                namespace,
                pod,
                content_type,
                body_length,
                reason,
                response_status,
            } => {
                info!(
                    target: "audit",
                    _type = "KubernetesUnknownRequest1",
                    session = %subject.session_id,
                    user_id = %subject.user_id,
                    username = %subject.username,
                    target_id = %subject.target_id,
                    target_name = %subject.target_name,
                    related_users = %format_related_ids(&[subject.user_id]),
                    method = %method,
                    path = %path,
                    namespace = %namespace,
                    pod = pod.as_deref(),
                    content_type = content_type.as_deref(),
                    body_length = %body_length,
                    reason = %reason,
                    response_status = response_status.map(tracing::field::display),
                    "Kubernetes request with an unparseable body"
                );
            }
            Self::ProviderSynced {
                sync_id,
                provider,
                trigger,
                status,
                source,
                revision,
                actor_user_id,
            } => {
                let related_users = actor_user_id.map(|id| format_related_ids(&[id]));
                info!(
                    target: "audit",
                    _type = "ProviderSynced1",
                    sync_id = %sync_id,
                    provider = %provider,
                    trigger = %trigger,
                    status = %status,
                    source = %source,
                    revision = revision.as_deref(),
                    related_users = related_users.as_deref(),
                    "Provider synced"
                );
            }
            Self::ResourceChanged { change, by } => {
                let (sync, actor) = by.origin();
                let (Subject::Resource(_, id) | Subject::Row(_, id)) = change.subject;
                let user = matches!(change.subject, Subject::Row(RowKind::User, _))
                    .then(|| UserId::from_uuid(id));
                let users: Vec<UserId> = user.into_iter().chain(actor).collect();
                let related_users = (!users.is_empty()).then(|| format_related_ids(&users));
                let related_access_roles =
                    matches!(change.subject, Subject::Resource(ResourceKind::Role, _))
                        .then(|| format_related_ids(&[id]));
                let related_admin_roles =
                    matches!(change.subject, Subject::Row(RowKind::AdminRole, _))
                        .then(|| format_related_ids(&[id]));
                let fields = change
                    .fields
                    .as_ref()
                    .filter(|fields| !fields.is_empty())
                    .and_then(|fields| serde_json::to_string(fields).ok());
                info!(
                    target: "audit",
                    _type = "ResourceChanged1",
                    action = change.action.name(),
                    kind = change.subject.kind(),
                    id = %id,
                    name = %change.name,
                    fields = fields.as_deref(),
                    sync_id = sync.as_ref().map(|(id, _)| id.to_string()),
                    provider = sync.as_ref().map(|(_, provider)| provider.as_str()),
                    related_users = related_users.as_deref(),
                    related_access_roles = related_access_roles.as_deref(),
                    related_admin_roles = related_admin_roles.as_deref(),
                    "Resource changed"
                );
            }
            Self::SessionApproval {
                step,
                session_id,
                client_ip,
                user_id,
                username,
                protocol,
                target_name,
            } => {
                let (event, message) = match step {
                    SessionApprovalStep::Requested => (
                        "SessionApprovalRequested1",
                        "Session is awaiting administrator approval",
                    ),
                    SessionApprovalStep::TimedOut => {
                        ("SessionApprovalTimedOut1", "Session approval timed out")
                    }
                    SessionApprovalStep::Bypassed => (
                        "AdminApprovalBypassed1",
                        "Administrator approval bypassed within grace period",
                    ),
                };
                info!(
                    target: "audit",
                    _type = event,
                    session = %session_id,
                    client_ip = %client_ip,
                    user_id = %user_id,
                    username = %username,
                    protocol = %protocol,
                    target = %target_name,
                    related_users = %format_related_ids(&[*user_id]),
                    "{message}",
                );
            }
            Self::SessionApprovalResolved {
                session_id,
                client_ip,
                user_id,
                username,
                protocol,
                target_name,
                kind,
                resolved_by,
                resolved_by_user_id,
                approved,
            } => {
                // A user who approves their own session is listed once
                let mut related = vec![*user_id];
                if resolved_by_user_id != user_id {
                    related.push(*resolved_by_user_id);
                }
                info!(
                    target: "audit",
                    _type = "SessionApprovalResolved1",
                    session = %session_id,
                    client_ip = %client_ip,
                    user_id = %user_id,
                    username = %username,
                    protocol = %protocol,
                    target = %target_name,
                    kind = ?kind,
                    resolved_by = %resolved_by,
                    approved = approved,
                    related_users = %format_related_ids(&related),
                    "Session approval resolved",
                );
            }
            Self::UserAuthenticationFailed {
                session_id,
                client_ip,
                username,
                credentials,
                reason,
            } => {
                let client_ip =
                    client_ip.map_or_else(|| "<unknown>".to_string(), |ip| ip.to_string());
                info!(
                    target: "audit",
                    _type = "UserAuthenticationFailed1",
                    session = %session_id,
                    client_ip = %client_ip,
                    username = %username,
                    credentials = %credentials,
                    reason = %reason,
                    "Authentication failed",
                );
            }
            Self::ProviderResourceReleased {
                provider,
                kind,
                id,
                actor_user_id,
            } => {
                info!(
                    target: "audit",
                    _type = "ProviderResourceReleased1",
                    provider = %provider,
                    kind = %kind,
                    id = %id,
                    related_users = %format_related_ids(&[*actor_user_id]),
                    "Managed resource manually released from its provider"
                );
            }
            Self::UnmanagedResourcesExported { actor_user_id } => {
                info!(
                    target: "audit",
                    _type = "UnmanagedResourcesExported1",
                    related_users = %format_related_ids(&[*actor_user_id]),
                    "Unmanaged resources exported with their credentials"
                );
            }
        }
    }
}

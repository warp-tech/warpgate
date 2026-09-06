use std::fmt::Display;

use tracing::info;
use uuid::Uuid;

use crate::helpers::logging::format_related_ids;

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
/// this identity, and the protocol builds it once per request, so it is one
/// struct rather than four fields repeated across six variants.
#[derive(Clone)]
pub struct KubernetesAuditSubject {
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub username: String,
    pub target_id: Uuid,
    pub target_name: String,
}

#[derive(Clone)]
pub enum AuditEvent {
    CredentialCreated {
        credential_type: String,
        credential_name: Option<String>,
        via: CredentialChangedVia,
        user_id: Uuid,
        username: String,
        actor_user_id: Uuid,
    },
    CredentialDeleted {
        credential_type: String,
        credential_name: Option<String>,
        via: CredentialChangedVia,
        user_id: Uuid,
        username: String,
        actor_user_id: Uuid,
    },
    UserCreated {
        user_id: Uuid,
        username: String,
        actor_user_id: Uuid,
    },
    UserDeleted {
        user_id: Uuid,
        username: String,
        actor_user_id: Uuid,
    },
    TargetSessionStarted {
        session_id: Uuid,
        target_name: String,
        target_id: Uuid,
        user_id: Uuid,
        username: String,
    },
    TargetSessionEnded {
        session_id: Uuid,
        target_name: String,
        target_id: Uuid,
        user_id: Uuid,
        username: String,
    },
    AccessRoleGranted {
        grantee_id: Uuid,
        grantee_username: String,
        role_id: Uuid,
        role_name: String,
        actor_user_id: Uuid,
        related_access_roles: String,
    },
    AccessRoleRevoked {
        grantee_id: Uuid,
        grantee_username: String,
        role_id: Uuid,
        role_name: String,
        actor_user_id: Uuid,
        related_access_roles: String,
    },
    AdminRoleGranted {
        grantee_id: Uuid,
        grantee_username: String,
        admin_role_id: Uuid,
        admin_role_name: String,
        actor_user_id: Uuid,
        related_admin_roles: String,
    },
    AdminRoleRevoked {
        grantee_id: Uuid,
        grantee_username: String,
        admin_role_id: Uuid,
        admin_role_name: String,
        actor_user_id: Uuid,
        related_admin_roles: String,
    },
    // currently used for RDP logon PDU
    TargetLogon {
        session_id: Uuid,
        target_name: String,
        target_id: Uuid,
        user_id: Uuid,
        username: String,
        /// for RPD, DOMAIN\user
        target_account: Option<String>,
        target_session_id: Option<u32>,
    },
    TicketCreated {
        ticket_id: Uuid,
        user_id: Uuid,
        username: String,
        target: String,
        actor_user_id: Uuid,
    },
    TicketDeleted {
        ticket_id: Uuid,
        user_id: Uuid,
        username: String,
        target: String,
        actor_user_id: Uuid,
    },
    /// `kubectl exec` — a command run inside an existing container.
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
    /// The cluster refused a streaming request — typically RBAC. Recorded
    /// separately because a denied attempt is exactly as interesting as a
    /// successful one, and the `...Started` event alone cannot say which it was.
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
        response_status: u16,
    },
    /// A pod was created — how `kubectl debug node/...` and `kubectl debug
    /// --copy-to` land a debug workload, and worth auditing in its own right.
    KubernetesPodCreated {
        subject: KubernetesAuditSubject,
        namespace: String,
        pod: String,
        /// Container images as a JSON array.
        images: String,
        node_name: Option<String>,
        host_pid: bool,
        host_network: bool,
        privileged: bool,
        response_status: u16,
    },
}

impl AuditEvent {
    pub fn emit(&self) {
        match self {
            Self::CredentialCreated {
                credential_type,
                credential_name,
                via,
                user_id,
                username,
                actor_user_id,
            } => {
                if let Some(credential_name) = credential_name {
                    info!(
                        target: "audit",
                        _type = "CredentialCreated1",
                        credential_type = %credential_type,
                        credential_name = %credential_name,
                        via = %via,
                        user_id = %user_id,
                        username = %username,
                        related_users = ?format_related_ids(&[*user_id, *actor_user_id]),
                        "Created credential"
                    );
                } else {
                    info!(
                        target: "audit",
                        _type = "CredentialCreated1",
                        credential_type = %credential_type,
                        via = %via,
                        user_id = %user_id,
                        username = %username,
                        related_users = ?format_related_ids(&[*user_id, *actor_user_id]),
                        "Created credential"
                    );
                }
            }
            Self::CredentialDeleted {
                credential_type,
                credential_name,
                via,
                user_id,
                username,
                actor_user_id,
            } => {
                if let Some(credential_name) = credential_name {
                    info!(
                        target: "audit",
                        _type = "CredentialDeleted1",
                        credential_type = %credential_type,
                        credential_name = %credential_name,
                        via = %via,
                        user_id = %user_id,
                        username = %username,
                        related_users = ?format_related_ids(&[*user_id, *actor_user_id]),
                        "Deleted credential"
                    );
                } else {
                    info!(
                        target: "audit",
                        _type = "CredentialDeleted1",
                        credential_type = %credential_type,
                        via = %via,
                        user_id = %user_id,
                        username = %username,
                        related_users = ?format_related_ids(&[*user_id, *actor_user_id]),
                        "Deleted credential"
                    );
                }
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
                        related_users = ?format_related_ids(&[*user_id, *actor_user_id]),
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
                        related_users = ?format_related_ids(&[*user_id, *actor_user_id]),
                    "Deleted user"
                );
            }
            Self::AccessRoleGranted {
                grantee_id,
                grantee_username,
                role_id,
                role_name,
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
                        related_users = ?format_related_ids(&[*grantee_id, *actor_user_id]),
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
                        related_users = ?format_related_ids(&[*grantee_id, *actor_user_id]),
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
                        related_users = ?format_related_ids(&[*grantee_id, *actor_user_id]),
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
                    related_users = ?format_related_ids(&[*grantee_id, *actor_user_id]),
                    ?related_admin_roles,
                    "Revoked admin role"
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
                    related_users = ?format_related_ids(&[*user_id]),
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
                    related_users = ?format_related_ids(&[*user_id]),
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
                    related_users = ?format_related_ids(&[*user_id]),
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
                    related_users = ?format_related_ids(&[*user_id, *actor_user_id]),
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
                    related_users = ?format_related_ids(&[*user_id, *actor_user_id]),
                    "Deleted ticket"
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
                // The optional container is emitted as a field only when the
                // client actually named one, rather than as a placeholder that
                // would read like a real container name.
                if let Some(container) = container {
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
                        container = %container,
                        command = %command,
                        tty = %tty,
                        stdin = %stdin,
                        "Kubernetes exec"
                    );
                } else {
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
                        command = %command,
                        tty = %tty,
                        stdin = %stdin,
                        "Kubernetes exec"
                    );
                }
            }
            Self::KubernetesAttachStarted {
                subject,
                namespace,
                pod,
                container,
                tty,
            } => {
                if let Some(container) = container {
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
                        container = %container,
                        tty = %tty,
                        "Kubernetes attach"
                    );
                } else {
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
                        tty = %tty,
                        "Kubernetes attach"
                    );
                }
            }
            Self::KubernetesPortForwardStarted {
                subject,
                namespace,
                pod,
                ports,
            } => {
                if let Some(ports) = ports {
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
                        ports = %ports,
                        "Kubernetes port forwarding"
                    );
                } else {
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
                        "Kubernetes port forwarding"
                    );
                }
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
                if let Some(target_container) = target_container {
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
                        target_container = %target_container,
                        command = %command,
                        tty = %tty,
                        response_status = %response_status,
                        "Kubernetes debug container"
                    );
                } else {
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
                        command = %command,
                        tty = %tty,
                        response_status = %response_status,
                        "Kubernetes debug container"
                    );
                }
            }
            Self::KubernetesPodCreated {
                subject,
                namespace,
                pod,
                images,
                node_name,
                host_pid,
                host_network,
                privileged,
                response_status,
            } => {
                if let Some(node_name) = node_name {
                    info!(
                        target: "audit",
                        _type = "KubernetesPodCreated1",
                        session = %subject.session_id,
                        user_id = %subject.user_id,
                        username = %subject.username,
                        target_id = %subject.target_id,
                        target_name = %subject.target_name,
                        related_users = %format_related_ids(&[subject.user_id]),
                        namespace = %namespace,
                        pod = %pod,
                        images = %images,
                        node_name = %node_name,
                        host_pid = %host_pid,
                        host_network = %host_network,
                        privileged = %privileged,
                        response_status = %response_status,
                        "Kubernetes pod created"
                    );
                } else {
                    info!(
                        target: "audit",
                        _type = "KubernetesPodCreated1",
                        session = %subject.session_id,
                        user_id = %subject.user_id,
                        username = %subject.username,
                        target_id = %subject.target_id,
                        target_name = %subject.target_name,
                        related_users = %format_related_ids(&[subject.user_id]),
                        namespace = %namespace,
                        pod = %pod,
                        images = %images,
                        host_pid = %host_pid,
                        host_network = %host_network,
                        privileged = %privileged,
                        response_status = %response_status,
                        "Kubernetes pod created"
                    );
                }
            }
        }
    }
}

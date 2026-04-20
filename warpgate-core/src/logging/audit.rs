use std::fmt::Display;

use tracing::info;
use uuid::Uuid;

use crate::logging::format_related_ids;

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
        }
    }
}

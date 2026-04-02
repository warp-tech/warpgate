use std::fmt::Display;

use tracing::info;
use uuid::Uuid;

#[derive(Clone)]
pub enum CredentialChangedVia {
    Admin,
    SelfService,
}

impl Display for CredentialChangedVia {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialChangedVia::Admin => write!(f, "admin"),
            CredentialChangedVia::SelfService => write!(f, "self-service"),
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
        related_users: String,
    },
    CredentialDeleted {
        credential_type: String,
        credential_name: Option<String>,
        via: CredentialChangedVia,
        user_id: Uuid,
        username: String,
        related_users: String,
    },
    UserCreated {
        user_id: Uuid,
        username: String,
        related_users: String,
    },
    UserDeleted {
        user_id: Uuid,
        username: String,
        related_users: String,
    },
    AccessRoleGranted {
        grantee_id: Uuid,
        grantee_username: String,
        role_id: Uuid,
        role_name: String,
        related_users: String,
        related_access_roles: String,
    },
    AccessRoleRevoked {
        grantee_id: Uuid,
        grantee_username: String,
        role_id: Uuid,
        role_name: String,
        related_users: String,
        related_access_roles: String,
    },
    AdminRoleGranted {
        grantee_id: Uuid,
        grantee_username: String,
        admin_role_id: Uuid,
        admin_role_name: String,
        related_users: String,
        related_admin_roles: String,
    },
    AdminRoleRevoked {
        grantee_id: Uuid,
        grantee_username: String,
        admin_role_id: Uuid,
        admin_role_name: String,
        related_users: String,
        related_admin_roles: String,
    },
    TicketCreated {
        ticket_id: Uuid,
        username: String,
        target: String,
        related_users: String,
    },
    TicketDeleted {
        ticket_id: Uuid,
        username: String,
        target: String,
        related_users: String,
    },
}

impl AuditEvent {
    pub fn emit(&self) {
        match self {
            AuditEvent::CredentialCreated {
                credential_type,
                credential_name,
                via,
                user_id,
                username,
                related_users,
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
                        ?related_users,
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
                        ?related_users,
                        "Created credential"
                    );
                }
            }
            AuditEvent::CredentialDeleted {
                credential_type,
                credential_name,
                via,
                user_id,
                username,
                related_users,
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
                        ?related_users,
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
                        ?related_users,
                        "Deleted credential"
                    );
                }
            }
            AuditEvent::UserCreated {
                user_id,
                username,
                related_users,
            } => {
                info!(
                    target: "audit",
                    _type = "UserCreated1",
                    user_id = %user_id,
                    username = %username,
                    ?related_users,
                    "Created user"
                );
            }
            AuditEvent::UserDeleted {
                user_id,
                username,
                related_users,
            } => {
                info!(
                    target: "audit",
                    _type = "UserDeleted1",
                    user_id = %user_id,
                    username = %username,
                    ?related_users,
                    "Deleted user"
                );
            }
            AuditEvent::AccessRoleGranted {
                grantee_id,
                grantee_username,
                role_id,
                role_name,
                related_users,
                related_access_roles,
            } => {
                info!(
                    target: "audit",
                    _type = "AccessRoleGranted1",
                    grantee_id = %grantee_id,
                    grantee_username = %grantee_username,
                    role_id = %role_id,
                    role_name = %role_name,
                    ?related_users,
                    ?related_access_roles,
                    "Granted access role"
                );
            }
            AuditEvent::AccessRoleRevoked {
                grantee_id,
                grantee_username,
                role_id,
                role_name,
                related_users,
                related_access_roles,
            } => {
                info!(
                    target: "audit",
                    _type = "AccessRoleRevoked1",
                    grantee_id = %grantee_id,
                    grantee_username = %grantee_username,
                    role_id = %role_id,
                    role_name = %role_name,
                    ?related_users,
                    ?related_access_roles,
                    "Revoked access role"
                );
            }
            AuditEvent::AdminRoleGranted {
                grantee_id,
                grantee_username,
                admin_role_id,
                admin_role_name,
                related_users,
                related_admin_roles,
            } => {
                info!(
                    target: "audit",
                    _type = "AdminRoleGranted1",
                    grantee_id = %grantee_id,
                    grantee_username = %grantee_username,
                    admin_role_id = %admin_role_id,
                    admin_role_name = %admin_role_name,
                    ?related_users,
                    ?related_admin_roles,
                    "Granted admin role"
                );
            }
            AuditEvent::AdminRoleRevoked {
                grantee_id,
                grantee_username,
                admin_role_id,
                admin_role_name,
                related_users,
                related_admin_roles,
            } => {
                info!(
                    target: "audit",
                    _type = "AdminRoleRevoked1",
                    grantee_id = %grantee_id,
                    grantee_username = %grantee_username,
                    admin_role_id = %admin_role_id,
                    admin_role_name = %admin_role_name,
                    ?related_users,
                    ?related_admin_roles,
                    "Revoked admin role"
                );
            }
            AuditEvent::TicketCreated {
                ticket_id,
                username,
                target,
                related_users,
            } => {
                info!(
                    target: "audit",
                    _type = "TicketCreated1",
                    ticket_id = %ticket_id,
                    username = %username,
                    target = %target,
                    ?related_users,
                    "Created ticket"
                );
            }
            AuditEvent::TicketDeleted {
                ticket_id,
                username,
                target,
                related_users,
            } => {
                info!(
                    target: "audit",
                    _type = "TicketDeleted1",
                    ticket_id = %ticket_id,
                    username = %username,
                    target = %target,
                    ?related_users,
                    "Deleted ticket"
                );
            }
        }
    }
}

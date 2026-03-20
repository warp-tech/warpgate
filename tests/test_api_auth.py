import contextlib
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Set
from json import load
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
import requests

from .api_client import sdk, admin_client as new_admin_client
from .conftest import WarpgateProcess
from .test_http_common import *  # noqa


@dataclass
class AdminApiTestCase:
    id: str
    permission: Optional[str]
    call: Callable[[sdk.DefaultApi, Dict[str, object]], sdk.ApiResponse]
    expected_statuses: Set[int]


@contextlib.contextmanager
def assert_401():
    with pytest.raises(sdk.ApiException) as e:
        yield
    assert e.value.status == 401


def make_limited_admin_role_payload(**overrides):
    return {
        "name": overrides.get("name", f"limited-{uuid4()}"),
        "description": "limited permissions",
        "targets_create": False,
        "targets_edit": False,
        "targets_delete": False,
        "users_create": False,
        "users_edit": False,
        "users_delete": False,
        "access_roles_create": False,
        "access_roles_edit": False,
        "access_roles_delete": False,
        "access_roles_assign": False,
        "sessions_view": False,
        "sessions_terminate": False,
        "recordings_view": False,
        "tickets_create": False,
        "tickets_delete": False,
        "config_edit": False,
        "admin_roles_manage": False,
        "ticket_requests_manage": False,
        **overrides,
    }


ADMIN_API_TEST_CASES: list[AdminApiTestCase] = [
    AdminApiTestCase(
        id="get_sessions",
        permission="sessions_view",
        call=lambda api, r: api.get_sessions_with_http_info(),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="get_session",
        permission="sessions_view",
        call=lambda api, r: api.get_session_with_http_info(r["session_id"]),
        expected_statuses={200, 404},
    ),
    AdminApiTestCase(
        id="get_session_recordings",
        permission="recordings_view",
        call=lambda api, r: api.get_session_recordings_with_http_info(r["session_id"]),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="close_session",
        permission="sessions_terminate",
        call=lambda api, r: api.close_session_with_http_info(r["session_id"]),
        expected_statuses={200, 404},
    ),
    AdminApiTestCase(
        id="close_all_sessions",
        permission="sessions_terminate",
        call=lambda api, r: api.close_all_sessions_with_http_info(),
        expected_statuses={201},
    ),
    AdminApiTestCase(
        id="get_recording",
        permission="recordings_view",
        call=lambda api, r: api.get_recording_with_http_info(r["recording_id"]),
        expected_statuses={200, 404},
    ),
    AdminApiTestCase(
        id="get_kubernetes_recording",
        permission="recordings_view",
        call=lambda api, r: api.get_kubernetes_recording_with_http_info(
            r["recording_id"]
        ),
        expected_statuses={200, 404},
    ),
    AdminApiTestCase(
        id="get_roles",
        permission=None,
        call=lambda api, r: api.get_roles_with_http_info(),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="create_role",
        permission="access_roles_create",
        call=lambda api, r: api.create_role_with_http_info(
            sdk.RoleDataRequest(name=f"role-{uuid4()}"),
        ),
        expected_statuses={201},
    ),
    AdminApiTestCase(
        id="get_role",
        permission=None,
        call=lambda api, r: api.get_role_with_http_info(r["role_id"]),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="update_role",
        permission="access_roles_edit",
        call=lambda api, r: api.update_role_with_http_info(
            r["role_id"],
            sdk.RoleDataRequest(name=f"role-{uuid4()}"),
        ),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="get_role_targets",
        permission=None,
        call=lambda api, r: api.get_role_targets_with_http_info(r["role_id"]),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="get_role_users",
        permission=None,
        call=lambda api, r: api.get_role_users_with_http_info(r["role_id"]),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="get_admin_roles",
        permission=None,
        call=lambda api, r: api.get_admin_roles_with_http_info(),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="create_admin_role",
        permission="admin_roles_manage",
        call=lambda api, r: api.create_admin_role_with_http_info(
            sdk.AdminRoleDataRequest(
                **make_limited_admin_role_payload(name=f"admin-role-{uuid4()}")
            )
        ),
        expected_statuses={201},
    ),
    AdminApiTestCase(
        id="get_admin_role",
        permission=None,
        call=lambda api, r: api.get_admin_role_with_http_info(r["admin_role_id"]),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="update_admin_role",
        permission="admin_roles_manage",
        call=lambda api, r: api.update_admin_role_with_http_info(
            r["admin_role_id"],
            sdk.AdminRoleDataRequest(
                **make_limited_admin_role_payload(name=f"admin-role-{uuid4()}")
            ),
        ),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="get_admin_role_users",
        permission=None,
        call=lambda api, r: api.get_admin_role_users_with_http_info(r["admin_role_id"]),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="get_tickets",
        permission=None,
        call=lambda api, r: api.get_tickets_with_http_info(),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="create_ticket",
        permission="tickets_create",
        call=lambda api, r: api.create_ticket_with_http_info(
            sdk.CreateTicketRequest(
                username=r["username"],
                target_name=r["target_name"],
            ),
        ),
        expected_statuses={201},
    ),
    AdminApiTestCase(
        id="delete_ticket",
        permission="tickets_delete",
        call=lambda api, r: api.delete_ticket_with_http_info(r["ticket_id"]),
        expected_statuses={204},
    ),
    AdminApiTestCase(
        id="add_ssh_known_host",
        permission="config_edit",
        call=lambda api, r: api.add_ssh_known_host_with_http_info(
            sdk.AddSshKnownHostRequest(
                host="127.0.0.1",
                port=22,
                key_type="ecdsa-sha2-nistp256",
                key_base64="AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKL5C+OCN2hAbPoR+mwG4M402Z0XVDOuV5k7n6zCRIMsgnYiyz6a61Zcw/RRHoQAb7ndqUyk8eAi9gjPEiGq2d0=",
            ),
        ),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="get_ssh_known_hosts",
        permission="config_edit",
        call=lambda api, r: api.get_ssh_known_hosts_with_http_info(),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="delete_ssh_known_host",
        permission="config_edit",
        call=lambda api, r: api.delete_ssh_known_host_with_http_info(
            r["ssh_known_host_id"]
        ),
        expected_statuses={204, 404},
    ),
    AdminApiTestCase(
        id="get_ssh_own_keys",
        permission=None,
        call=lambda api, r: api.get_ssh_own_keys_with_http_info(),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="get_logs",
        permission=None,
        call=lambda api, r: api.get_logs_with_http_info(sdk.GetLogsRequest(search="")),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="get_targets",
        permission=None,
        call=lambda api, r: api.get_targets_with_http_info(),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="create_target",
        permission="targets_create",
        call=lambda api, r: api.create_target_with_http_info(
            sdk.TargetDataRequest(
                name=f"target-{uuid4()}",
                options=sdk.TargetOptions(
                    sdk.TargetOptionsTargetSSHOptions(
                        kind="Ssh",
                        host="127.0.0.1",
                        port=22,
                        username="user",
                        auth=sdk.SSHTargetAuth(
                            sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                        ),
                    )
                ),
            ),
        ),
        expected_statuses={201},
    ),
    AdminApiTestCase(
        id="get_target",
        permission=None,
        call=lambda api, r: api.get_target_with_http_info(r["target_id"]),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="update_target",
        permission="targets_edit",
        call=lambda api, r: api.update_target_with_http_info(
            r["target_id"],
            sdk.TargetDataRequest(
                name=f"target-{uuid4()}",
                options=sdk.TargetOptions(
                    sdk.TargetOptionsTargetSSHOptions(
                        kind="Ssh",
                        host="127.0.0.1",
                        port=22,
                        username="user",
                        auth=sdk.SSHTargetAuth(
                            sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                        ),
                    )
                ),
            ),
        ),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="get_ssh_target_known_ssh_host_keys",
        permission="targets_edit",
        call=lambda api, r: api.get_ssh_target_known_ssh_host_keys_with_http_info(
            r["target_id"]
        ),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="get_target_roles",
        permission=None,
        call=lambda api, r: api.get_target_roles_with_http_info(r["target_id"]),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="add_target_role",
        permission="access_roles_assign",
        call=lambda api, r: api.add_target_role_with_http_info(
            r["target_id"], r["role_id"]
        ),
        expected_statuses={201, 409},
    ),
    AdminApiTestCase(
        id="delete_target_role",
        permission="access_roles_assign",
        call=lambda api, r: api.delete_target_role_with_http_info(
            r["target_id"], r["role_id"]
        ),
        expected_statuses={204},
    ),
    AdminApiTestCase(
        id="list_target_groups",
        permission=None,
        call=lambda api, r: api.list_target_groups_with_http_info(),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="create_target_group",
        permission="targets_create",
        call=lambda api, r: api.create_target_group_with_http_info(
            sdk.TargetGroupDataRequest(name=f"group-{uuid4()}"),
        ),
        expected_statuses={201},
    ),
    AdminApiTestCase(
        id="get_target_group",
        permission=None,
        call=lambda api, r: api.get_target_group_with_http_info(r["target_group_id"]),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="update_target_group",
        permission="targets_edit",
        call=lambda api, r: api.update_target_group_with_http_info(
            r["target_group_id"],
            sdk.TargetGroupDataRequest(name=f"group-{uuid4()}"),
        ),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="delete_target_group",
        permission="targets_delete",
        call=lambda api, r: api.delete_target_group_with_http_info(
            r["target_group_id"]
        ),
        expected_statuses={204},
    ),
    AdminApiTestCase(
        id="get_users",
        permission=None,
        call=lambda api, r: api.get_users_with_http_info(),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="create_user",
        permission="users_create",
        call=lambda api, r: api.create_user_with_http_info(
            sdk.CreateUserRequest(username=f"user-{uuid4()}"),
        ),
        expected_statuses={201},
    ),
    AdminApiTestCase(
        id="get_user",
        permission=None,
        call=lambda api, r: api.get_user_with_http_info(r["user_id"]),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="update_user",
        permission="users_edit",
        call=lambda api, r: api.update_user_with_http_info(
            r["user_id"],
            sdk.UserDataRequest(username=f"user-{uuid4()}"),
        ),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="unlink_user_from_ldap",
        permission="users_edit",
        call=lambda api, r: api.unlink_user_from_ldap_with_http_info(r["user_id"]),
        expected_statuses={200, 400},
    ),
    AdminApiTestCase(
        id="auto_link_user_to_ldap",
        permission="users_edit",
        call=lambda api, r: api.auto_link_user_to_ldap_with_http_info(r["user_id"]),
        expected_statuses={200, 400},
    ),
    AdminApiTestCase(
        id="get_user_roles",
        permission=None,
        call=lambda api, r: api.get_user_roles_with_http_info(r["user_id"]),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="add_user_role",
        permission="access_roles_assign",
        call=lambda api, r: api.add_user_role_with_http_info(
            r["user_id"], r["role_id"]
        ),
        expected_statuses={201},
    ),
    AdminApiTestCase(
        id="delete_user_role",
        permission="access_roles_assign",
        call=lambda api, r: api.delete_user_role_with_http_info(
            r["user_id"], r["role_id"]
        ),
        expected_statuses={204},
    ),
    AdminApiTestCase(
        id="get_user_admin_roles",
        permission=None,
        call=lambda api, r: api.get_user_admin_roles_with_http_info(r["user_id"]),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="add_user_admin_role",
        permission="admin_roles_manage",
        call=lambda api, r: api.add_user_admin_role_with_http_info(
            r["user_id"], r["admin_role_id"]
        ),
        expected_statuses={201},
    ),
    AdminApiTestCase(
        id="delete_user_admin_role",
        permission="admin_roles_manage",
        call=lambda api, r: api.delete_user_admin_role_with_http_info(
            r["user_id"], r["admin_role_id"]
        ),
        expected_statuses={204},
    ),
    AdminApiTestCase(
        id="get_password_credentials",
        permission="users_edit",
        call=lambda api, r: api.get_password_credentials_with_http_info(r["user_id"]),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="create_password_credential",
        permission="users_edit",
        call=lambda api, r: api.create_password_credential_with_http_info(
            r["user_id"],
            sdk.NewPasswordCredential(password="123"),
        ),
        expected_statuses={201},
    ),
    AdminApiTestCase(
        id="delete_password_credential",
        permission="users_edit",
        call=lambda api, r: api.delete_password_credential_with_http_info(
            r["user_id"], r["password_id"]
        ),
        expected_statuses={204},
    ),
    AdminApiTestCase(
        id="get_sso_credentials",
        permission="users_edit",
        call=lambda api, r: api.get_sso_credentials_with_http_info(r["user_id"]),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="create_sso_credential",
        permission="users_edit",
        call=lambda api, r: api.create_sso_credential_with_http_info(
            r["user_id"],
            sdk.NewSsoCredential(email="test@example.com", provider="test"),
        ),
        expected_statuses={201},
    ),
    AdminApiTestCase(
        id="update_sso_credential",
        permission="users_edit",
        call=lambda api, r: api.update_sso_credential_with_http_info(
            r["user_id"],
            r["sso_id"],
            sdk.NewSsoCredential(email="test@example.com", provider="test"),
        ),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="delete_sso_credential",
        permission="users_edit",
        call=lambda api, r: api.delete_sso_credential_with_http_info(
            r["user_id"], r["sso_id"]
        ),
        expected_statuses={204},
    ),
    AdminApiTestCase(
        id="get_public_key_credentials",
        permission="users_edit",
        call=lambda api, r: api.get_public_key_credentials_with_http_info(r["user_id"]),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="create_public_key_credential",
        permission="users_edit",
        call=lambda api, r: api.create_public_key_credential_with_http_info(
            r["user_id"],
            sdk.NewPublicKeyCredential(
                label="key",
                openssh_public_key="ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKL5C+OCN2hAbPoR+mwG4M402Z0XVDOuV5k7n6zCRIMsgnYiyz6a61Zcw/RRHoQAb7ndqUyk8eAi9gjPEiGq2d0=",
            ),
        ),
        expected_statuses={201},
    ),
    AdminApiTestCase(
        id="update_public_key_credential",
        permission="users_edit",
        call=lambda api, r: api.update_public_key_credential_with_http_info(
            r["user_id"],
            r["public_key_id"],
            sdk.NewPublicKeyCredential(
                label="key",
                openssh_public_key="ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKL5C+OCN2hAbPoR+mwG4M402Z0XVDOuV5k7n6zCRIMsgnYiyz6a61Zcw/RRHoQAb7ndqUyk8eAi9gjPEiGq2d0=",
            ),
        ),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="delete_public_key_credential",
        permission="users_edit",
        call=lambda api, r: api.delete_public_key_credential_with_http_info(
            r["user_id"], r["public_key_id"]
        ),
        expected_statuses={204},
    ),
    AdminApiTestCase(
        id="get_otp_credentials",
        permission="users_edit",
        call=lambda api, r: api.get_otp_credentials_with_http_info(r["user_id"]),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="create_otp_credential",
        permission="users_edit",
        call=lambda api, r: api.create_otp_credential_with_http_info(
            r["user_id"],
            sdk.NewOtpCredential(name="otp-1", secret_key=[1, 2, 3]),
        ),
        expected_statuses={201},
    ),
    AdminApiTestCase(
        id="delete_otp_credential",
        permission="users_edit",
        call=lambda api, r: api.delete_otp_credential_with_http_info(
            r["user_id"], r["otp_id"]
        ),
        expected_statuses={204},
    ),
    AdminApiTestCase(
        id="get_ldap_servers",
        permission="config_edit",
        call=lambda api, r: api.get_ldap_servers_with_http_info(),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="create_ldap_server",
        permission="config_edit",
        call=lambda api, r: api.create_ldap_server_with_http_info(
            sdk.CreateLdapServerRequest(
                name=f"ldap-{uuid4()}",
                host="127.0.0.1",
                bind_dn="cn=admin,dc=example,dc=org",
                bind_password="pass",
            ),
        ),
        expected_statuses={201},
    ),
    AdminApiTestCase(
        id="test_ldap_server_connection",
        permission="config_edit",
        call=lambda api, r: api.test_ldap_server_connection_with_http_info(
            sdk.TestLdapServerRequest(
                host="127.0.0.1",
                port=389,
                bind_dn="cn=admin,dc=example,dc=org",
                bind_password="pass",
                tls_mode=sdk.TlsMode.DISABLED,
                tls_verify=False,
            ),
        ),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="get_ldap_server",
        permission="config_edit",
        call=lambda api, r: api.get_ldap_server_with_http_info(r["ldap_server_id"]),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="update_ldap_server",
        permission="config_edit",
        call=lambda api, r: api.update_ldap_server_with_http_info(
            r["ldap_server_id"],
            sdk.UpdateLdapServerRequest(
                name=f"ldap-{uuid4()}",
                host="127.0.0.1",
                bind_dn="cn=admin,dc=example,dc=org",
                bind_password="pass",
                auto_link_sso_users=False,
                description="",
                enabled=True,
                port=123,
                ssh_key_attribute="asd",
                tls_mode=sdk.TlsMode.DISABLED,
                tls_verify=False,
                user_filter="(&(objectClass=person)(uid={0}))",
                username_attribute=sdk.LdapUsernameAttribute.UID,
                uuid_attribute="uid",
            ),
        ),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="get_ldap_users",
        permission="users_create",
        call=lambda api, r: api.get_ldap_users_with_http_info(r["ldap_server_id"]),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="import_ldap_users",
        permission="users_create",
        call=lambda api, r: api.import_ldap_users_with_http_info(
            r["ldap_server_id"],
            import_ldap_users_request=sdk.ImportLdapUsersRequest(dns=[]),
        ),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="get_parameters",
        permission=None,
        call=lambda api, r: api.get_parameters_with_http_info(),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="update_parameters",
        permission="config_edit",
        call=lambda api, r: api.update_parameters_with_http_info(
            sdk.ParameterUpdate(
                allow_own_credential_management=True,
                minimize_password_login=False,
                rate_limit_bytes_per_second=None,
                ssh_client_auth_keyboard_interactive=True,
                ssh_client_auth_password=True,
                ssh_client_auth_publickey=True,
                ticket_self_service_enabled=False,
                ticket_auto_approve_existing_access=True,
                ticket_max_duration_seconds=28800,
                ticket_max_uses=None,
                ticket_require_description=False,
            ),
        ),
        expected_statuses={201},
    ),
    AdminApiTestCase(
        id="get_ticket_requests",
        permission="ticket_requests_manage",
        call=lambda api, r: api.get_ticket_requests_with_http_info(),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="approve_ticket_request",
        permission="ticket_requests_manage",
        call=lambda api, r: api.approve_ticket_request_with_http_info(r["ticket_request_id"]),
        expected_statuses={200, 404},
    ),
    AdminApiTestCase(
        id="deny_ticket_request",
        permission="ticket_requests_manage",
        call=lambda api, r: api.deny_ticket_request_with_http_info(
            r["ticket_request_id"],
            sdk.DenyTicketRequestBody(reason="test"),
        ),
        expected_statuses={200, 404},
    ),
    AdminApiTestCase(
        id="check_ssh_host_key",
        permission="targets_edit",
        call=lambda api, r: api.check_ssh_host_key_with_http_info(
            sdk.CheckSshHostKeyRequest(host="127.0.0.1", port=22),
        ),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="get_certificate_credentials",
        permission="users_edit",
        call=lambda api, r: api.get_certificate_credentials_with_http_info(
            r["user_id"]
        ),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="issue_certificate_credential",
        permission="users_edit",
        call=lambda api, r: api.issue_certificate_credential_with_http_info(
            r["user_id"],
            sdk.IssueCertificateCredentialRequest(
                label="test",
                public_key_pem="-----BEGIN PUBLIC KEY-----\nMFswDQYJKoZIhvcNAQEBBQADSgAwRwJAXWRPQyGlEY+SXz8Uslhe+MLjTgWd8lf/\nnA0hgCm9JFKC1tq1S73cQ9naClNXsMqY7pwPt1bSY8jYRqHHbdoUvwIDAQAB\n-----END PUBLIC KEY-----",
            ),
        ),
        expected_statuses={201},
    ),
    AdminApiTestCase(
        id="update_certificate_credential",
        permission="users_edit",
        call=lambda api, r: api.update_certificate_credential_with_http_info(
            r["user_id"],
            r["certificate_id"],
            sdk.UpdateCertificateCredential(label="test"),
        ),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="revoke_certificate_credential",
        permission="users_edit",
        call=lambda api, r: api.revoke_certificate_credential_with_http_info(
            r["user_id"], r["certificate_id"]
        ),
        expected_statuses={204},
    ),
    AdminApiTestCase(
        id="delete_role",
        permission="access_roles_delete",
        call=lambda api, r: api.delete_role_with_http_info(r["role_id"]),
        expected_statuses={204},
    ),
    AdminApiTestCase(
        id="delete_target",
        permission="targets_delete",
        call=lambda api, r: api.delete_target_with_http_info(r["target_id"]),
        expected_statuses={204},
    ),
    AdminApiTestCase(
        id="delete_user",
        permission="users_delete",
        call=lambda api, r: api.delete_user_with_http_info(r["user_id"]),
        expected_statuses={204},
    ),
    AdminApiTestCase(
        id="delete_ldap_server",
        permission="config_edit",
        call=lambda api, r: api.delete_ldap_server_with_http_info(r["ldap_server_id"]),
        expected_statuses={204},
    ),
    AdminApiTestCase(
        id="delete_admin_role",
        permission="admin_roles_manage",
        call=lambda api, r: api.delete_admin_role_with_http_info(r["admin_role_id"]),
        expected_statuses={204},
    ),
]


def _verify_all_openapi_ops_are_covered():
    schema = load(
        open(
            Path(__file__).resolve().parents[1]
            / "warpgate-web"
            / "src"
            / "admin"
            / "lib"
            / "openapi-schema.json"
        )
    )
    schema_ops = {
        op.get("operationId")
        for methods in schema.get("paths", {}).values()
        for op in methods.values()
        if op.get("operationId")
    }
    missing = schema_ops - {c.id for c in ADMIN_API_TEST_CASES}
    assert not missing, f"Missing test cases for operations: {sorted(missing)}"


def _create_admin_role(admin_api: sdk.DefaultApi, payload: dict) -> sdk.AdminRole:
    return admin_api.create_admin_role(sdk.AdminRoleDataRequest(**payload))


def _create_user_with_role(admin_api: sdk.DefaultApi, role_id: str | None):
    user = admin_api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
    admin_api.create_password_credential(
        user.id, sdk.NewPasswordCredential(password="123")
    )
    if role_id:
        admin_api.add_user_admin_role(user.id, role_id)
    return user


def _create_user_api_token(
    base_url: str, username: str, password: str, label: str = "test"
) -> str:
    session = requests.Session()
    session.verify = False

    # Log in to get an authenticated session cookie.
    resp = session.post(
        f"{base_url}/@warpgate/api/auth/login",
        json={"username": username, "password": password},
    )
    resp.raise_for_status()

    expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    token_resp = session.post(
        f"{base_url}/@warpgate/api/profile/api-tokens",
        json={"label": label, "expiry": expiry},
    )
    token_resp.raise_for_status()

    return token_resp.json()["secret"]


def test_all_openapi_admin_operations_permission_enforcement(
    shared_wg: WarpgateProcess, admin_client: sdk.DefaultApi
):
    _verify_all_openapi_ops_are_covered()

    url = f"https://localhost:{shared_wg.http_port}"

    resources: Dict[str, object] = {}
    resources["role_id"] = admin_client.create_role(
        sdk.RoleDataRequest(name=f"role-{uuid4()}")
    ).id
    resources["admin_role_id"] = _create_admin_role(
        admin_client,
        make_limited_admin_role_payload(name=f"admin-role-{uuid4()}"),
    ).id
    resources["target_group_id"] = admin_client.create_target_group(
        sdk.TargetGroupDataRequest(
            name=f"group-{uuid4()}", description="", color=sdk.BootstrapThemeColor.INFO
        )
    ).id
    user = admin_client.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
    resources["user_id"] = user.id
    resources["username"] = user.username

    # fake IDs here
    resources["session_id"] = str(uuid4())
    resources["recording_id"] = str(uuid4())
    resources["ssh_known_host_id"] = str(uuid4())
    resources["ticket_request_id"] = str(uuid4())

    target = admin_client.create_target(
        sdk.TargetDataRequest(
            name=f"target-{uuid4()}",
            options=sdk.TargetOptions(
                sdk.TargetOptionsTargetSSHOptions(
                    kind="Ssh",
                    host="127.0.0.1",
                    port=22,
                    username="user",
                    auth=sdk.SSHTargetAuth(
                        sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                    ),
                )
            ),
        )
    )
    resources["target_id"] = target.id
    resources["target_name"] = target.name

    ticket = admin_client.create_ticket(
        sdk.CreateTicketRequest(username="test", target_name=resources["target_name"])
    )
    resources["ticket_id"] = ticket.ticket.id

    pw = admin_client.create_password_credential(
        resources["user_id"], sdk.NewPasswordCredential(password="123")
    )
    resources["password_id"] = pw.id
    sso = admin_client.create_sso_credential(
        resources["user_id"],
        sdk.NewSsoCredential(email="test@example.com", provider="test"),
    )
    resources["sso_id"] = sso.id
    public_key = admin_client.create_public_key_credential(
        resources["user_id"],
        sdk.NewPublicKeyCredential(
            label="key",
            openssh_public_key="ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKL5C+OCN2hAbPoR+mwG4M402Z0XVDOuV5k7n6zCRIMsgnYiyz6a61Zcw/RRHoQAb7ndqUyk8eAi9gjPEiGq2d0=",
        ),
    )
    resources["public_key_id"] = public_key.id
    otp = admin_client.create_otp_credential(
        resources["user_id"], sdk.NewOtpCredential(name="otp-1", secret_key=[1, 2, 3])
    )
    resources["otp_id"] = otp.id
    cert = admin_client.issue_certificate_credential(
        resources["user_id"],
        sdk.IssueCertificateCredentialRequest(
            label="test",
            public_key_pem="-----BEGIN PUBLIC KEY-----\nMFswDQYJKoZIhvcNAQEBBQADSgAwRwJAXWRPQyGlEY+SXz8Uslhe+MLjTgWd8lf/\nnA0hgCm9JFKC1tq1S73cQ9naClNXsMqY7pwPt1bSY8jYRqHHbdoUvwIDAQAB\n-----END PUBLIC KEY-----",
        ),
    )
    resources["certificate_id"] = cert.credential.id
    ldap = admin_client.create_ldap_server(
        sdk.CreateLdapServerRequest(
            name=f"ldap-{uuid4()}",
            host="127.0.0.1",
            bind_dn="cn=admin,dc=example,dc=org",
            bind_password="pass",
        )
    )
    resources["ldap_server_id"] = ldap.id

    for case in ADMIN_API_TEST_CASES:
        # Positive case: role has required permission (or any admin if None).
        allow_payload = make_limited_admin_role_payload(
            **({case.permission: True} if case.permission else {})
        )
        allowed_role = _create_admin_role(admin_client, allow_payload)
        allowed_user = _create_user_with_role(admin_client, allowed_role.id)
        token = _create_user_api_token(url, allowed_user.username, "123")
        with new_admin_client(url, token) as allowed_api:
            try:
                response = case.call(allowed_api, resources)
                (status, body) = response.status_code, response.data
            except sdk.ApiException as e:
                (status, body) = e.status, e.body
            assert status in case.expected_statuses, (
                f"{case.id} expected {case.expected_statuses} but got {status}: {body}"
            )

            # Negative case: permission missing should be rejected.
            if case.permission:
                denied_role = _create_admin_role(
                    admin_client,
                    {
                        k: not v if isinstance(v, bool) else v
                        for k, v in allow_payload.items()
                    },
                )
                denied_user = _create_user_with_role(admin_client, denied_role.id)
            else:
                denied_user = _create_user_with_role(admin_client, None)

            denied_token = _create_user_api_token(url, denied_user.username, "123")

            with new_admin_client(
                f"https://localhost:{shared_wg.http_port}", denied_token
            ) as denied_api:
                try:
                    response = case.call(denied_api, resources)
                    (status, body) = response.status_code, response.data
                except sdk.ApiException as e:
                    (status, body) = e.status, e.body
                assert status in {401, 403}, (
                    f"{case.id} should be forbidden without {case.permission}, got {status}: {body}"
                )

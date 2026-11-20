"""
This test runs against Postgres for a better chance to catch
DB field type related issues that don't surface on SQLite (e.g. timestamp types)
"""

import base64
import contextlib
import hashlib
import hmac
import json
import os
import time
import subprocess
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Set
from json import load
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
import requests

from .api_client import sdk, admin_client as new_admin_client
from .conftest import ProcessManager, WarpgateProcess, binary_path, cargo_root
from .test_http_common import *  # noqa
from .util import wait_port


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


def _ssh_target_request(name: str) -> sdk.TargetDataRequest:
    return sdk.TargetDataRequest(
        name=name,
        require_approval=False,
        ticket_requests_disabled=False,
        ticket_require_approval=False,
        options=sdk.TargetOptions(
            sdk.TargetOptionsTargetSSHOptions(
                kind="Ssh",
                allow_insecure_algos=False,
                host="127.0.0.1",
                port=22,
                username="user",
                auth=sdk.SSHTargetAuth(
                    sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                ),
            )
        ),
    )


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
        "approve_sessions": False,
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
        id="get_session_approvals",
        permission="approve_sessions",
        call=lambda api, r: api.get_session_approvals_with_http_info(),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="approve_session",
        permission="approve_sessions",
        call=lambda api, r: api.approve_session_with_http_info(
            r["session_id"],
            sdk.ApproveSessionRequest(
                scope=sdk.ApprovalScope.ONCE, target="no-such-target"
            ),
        ),
        expected_statuses={200, 404},
    ),
    AdminApiTestCase(
        id="reject_session",
        permission="approve_sessions",
        call=lambda api, r: api.reject_session_with_http_info(
            r["session_id"], sdk.RejectSessionRequest(target="no-such-target")
        ),
        expected_statuses={200, 404},
    ),
    AdminApiTestCase(
        id="get_recording",
        permission="recordings_view",
        call=lambda api, r: api.get_recording_with_http_info(r["recording_id"]),
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
        id="release_role",
        permission="config_edit",
        call=lambda api, r: api.release_role_with_http_info(r["role_id"]),
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
        id="import_ssh_own_key_reference",
        permission="config_edit",
        call=lambda api, r: api.import_ssh_own_key_reference_with_http_info(
            sdk.ImportSshClientKeyReferenceRequest(
                label=f"key-{uuid4()}",
                reference="secret://not-configured/secret/key#private_key",
                is_default=False,
            )
        ),
        expected_statuses={400},
    ),
    AdminApiTestCase(
        id="get_secret_backends",
        permission="config_edit",
        call=lambda api, r: api.get_secret_backends_with_http_info(),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="get_secret_backends_summary",
        permission=None,
        call=lambda api, r: api.get_secret_backends_summary_with_http_info(),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="get_secret_reference_usage",
        permission="targets_edit",
        call=lambda api, r: api.get_secret_reference_usage_with_http_info(str(uuid4())),
        expected_statuses={404},
    ),
    AdminApiTestCase(
        id="create_secret_backend",
        permission="config_edit",
        call=lambda api, r: api.create_secret_backend_with_http_info(
            sdk.SecretBackendRequest(
                name=f"vault-{uuid4().hex[:8]}",
                backend_type="vault",
                address="https://vault.invalid:8200",
                auth=sdk.SecretBackendAuth(
                    sdk.SecretBackendAuthVaultTokenAuth(method="Token", token="test")
                ),
            )
        ),
        expected_statuses={201},
    ),
    AdminApiTestCase(
        id="get_secret_backend",
        permission=None,
        call=lambda api, r: api.get_secret_backend_with_http_info(str(uuid4())),
        expected_statuses={404},
    ),
    AdminApiTestCase(
        id="update_secret_backend",
        permission="config_edit",
        call=lambda api, r: api.update_secret_backend_with_http_info(
            str(uuid4()),
            sdk.SecretBackendRequest(
                name="vault-missing",
                backend_type="vault",
                address="https://vault.invalid:8200",
                auth=sdk.SecretBackendAuth(sdk.SecretBackendAuthVaultTokenAuth(method="Token", token="")),
            ),
        ),
        expected_statuses={404},
    ),
    AdminApiTestCase(
        id="delete_secret_backend",
        permission="config_edit",
        call=lambda api, r: api.delete_secret_backend_with_http_info(str(uuid4())),
        expected_statuses={404},
    ),
    AdminApiTestCase(
        id="check_secret_backend_health",
        permission="config_edit",
        call=lambda api, r: api.check_secret_backend_health_with_http_info(str(uuid4())),
        expected_statuses={404},
    ),
    AdminApiTestCase(
        id="test_secret_resolve",
        permission="targets_edit",
        call=lambda api, r: api.test_secret_resolve_with_http_info(
            sdk.TestResolveRequest(
                reference="secret://not-configured/secret/x#password"
            )
        ),
        expected_statuses={404},
    ),
    AdminApiTestCase(
        id="import_ssh_own_key",
        permission="config_edit",
        call=lambda api, r: api.import_ssh_own_key_with_http_info(
            sdk.ImportSshClientKeyRequest(
                label=f"key-{uuid4()}",
                secret_key=open("ssh-keys/id_ed25519").read(),
                is_default=False,
            )
        ),
        expected_statuses={201, 409},
    ),
    AdminApiTestCase(
        id="generate_ssh_own_key",
        permission="config_edit",
        call=lambda api, r: api.generate_ssh_own_key_with_http_info(
            sdk.GenerateSSHClientKeyRequest(
                label=f"key-{uuid4()}", kind=sdk.SSHClientKeyKind.ED25519
            )
        ),
        expected_statuses={201},
    ),
    AdminApiTestCase(
        id="update_ssh_own_key",
        permission="config_edit",
        call=lambda api, r: api.update_ssh_own_key_with_http_info(
            r["ssh_client_key_id"],
            sdk.UpdateSSHClientKeyRequest(label=f"key-{uuid4()}", is_default=False),
        ),
        expected_statuses={200, 404},
    ),
    AdminApiTestCase(
        id="release_ssh_own_key",
        permission="config_edit",
        call=lambda api, r: api.release_ssh_own_key_with_http_info(
            r["ssh_client_key_id"]
        ),
        expected_statuses={200, 404},
    ),
    AdminApiTestCase(
        id="delete_ssh_own_key",
        permission="config_edit",
        call=lambda api, r: api.delete_ssh_own_key_with_http_info(
            r["ssh_client_key_id"]
        ),
        expected_statuses={204, 400, 404},
    ),
    AdminApiTestCase(
        id="get_logs",
        permission=None,
        # A non-empty search is what actually exercises the filter - an empty one
        # is skipped, hiding e.g. Postgres rejecting lower() on the JSON column
        call=lambda api, r: api.get_logs_with_http_info(
            sdk.GetLogsRequest(search="test")
        ),
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
            _ssh_target_request(f"target-{uuid4()}"),
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
            _ssh_target_request(f"target-{uuid4()}"),
        ),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="release_target",
        permission="config_edit",
        call=lambda api, r: api.release_target_with_http_info(r["target_id"]),
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
        id="release_target_group",
        permission="config_edit",
        call=lambda api, r: api.release_target_group_with_http_info(
            r["target_group_id"]
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
        id="sync_gitops",
        permission="config_edit",
        call=lambda api, r: api.sync_gitops_with_http_info(sdk.SyncGitopsRequest()),
        expected_statuses={200, 400},
    ),
    AdminApiTestCase(
        id="dry_run_gitops",
        permission="config_edit",
        call=lambda api, r: api.dry_run_gitops_with_http_info(sdk.SyncGitopsRequest()),
        expected_statuses={200, 400},
    ),
    AdminApiTestCase(
        id="export_gitops_unmanaged",
        permission="config_edit",
        call=lambda api, r: api.export_gitops_unmanaged_with_http_info(),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="get_gitops_history",
        permission=None,
        call=lambda api, r: api.get_gitops_history_with_http_info(),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="get_gitops_history_latest",
        permission=None,
        call=lambda api, r: api.get_gitops_history_latest_with_http_info(),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="update_parameters",
        permission="config_edit",
        call=lambda api, r: api.update_parameters_with_http_info(
            sdk.ParameterUpdate(
                allow_own_credential_management=True,
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
        id="set_logo",
        permission="config_edit",
        call=lambda api, r: api.set_logo_with_http_info(
            sdk.LogoUpdate(logo="data:image/png;base64,iVBORw0KGgo=")
        ),
        expected_statuses={201},
    ),
    AdminApiTestCase(
        id="delete_logo",
        permission="config_edit",
        call=lambda api, r: api.delete_logo_with_http_info(),
        expected_statuses={204},
    ),
    AdminApiTestCase(
        id="test_recordings_storage",
        permission="config_edit",
        call=lambda api, r: api.test_recordings_storage_with_http_info(
            sdk.RecordingsStorageConfig(
                sdk.RecordingsStorageConfigRecordingsDiskConfig(
                    kind="Disk", path="/tmp/recordings-test"
                )
            )
        ),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="get_analytics_preview",
        permission="config_edit",
        call=lambda api, r: api.get_analytics_preview_with_http_info(normal=True),
        expected_statuses={200},
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
        call=lambda api, r: api.approve_ticket_request_with_http_info(
            r["ticket_request_id"]
        ),
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
            sdk.CheckSshHostKeyRequest(target_id=r["target_id"]),
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
        id="get_user_role",
        permission=None,
        call=lambda api, r: api.get_user_role_with_http_info(
            r["user_id"], r["role_id"]
        ),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="update_user_role",
        permission="access_roles_assign",
        call=lambda api, r: api.update_user_role_with_http_info(
            r["user_id"],
            r["role_id"],
            sdk.UpdateUserRoleRequest(
                expires_at=(datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
            ),
        ),
        expected_statuses={200},
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
    AdminApiTestCase(
        id="get_security_status",
        permission=None,
        call=lambda api, r: api.get_security_status_with_http_info(),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="list_blocked_ips",
        permission=None,
        call=lambda api, r: api.list_blocked_ips_with_http_info(),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="unblock_ip",
        permission="config_edit",
        call=lambda api, r: api.unblock_ip_with_http_info(
            sdk.UnblockIpRequest(ip="127.0.0.1")
        ),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="list_locked_users",
        permission=None,
        call=lambda api, r: api.list_locked_users_with_http_info(),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="unlock_user",
        permission="config_edit",
        call=lambda api, r: api.unlock_user_with_http_info("nonexistent-user"),
        expected_statuses={200, 404},
    ),
    AdminApiTestCase(
        id="get_listener_states",
        permission="config_edit",
        call=lambda api, r: api.get_listener_states_with_http_info(),
        expected_statuses={200},
    ),
    AdminApiTestCase(
        id="get_ip_echo",
        permission="config_edit",
        call=lambda api, r: api.get_ip_echo_with_http_info(),
        expected_statuses={200},
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


@pytest.fixture(scope="session")
def pg_wg(processes: ProcessManager):
    db_port = processes.start_postgres_server()
    wg = processes.start_wg(
        database_url=f"postgres://user:123@localhost:{db_port}/db",
    )
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    wait_port(wg.ssh_port, for_process=wg.process)
    wait_port(wg.kubernetes_port, for_process=wg.process, recv=False)
    yield wg


@pytest.fixture
def admin_client(pg_wg: WarpgateProcess):
    url = f"https://localhost:{pg_wg.http_port}"
    with new_admin_client(url) as api:
        yield api


@pytest.fixture(scope="session")
def _session_admin_client(pg_wg: WarpgateProcess):
    url = f"https://localhost:{pg_wg.http_port}"
    with new_admin_client(url) as api:
        yield api


@pytest.fixture(scope="session")
def api_test_resources(
    pg_wg: WarpgateProcess, _session_admin_client: sdk.DefaultApi
) -> Dict[str, object]:
    _verify_all_openapi_ops_are_covered()

    ac = _session_admin_client
    resources: Dict[str, object] = {}
    resources["role_id"] = ac.create_role(
        sdk.RoleDataRequest(name=f"role-{uuid4()}")
    ).id
    resources["admin_role_id"] = _create_admin_role(
        ac,
        make_limited_admin_role_payload(name=f"admin-role-{uuid4()}"),
    ).id
    resources["target_group_id"] = ac.create_target_group(
        sdk.TargetGroupDataRequest(
            name=f"group-{uuid4()}", description="", color=sdk.BootstrapThemeColor.INFO
        )
    ).id
    user = ac.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
    resources["user_id"] = user.id
    resources["username"] = user.username

    # fake IDs here
    resources["session_id"] = str(uuid4())
    resources["recording_id"] = str(uuid4())
    resources["ssh_known_host_id"] = str(uuid4())
    resources["ssh_client_key_id"] = str(uuid4())
    resources["ticket_request_id"] = str(uuid4())

    target = ac.create_target(_ssh_target_request(f"target-{uuid4()}"))
    resources["target_id"] = target.id
    resources["target_name"] = target.name

    ticket = ac.create_ticket(
        sdk.CreateTicketRequest(
            username=resources["username"], target_name=resources["target_name"]
        )
    )
    resources["ticket_id"] = ticket.ticket.id

    pw = ac.create_password_credential(
        resources["user_id"], sdk.NewPasswordCredential(password="123")
    )
    resources["password_id"] = pw.id
    sso = ac.create_sso_credential(
        resources["user_id"],
        sdk.NewSsoCredential(email="test@example.com", provider="test"),
    )
    resources["sso_id"] = sso.id
    public_key = ac.create_public_key_credential(
        resources["user_id"],
        sdk.NewPublicKeyCredential(
            label="key",
            openssh_public_key="ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKL5C+OCN2hAbPoR+mwG4M402Z0XVDOuV5k7n6zCRIMsgnYiyz6a61Zcw/RRHoQAb7ndqUyk8eAi9gjPEiGq2d0=",
        ),
    )
    resources["public_key_id"] = public_key.id
    otp = ac.create_otp_credential(
        resources["user_id"], sdk.NewOtpCredential(name="otp-1", secret_key=[1, 2, 3])
    )
    resources["otp_id"] = otp.id
    cert = ac.issue_certificate_credential(
        resources["user_id"],
        sdk.IssueCertificateCredentialRequest(
            label="test",
            public_key_pem="-----BEGIN PUBLIC KEY-----\nMFswDQYJKoZIhvcNAQEBBQADSgAwRwJAXWRPQyGlEY+SXz8Uslhe+MLjTgWd8lf/\nnA0hgCm9JFKC1tq1S73cQ9naClNXsMqY7pwPt1bSY8jYRqHHbdoUvwIDAQAB\n-----END PUBLIC KEY-----",
        ),
    )
    resources["certificate_id"] = cert.credential.id
    ldap = ac.create_ldap_server(
        sdk.CreateLdapServerRequest(
            name=f"ldap-{uuid4()}",
            host="127.0.0.1",
            bind_dn="cn=admin,dc=example,dc=org",
            bind_password="pass",
        )
    )
    resources["ldap_server_id"] = ldap.id

    return resources


@pytest.mark.parametrize(
    "case",
    ADMIN_API_TEST_CASES,
    ids=[c.id for c in ADMIN_API_TEST_CASES],
)
def test_admin_api_permission_enforcement(
    pg_wg: WarpgateProcess,
    admin_client: sdk.DefaultApi,
    api_test_resources: Dict[str, object],
    case: AdminApiTestCase,
):
    url = f"https://localhost:{pg_wg.http_port}"

    # Base-check endpoints (permission=None) admit any admin. An admin holds at least one
    # permission — a permissionless role is not a real admin — so grant a benign baseline.
    allow_payload = make_limited_admin_role_payload(
        **({case.permission: True} if case.permission else {"sessions_view": True})
    )
    allowed_role = _create_admin_role(admin_client, allow_payload)
    allowed_user = _create_user_with_role(admin_client, allowed_role.id)
    token = _create_user_api_token(url, allowed_user.username, "123")
    with new_admin_client(url, token) as allowed_api:
        try:
            response = case.call(allowed_api, api_test_resources)
            status, body = response.status_code, response.data
        except sdk.ApiException as e:
            status, body = e.status, e.body
        assert (
            status in case.expected_statuses
        ), f"{case.id} expected {case.expected_statuses} but got {status}: {body}"

    if case.permission:
        denied_role = _create_admin_role(
            admin_client,
            {k: not v if isinstance(v, bool) else v for k, v in allow_payload.items()},
        )
        denied_user = _create_user_with_role(admin_client, denied_role.id)
    else:
        denied_user = _create_user_with_role(admin_client, None)

    denied_token = _create_user_api_token(url, denied_user.username, "123")
    with new_admin_client(url, denied_token) as denied_api:
        try:
            response = case.call(denied_api, api_test_resources)
            status, body = response.status_code, response.data
        except sdk.ApiException as e:
            status, body = e.status, e.body
        assert status in {
            401,
            403,
        }, f"{case.id} should be forbidden without {case.permission}, got {status}: {body}"


def test_admin_cannot_edit_user_with_broader_admin_permissions(
    pg_wg: WarpgateProcess,
    admin_client: sdk.DefaultApi,
):
    url = f"https://localhost:{pg_wg.http_port}"

    narrow_role = _create_admin_role(
        admin_client, make_limited_admin_role_payload(users_edit=True)
    )
    broad_role = _create_admin_role(
        admin_client,
        make_limited_admin_role_payload(users_edit=True, config_edit=True),
    )
    actor = _create_user_with_role(admin_client, narrow_role.id)
    peer = _create_user_with_role(admin_client, narrow_role.id)
    superior = _create_user_with_role(admin_client, broad_role.id)

    token = _create_user_api_token(url, actor.username, "123")
    with new_admin_client(url, token) as api:
        api.create_password_credential(
            peer.id, sdk.NewPasswordCredential(password="456")
        )

        with pytest.raises(sdk.ApiException) as e:
            api.create_password_credential(
                superior.id, sdk.NewPasswordCredential(password="456")
            )
        assert e.value.status == 403

        with pytest.raises(sdk.ApiException) as e:
            api.update_user(
                superior.id, sdk.UserDataRequest(username=superior.username)
            )
        assert e.value.status == 403


def test_update_target_must_state_the_approval_gate(
    pg_wg: WarpgateProcess, admin_client: sdk.DefaultApi
):
    # The gate is a required field of every target write: a client that
    # predates it — or simply doesn't set it — is rejected outright rather
    # than silently taking the gate off a target by saving the rest of it.
    # The generated client can't express the omission, so raw JSON it is.
    gated = _ssh_target_request(f"gated-{uuid4()}")
    gated.require_approval = True
    target = admin_client.create_target(gated)
    assert target.require_approval

    url = f"https://localhost:{pg_wg.http_port}"
    session = requests.Session()
    session.verify = False
    session.headers["X-Warpgate-Token"] = "token-value"
    body = admin_client.get_target(target.id).to_dict()
    del body["require_approval"]
    silent = session.put(f"{url}/@warpgate/admin/api/targets/{target.id}", json=body)
    assert silent.status_code == 400, (
        "an update that says nothing about the gate must be refused, "
        f"got {silent.status_code}"
    )
    assert admin_client.get_target(
        target.id
    ).require_approval, "and must not have touched it"

    # Turning it off is an ordinary, explicit edit.
    off = _ssh_target_request(target.name)
    off.require_approval = False
    admin_client.update_target(target.id, off)
    assert not admin_client.get_target(target.id).require_approval


def test_provider_cannot_be_set_by_clients(pg_wg):
    """`provider` marks rows a reconciler owns; the server alone sets it."""
    url = f"https://localhost:{pg_wg.http_port}/@warpgate/admin/api"
    session = requests.Session()
    session.verify = False
    session.headers["X-Warpgate-Token"] = "token-value"
    name = f"forged-{uuid4()}"

    # Where each kind is created and updated, with a body both calls accept
    for create, update, body in [
        ("targets", "targets", _ssh_target_request(name).to_dict()),
        ("roles", "role", {"name": name}),
        ("target-groups", "target-groups", {"name": name}),
        (
            "ssh/own-keys/generate",
            "ssh/own-keys",
            {"label": name, "kind": "Ed25519", "is_default": False},
        ),
    ]:
        body["provider"] = "00000000-0000-0000-0000-000000000000"
        created = session.post(f"{url}/{create}", json=body)
        assert created.status_code == 201, created.text
        assert created.json()["provider"] is None, create
        updated = session.put(f"{url}/{update}/{created.json()['id']}", json=body)
        assert updated.status_code == 200, updated.text
        assert updated.json()["provider"] is None, update


def _poll_logs(
    admin_client: sdk.DefaultApi,
    request: sdk.GetLogsRequest,
    collect: Callable,
    done: Callable,
):
    """Re-reads the log for up to 10 s until `done` accepts `collect(entries)`,
    and returns that. Log entries reach the database asynchronously"""
    deadline = time.monotonic() + 10
    while True:
        found = collect(admin_client.get_logs(request))
        if done(found) or time.monotonic() > deadline:
            return found
        time.sleep(0.5)


def _audited(admin_client: sdk.DefaultApi, count: int, **values: str) -> list[dict]:
    """Audit entries carrying `values`, waiting up to 10 s for `count` of them."""
    return _poll_logs(
        admin_client,
        sdk.GetLogsRequest(limit=500),
        lambda entries: [
            entry.values or {}
            for entry in entries
            if values.items() <= (entry.values or {}).items()
        ],
        lambda found: len(found) >= count,
    )


def _config(wg, *args: str) -> subprocess.CompletedProcess:
    """Runs a `warpgate config` subcommand against a running instance's database."""
    return subprocess.run(
        [os.path.join(cargo_root, binary_path), "--config", str(wg.config_path), "config", *args],
        cwd=cargo_root,
        env={
            **os.environ,
            "LLVM_PROFILE_FILE": f"{cargo_root}/target/llvm-cov-target/warpgate-%m.profraw",
            "WARPGATE_UNDER_TEST": "1",
        },
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_gitops_rows_are_read_only_through_the_api(
    admin_client: sdk.DefaultApi, pg_wg, tmp_path
):
    name = f"gitops-{uuid4()}"
    files = tmp_path / "gitops"
    files.mkdir()
    resource = files / "resources.yaml"
    key_path = tmp_path / "key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key_path)], check=True
    )
    private_key = "\n".join("    " + line for line in key_path.read_text().splitlines())

    def write(port: int):
        resource.write_text(
            f"""apiVersion: warpgate/v1
kind: Role
metadata:
  name: {name}
spec: {{}}
---
apiVersion: warpgate/v1
kind: TargetGroup
metadata:
  name: {name}
spec: {{}}
---
apiVersion: warpgate/v1
kind: SshClientKey
metadata:
  name: {name}
spec:
  private_key: |
{private_key}
---
apiVersion: warpgate/v1
kind: Target
metadata:
  name: {name}
spec:
  group: {name}
  roles: [{name}]
  options:
    ssh:
      host: 127.0.0.1
      port: {port}
      username: user
      auth:
        kind: publickey
        key_id: {name}
"""
        )

    write(22)
    planned = _config(pg_wg, "plan", str(files))
    assert planned.returncode == 3, planned.stdout + planned.stderr
    applied = _config(pg_wg, "apply", "--yes", str(files))
    assert applied.returncode == 0, applied.stdout + applied.stderr
    assert _config(pg_wg, "plan", str(files)).returncode == 0
    recorded = admin_client.get_gitops_history().items[0]
    assert (recorded.triggered_by, recorded.status) == ("Cli", "Applied")
    assert recorded.stats.create == 4
    assert len(_audited(admin_client, 5, sync_id=str(recorded.id))) == 5

    target = next(t for t in admin_client.get_targets() if t.name == name)
    role = next(r for r in admin_client.get_roles() if r.name == name)
    group = admin_client.get_target_group(target.group_id)
    assert target.provider.id == "00000000-0000-0000-0000-000000000000"
    assert target.provider.label == "GitOps"
    assert role.provider == target.provider
    assert group.provider == target.provider
    key = next(k for k in admin_client.get_ssh_own_keys() if k.label == name)
    assert key.provider == target.provider
    assert target.options.actual_instance.auth.actual_instance.key_id == key.id
    other = admin_client.create_role(sdk.RoleDataRequest(name=f"manual-{uuid4()}"))

    for call in [
        lambda: admin_client.update_target(target.id, _ssh_target_request(name)),
        lambda: admin_client.delete_target(target.id),
        lambda: admin_client.add_target_role(target.id, other.id),
        lambda: admin_client.delete_target_role(target.id, role.id),
        lambda: admin_client.update_role(role.id, sdk.RoleDataRequest(name=name)),
        lambda: admin_client.delete_role(role.id),
        lambda: admin_client.delete_target_group(group.id),
        lambda: admin_client.update_ssh_own_key(
            key.id, sdk.UpdateSSHClientKeyRequest(label=name, is_default=False)
        ),
        lambda: admin_client.delete_ssh_own_key(key.id),
    ]:
        with pytest.raises(sdk.ApiException) as err:
            call()
        assert err.value.status == 409, err.value.body
        assert "managed by GitOps" in err.value.body

    # Edits to the file still go through
    write(2222)
    assert _config(pg_wg, "plan", str(files)).returncode == 3
    applied = _config(pg_wg, "apply", "--yes", str(files))
    assert applied.returncode == 0, applied.stdout + applied.stderr
    assert admin_client.get_target(target.id).options.actual_instance.port == 2222

    # Released rows are the admin's again, and the files now collide with them
    released = [
        admin_client.release_target(target.id),
        admin_client.release_target_group(group.id),
        admin_client.release_role(role.id),
        admin_client.release_ssh_own_key(key.id),
    ]
    assert [r.provider for r in released] == [None] * 4
    assert _audited(
        admin_client, 1, _type="ProviderResourceReleased1", id=str(target.id)
    )
    admin_client.delete_target_role(target.id, role.id)
    planned = _config(pg_wg, "plan", str(files))
    assert planned.returncode == 1, planned.stdout + planned.stderr


def test_gitops_syncs_from_a_git_repository(
    admin_client: sdk.DefaultApi, pg_wg: WarpgateProcess, tmp_path
):
    name = f"synced-{uuid4()}"
    repo = tmp_path / "repo"
    (repo / "warpgate").mkdir(parents=True)

    def git(*args: str) -> str:
        return subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def commit(port: int) -> str:
        (repo / "warpgate" / "resources.yaml").write_text(
            f"""apiVersion: warpgate/v1
kind: Role
metadata:
  name: {name}
spec: {{}}
---
apiVersion: warpgate/v1
kind: Target
metadata:
  name: {name}
spec:
  roles: [{name}]
  options:
    ssh:
      host: 127.0.0.1
      port: {port}
      username: user
"""
        )
        git("add", ".")
        git("commit", "-qm", str(port))
        return git("rev-parse", "HEAD")

    git("init", "-q", "-b", "main")
    commit(22)
    second = commit(2222)

    def audited(sync_id: str, count: int) -> list[dict]:
        return _audited(admin_client, count, sync_id=str(sync_id))

    def port() -> int:
        target = next(t for t in admin_client.get_targets() if t.name == name)
        assert target.provider.id == "00000000-0000-0000-0000-000000000000"
        return target.options.actual_instance.port

    # Raw JSON: clearing needs an explicit null, which the generated client
    # drops along with every other None field
    session = requests.Session()
    session.verify = False
    session.headers["X-Warpgate-Token"] = "token-value"
    parameters = f"https://localhost:{pg_wg.http_port}/@warpgate/admin/api/parameters"

    source = {"kind": "Git", "url": f"file://{repo}", "reference": "main", "path": "warpgate"}
    assert session.put(parameters, json={"gitops_source": source}).status_code // 100 == 2
    try:
        dry = admin_client.dry_run_gitops(sdk.SyncGitopsRequest())
        assert (dry.revision, dry.error) == (second, None)
        assert sorted((c.action, c.kind) for c in dry.plan) == [
            ("create", "Role"),
            ("create", "Target"),
        ]
        assert all(t.name != name for t in admin_client.get_targets()), "a dry run applies nothing"

        with pytest.raises(sdk.ApiException) as err:
            admin_client.sync_gitops(sdk.SyncGitopsRequest(yaml="{}"))
        assert err.value.status == 400, "a source and pushed files exclude each other"
        pushed = admin_client.dry_run_gitops(sdk.SyncGitopsRequest(yaml="{}"))
        assert pushed.source == "request", "a dry run of pushed files writes nothing"
        applied = _config(pg_wg, "apply", "--yes", str(repo / "warpgate"))
        assert applied.returncode == 1, applied.stdout + applied.stderr
        assert "a GitOps source is configured" in applied.stderr

        head = admin_client.sync_gitops(sdk.SyncGitopsRequest())
        assert (head.status, head.revision, head.error) == ("Applied", second, None)
        assert (head.stats.create, head.stats.update) == (2, 0)
        assert port() == 2222
        assert f"file://{repo}@main" in head.source
        entries = audited(head.id, 4)
        assert {(e["_type"], e.get("action"), e.get("kind"), e.get("name")) for e in entries} == {
            ("ProviderSynced1", None, None, None),
            ("ResourceChanged1", "Create", "Role", name),
            ("ResourceChanged1", "Create", "Target", name),
            ("TargetRoleAdded1", None, None, None),
        }
        [granted] = [e for e in entries if e["_type"] == "TargetRoleAdded1"]
        assert (granted["target_name"], granted["role_name"]) == (name, name)
        role_id = next(r.id for r in admin_client.get_roles() if r.name == name)
        assert granted["related_access_roles"] == f"${role_id}$"

        again = admin_client.sync_gitops(sdk.SyncGitopsRequest())
        assert again.id == head.id, "an unchanged sync extends the latest row"
        assert [row.revision for row in admin_client.get_gitops_history().items[:1]] == [second]
        assert len(audited(head.id, 5)) == 4, "an unchanged sync is not audited again"

        webhook = f"https://localhost:{pg_wg.http_port}/@warpgate/api/gitops/webhook"

        body = b'{"ref": "refs/heads/main"}'

        def deliver(secret: bytes, body: bytes = body) -> int:
            signature = hmac.new(secret, body, hashlib.sha256).hexdigest()
            return requests.post(
                webhook,
                data=body,
                headers={"X-Hub-Signature-256": f"sha256={signature}"},
                verify=False,
            ).status_code

        secret = b"webhook-secret-0123"
        assert deliver(secret) == 404, "no webhook secret configured"
        assert (
            session.put(
                parameters, json={"gitops_webhook_secret": secret.decode()}
            ).status_code
            // 100
            == 2
        )
        assert deliver(b"wrong-secret-0123") == 401
        third = commit(2200)
        # A push with many commits is far over the body limit of other routes.
        assert deliver(secret, b"x" * 1_000_000) == 202
        deadline = time.monotonic() + 30
        while (latest := admin_client.get_gitops_history().items[0]).triggered_by != "Webhook":
            assert time.monotonic() < deadline, "the webhook never synced"
            time.sleep(0.5)
        assert (latest.status, latest.revision) == ("Applied", third)
        assert port() == 2200
        [update] = [e for e in audited(latest.id, 2) if e["_type"] == "ResourceChanged1"]
        assert (update["action"], update["kind"], update["name"]) == ("Update", "Target", name)
        assert '"from":2222' in update["fields"] and '"to":2200' in update["fields"]

        def deliver_with(headers: Dict[str, str]) -> int:
            return requests.post(webhook, data=body, headers=headers, verify=False).status_code

        bitbucket = hmac.new(secret, body, hashlib.sha256).hexdigest()
        assert deliver_with({"X-Hub-Signature": f"sha256={bitbucket}"}) == 202
        assert deliver_with({"Authorization": basic_auth("azure", secret.decode())}) == 202
        assert deliver_with({"Authorization": basic_auth("azure", "wrong-secret-0123")}) == 401
    finally:
        cleared = {"gitops_source": None, "gitops_webhook_secret": None}
        assert session.put(parameters, json=cleared).status_code // 100 == 2

    with pytest.raises(sdk.ApiException) as err:
        admin_client.sync_gitops(sdk.SyncGitopsRequest())
    assert err.value.status == 400
    with pytest.raises(sdk.ApiException) as err:
        admin_client.dry_run_gitops(sdk.SyncGitopsRequest())
    assert err.value.status == 400


def basic_auth(username: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()


def test_gitops_syncs_request_files_and_exports_unmanaged_rows(
    admin_client: sdk.DefaultApi, pg_wg: WarpgateProcess
):
    session = requests.Session()
    session.verify = False
    session.headers["X-Warpgate-Token"] = "token-value"
    parameters = f"https://localhost:{pg_wg.http_port}/@warpgate/admin/api/parameters"
    assert session.put(parameters, json={"gitops_source": None}).status_code // 100 == 2
    assert admin_client.get_parameters().gitops_source is None
    with pytest.raises(sdk.ApiException) as err:
        admin_client.sync_gitops(sdk.SyncGitopsRequest())
    assert err.value.status == 400, "without files or a source there is nothing to sync"

    hand_made = admin_client.create_role(sdk.RoleDataRequest(name=f"by-hand-{uuid4()}"))
    exported = admin_client.export_gitops_unmanaged()
    assert f"name: {hand_made.name}" in exported
    assert "adopt_existing: true" in exported
    assert _audited(admin_client, 1, _type="UnmanagedResourcesExported1")

    name = f"pushed-{uuid4()}"
    files = f"""apiVersion: warpgate/v1
kind: Target
metadata:
  name: {name}
spec:
  roles: [{hand_made.name}]
  options:
    ssh:
      host: 127.0.0.1
      username: user
"""
    dry = admin_client.dry_run_gitops(sdk.SyncGitopsRequest(yaml=files))
    assert (dry.source, dry.error) == ("request", None)
    assert [(c.action, c.name) for c in dry.plan if c.action == "create"] == [("create", name)]

    synced = admin_client.sync_gitops(sdk.SyncGitopsRequest(yaml=files))
    assert (synced.status, synced.source, synced.error) == ("Applied", "request", None)
    target = next(t for t in admin_client.get_targets() if t.name == name)
    assert [r.name for r in admin_client.get_target_roles(target.id)] == [hand_made.name]
    role = admin_client.get_role(hand_made.id)
    assert role.provider is None, "granting a hand-made role does not take it over"

    unknown = files.replace(hand_made.name, f"missing-{uuid4()}")
    failed = admin_client.sync_gitops(sdk.SyncGitopsRequest(yaml=unknown))
    assert failed.status == "Failed"
    assert "unknown Role" in (failed.error or "")


def test_approval_parameters_can_be_cleared_and_reject_nonsense(
    pg_wg: WarpgateProcess, admin_client: sdk.DefaultApi
):
    # The generated clients omit a `None` field rather than sending `null`, so
    # clearing one is only reachable over raw JSON — which is what the admin UI
    # sends when the field is blanked.
    url = f"https://localhost:{pg_wg.http_port}"
    session = requests.Session()
    session.verify = False
    session.headers["X-Warpgate-Token"] = "token-value"
    endpoint = f"{url}/@warpgate/admin/api/parameters"

    def put(**overrides):
        body = admin_client.get_parameters().to_dict()
        body.update(overrides)
        return session.put(endpoint, json=body)

    assert put(admin_approval_grace_period_seconds=300).status_code // 100 == 2
    assert admin_client.get_parameters().admin_approval_grace_period_seconds == 300

    assert put(admin_approval_grace_period_seconds=None).status_code // 100 == 2
    assert (
        admin_client.get_parameters().admin_approval_grace_period_seconds is None
    ), "an explicit null must turn approval caching off, not be ignored"

    for field in (
        "admin_approval_grace_period_seconds",
        "admin_approval_timeout_seconds",
    ):
        assert (
            put(**{field: -1}).status_code == 400
        ), f"{field} must reject a negative window"


def test_update_target_rejects_duplicate_name(admin_client: sdk.DefaultApi):
    first = admin_client.create_target(_ssh_target_request(f"dup-a-{uuid4()}"))
    second = admin_client.create_target(_ssh_target_request(f"dup-b-{uuid4()}"))
    with pytest.raises(sdk.ApiException) as err:
        admin_client.update_target(second.id, _ssh_target_request(first.name))
    assert err.value.status == 409
    still = admin_client.get_target(second.id)
    assert still.name == second.name

    renamed = admin_client.update_target(second.id, _ssh_target_request(second.name))
    assert renamed.name == second.name


def test_update_target_rejects_empty_name(admin_client: sdk.DefaultApi):
    target = admin_client.create_target(_ssh_target_request(f"empty-{uuid4()}"))
    with pytest.raises(sdk.ApiException) as err:
        admin_client.update_target(target.id, _ssh_target_request(""))
    assert err.value.status == 400
    assert admin_client.get_target(target.id).name == target.name


def _logged_in_full_admin(url: str, admin_client: sdk.DefaultApi):
    """Logs in as a new full admin. A request with the admin token has no user
    in its audit entries.
    Returns the admin and a `call(method, path, json)` helper for its session"""
    full_admin = {
        k: True if isinstance(v, bool) else v
        for k, v in make_limited_admin_role_payload().items()
    }
    actor = _create_user_with_role(
        admin_client, _create_admin_role(admin_client, full_admin).id
    )
    session = requests.Session()
    session.verify = False
    login = session.post(
        f"{url}/@warpgate/api/auth/login",
        json={"username": actor.username, "password": "123"},
    )
    assert login.ok, login.text

    def call(method, path, json=None):
        resp = session.request(method, f"{url}/@warpgate{path}", json=json)
        resp.raise_for_status()
        return resp.json() if resp.content else None

    return actor, call


def _wait_for_audit_entries(
    admin_client: sdk.DefaultApi,
    tag: str,
    expected: set,
    key: Callable = lambda values: values.get("_type"),
):
    """Polls the log for entries mentioning `tag` until one exists for each
    `key(values)` in `expected`. Returns them as {key: entry}"""
    return _poll_logs(
        admin_client,
        sdk.GetLogsRequest(search=tag, limit=100),
        lambda entries: {
            key(e.values): e for e in entries if key(e.values or {}) in expected
        },
        lambda found: expected <= found.keys(),
    )


def test_admin_changes_to_roles_and_targets_are_audited(
    pg_wg: WarpgateProcess, admin_client: sdk.DefaultApi
):
    actor, call = _logged_in_full_admin(f"https://localhost:{pg_wg.http_port}", admin_client)

    tag = uuid4().hex
    role = call("POST", "/admin/api/roles", {"name": f"audit-role-{tag}"})
    call("PUT", f"/admin/api/role/{role['id']}", {"name": role["name"], "description": "dbas"})
    group = call("POST", "/admin/api/target-groups", {"name": f"audit-group-{tag}"})
    call(
        "PUT",
        f"/admin/api/target-groups/{group['id']}",
        {"name": group["name"], "description": "prod"},
    )
    key = call(
        "POST", "/admin/api/ssh/own-keys/generate", {"label": f"audit-key-{tag}", "kind": "Ed25519"}
    )
    call(
        "PUT",
        f"/admin/api/ssh/own-keys/{key['id']}",
        {"label": f"audit-key-renamed-{tag}", "is_default": False},
    )
    call("DELETE", f"/admin/api/ssh/own-keys/{key['id']}")

    target_body = _ssh_target_request(f"audit-target-{tag}").to_dict()
    target_body["options"]["auth"] = {"kind": "Password", "password": "old-secret"}
    target = call("POST", "/admin/api/targets", target_body)
    call("PUT", f"/admin/api/targets/{target['id']}", target_body)
    target_body["options"]["port"] = 2222
    target_body["options"]["auth"]["password"] = "new-secret"
    target_body["group_id"] = group["id"]
    call("PUT", f"/admin/api/targets/{target['id']}", target_body)
    call("POST", f"/admin/api/targets/{target['id']}/roles/{role['id']}")
    call("DELETE", f"/admin/api/targets/{target['id']}/roles/{role['id']}")

    user = admin_client.create_user(sdk.CreateUserRequest(username=f"audit-user-{tag}"))
    admin_client.add_user_role(user.id, role["id"])
    admin_client.delete_user_role(user.id, role["id"])
    expiry = datetime.now(timezone.utc) + timedelta(hours=1)
    call(
        "PUT",
        f"/admin/api/users/{user.id}/roles/{role['id']}",
        {"expires_at": expiry.isoformat()},
    )

    call("DELETE", f"/admin/api/targets/{target['id']}")
    call("DELETE", f"/admin/api/target-groups/{group['id']}")
    call("DELETE", f"/admin/api/role/{role['id']}")

    expected = {
        ("ResourceChanged1", action, kind)
        for action in ("Create", "Update", "Delete")
        for kind in ("Role", "Target", "TargetGroup", "SshClientKey")
    } | {
        ("TargetRoleAdded1", None, None),
        ("TargetRoleRemoved1", None, None),
        ("AccessRoleExpiryChanged1", None, None),
    }
    entries = _wait_for_audit_entries(
        admin_client,
        tag,
        expected,
        key=lambda values: (values.get("_type"), values.get("action"), values.get("kind")),
    )

    assert entries.keys() == expected
    assert all(e.username == actor.username for e in entries.values())

    updates = _audited(
        admin_client, 1, _type="ResourceChanged1", action="Update", id=target["id"]
    )
    assert len(updates) == 1, "a save that changes nothing is not audited"
    fields = {field["path"]: field for field in json.loads(updates[0]["fields"])}
    assert fields.keys() == {
        "spec.group",
        "spec.options.ssh.auth.password",
        "spec.options.ssh.port",
    }
    assert (fields["spec.options.ssh.port"]["from"], fields["spec.options.ssh.port"]["to"]) == (22, 2222)
    assert fields["spec.group"]["to"] == group["name"]
    assert "secret" not in updates[0]["fields"]

    created = entries[("ResourceChanged1", "Create", "Target")].values["fields"]
    assert "secret" not in created
    created = {field["path"]: field for field in json.loads(created)}
    assert created["spec.options.ssh.port"] == {"path": "spec.options.ssh.port", "to": 22}
    assert created["spec.options.ssh.auth.password"]["credential"]

    added = entries[("TargetRoleAdded1", None, None)].values
    assert (added["target_name"], added["role_name"]) == (target["name"], role["name"])
    expiry_changed = entries[("AccessRoleExpiryChanged1", None, None)].values
    assert expiry_changed["revocation_cleared"] in (True, "true")
    assert expiry_changed["expires_at"].startswith(expiry.isoformat(timespec="seconds")[:19])


def test_admin_changes_to_configuration_are_audited(
    pg_wg: WarpgateProcess, admin_client: sdk.DefaultApi
):
    actor, call = _logged_in_full_admin(f"https://localhost:{pg_wg.http_port}", admin_client)

    tag = uuid4().hex[:8]
    ldap_body = sdk.UpdateLdapServerRequest(
        name=f"audit-ldap-{tag}",
        host="127.0.0.1",
        bind_dn="cn=admin,dc=example,dc=org",
        bind_password="old-secret",
        auto_link_sso_users=False,
        description="",
        enabled=True,
        port=389,
        ssh_key_attribute="sshPublicKey",
        tls_mode=sdk.TlsMode.DISABLED,
        tls_verify=False,
        user_filter="(uid={0})",
        username_attribute=sdk.LdapUsernameAttribute.UID,
        uuid_attribute="uid",
    ).to_dict()
    ldap = call("POST", "/admin/api/ldap-servers", ldap_body)
    call(
        "PUT",
        f"/admin/api/ldap-servers/{ldap['id']}",
        {**ldap_body, "port": 636, "bind_password": "new-secret"},
    )
    call("DELETE", f"/admin/api/ldap-servers/{ldap['id']}")

    backend_body = sdk.SecretBackendRequest(
        name=f"audit-{tag}",
        backend_type="vault",
        address="https://vault.invalid:8200",
        auth=sdk.SecretBackendAuth(
            sdk.SecretBackendAuthVaultTokenAuth(method="Token", token="old-secret")
        ),
    ).to_dict()
    backend = call("POST", "/admin/api/secret-backends", backend_body)
    call(
        "PUT",
        f"/admin/api/secret-backends/{backend['id']}",
        {
            **backend_body,
            "address": "https://vault2.invalid:8200",
            "auth": {"method": "Token", "token": "new-secret"},
        },
    )
    call("DELETE", f"/admin/api/secret-backends/{backend['id']}")

    known_host = call(
        "POST",
        "/admin/api/ssh/known-hosts",
        {
            "host": f"{tag}.invalid",
            "port": 22,
            "key_type": "ecdsa-sha2-nistp256",
            "key_base64": "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKL5C+OCN2hAbPoR+mwG4M402Z0XVDOuV5k7n6zCRIMsgnYiyz6a61Zcw/RRHoQAb7ndqUyk8eAi9gjPEiGq2d0=",
        },
    )
    call("DELETE", f"/admin/api/ssh/known-hosts/{known_host['id']}")

    call("PUT", "/admin/api/parameters", {"banner": f"audit-{tag}"})
    call("PUT", "/admin/api/parameters", {"banner": ""})

    expected = {
        ("ResourceChanged1", action, kind)
        for kind in ("LdapServer", "SecretBackend")
        for action in ("Create", "Update", "Delete")
    } | {
        ("ResourceChanged1", "Create", "KnownHost"),
        ("ResourceChanged1", "Delete", "KnownHost"),
        ("ResourceChanged1", "Update", "Parameters"),
    }
    entries = _wait_for_audit_entries(
        admin_client,
        tag,
        expected,
        key=lambda values: (values.get("_type"), values.get("action"), values.get("kind")),
    )

    assert entries.keys() == expected
    assert all(e.username == actor.username for e in entries.values())

    def changed(kind: str) -> dict:
        fields = entries[("ResourceChanged1", "Update", kind)].values["fields"]
        assert "secret" not in fields
        return {field["path"]: field for field in json.loads(fields)}

    ldap_fields = changed("LdapServer")
    assert ldap_fields.keys() == {"spec.bind_password", "spec.port"}
    assert ldap_fields["spec.bind_password"]["credential"]
    backend_fields = changed("SecretBackend")
    assert backend_fields.keys() == {"spec.address", "spec.auth.token"}
    assert backend_fields["spec.auth.token"]["credential"]
    assert changed("Parameters").keys() == {"spec.banner"}


def test_admin_changes_to_admin_roles_users_and_tokens_are_audited(
    pg_wg: WarpgateProcess, admin_client: sdk.DefaultApi
):
    actor, call = _logged_in_full_admin(f"https://localhost:{pg_wg.http_port}", admin_client)

    tag = uuid4().hex
    admin_role_body = make_limited_admin_role_payload(
        name=f"audit-admin-role-{tag}", sessions_view=True
    )
    admin_role = call("POST", "/admin/api/admin-roles", admin_role_body)
    call(
        "PUT",
        f"/admin/api/admin-roles/{admin_role['id']}",
        {**admin_role_body, "users_edit": True},
    )
    call("DELETE", f"/admin/api/admin-roles/{admin_role['id']}")

    user = admin_client.create_user(sdk.CreateUserRequest(username=f"audit-user-{tag}"))
    call(
        "PUT",
        f"/admin/api/users/{user.id}",
        {"username": user.username, "allowed_ip_ranges": ["10.0.0.0/8"]},
    )
    key = admin_client.create_public_key_credential(
        user.id,
        sdk.NewPublicKeyCredential(
            label=f"key-{tag}",
            openssh_public_key="ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKL5C+OCN2hAbPoR+mwG4M402Z0XVDOuV5k7n6zCRIMsgnYiyz6a61Zcw/RRHoQAb7ndqUyk8eAi9gjPEiGq2d0=",
        ),
    )
    call(
        "PUT",
        f"/admin/api/users/{user.id}/credentials/public-keys/{key.id}",
        {"label": f"key-{tag}", "openssh_public_key": key.openssh_public_key},
    )
    sso = admin_client.create_sso_credential(
        user.id, sdk.NewSsoCredential(email=f"{tag}@example.com")
    )
    call(
        "PUT",
        f"/admin/api/users/{user.id}/credentials/sso/{sso.id}",
        {"email": f"{tag}@example.org"},
    )
    cert = admin_client.issue_certificate_credential(
        user.id,
        sdk.IssueCertificateCredentialRequest(
            label=f"cert-{tag}",
            public_key_pem="-----BEGIN PUBLIC KEY-----\nMFswDQYJKoZIhvcNAQEBBQADSgAwRwJAXWRPQyGlEY+SXz8Uslhe+MLjTgWd8lf/\nnA0hgCm9JFKC1tq1S73cQ9naClNXsMqY7pwPt1bSY8jYRqHHbdoUvwIDAQAB\n-----END PUBLIC KEY-----",
        ),
    )
    call(
        "PATCH",
        f"/admin/api/users/{user.id}/credentials/certificates/{cert.credential.id}",
        {"label": f"cert-renamed-{tag}"},
    )

    expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    token = call("POST", "/api/profile/api-tokens", {"label": f"token-{tag}", "expiry": expiry})
    call("DELETE", f"/api/profile/api-tokens/{token['token']['id']}")

    expected = {
        ("ResourceChanged1", "AdminRole", "Create"),
        ("ResourceChanged1", "AdminRole", "Update"),
        ("ResourceChanged1", "AdminRole", "Delete"),
        ("ResourceChanged1", "User", "Update"),
        ("CredentialUpdated1", "public_key", None),
        ("CredentialUpdated1", "sso", None),
        ("CredentialUpdated1", "certificate", None),
        ("CredentialCreated1", "api_token", None),
        ("CredentialDeleted1", "api_token", None),
    }
    entries = _wait_for_audit_entries(
        admin_client,
        tag,
        expected,
        key=lambda values: (
            values.get("_type"),
            values.get("kind") or values.get("credential_type"),
            values.get("action"),
        ),
    )

    assert entries.keys() == expected
    assert all(e.username == actor.username for e in entries.values())
    role_created = json.loads(entries[("ResourceChanged1", "AdminRole", "Create")].values["fields"])
    granted = {field["path"] for field in role_created if field.get("to") is True}
    assert granted == {"spec.sessions_view"}
    role_updated = entries[("ResourceChanged1", "AdminRole", "Update")].values
    [permission] = json.loads(role_updated["fields"])
    assert (permission["path"], permission["to"]) == ("spec.users_edit", True)
    updated = entries[("ResourceChanged1", "User", "Update")].values
    assert updated["id"] == user.id
    [ranges] = json.loads(updated["fields"])
    assert (ranges["path"], ranges["to"]) == ("spec.allowed_ip_ranges", ["10.0.0.0/8"])
    assert (
        entries[("CredentialUpdated1", "certificate", None)].values["credential_name"]
        == f"cert-renamed-{tag}"
    )
    assert (
        entries[("CredentialCreated1", "api_token", None)].values["credential_name"]
        == f"token-{tag}"
    )


HTTP_HEADER_SECRET = "Bearer s3cr3t-upstream"
HTTP_URL_PASSWORD = "p4ss"


def _http_target_request(name: str) -> sdk.TargetDataRequest:
    return sdk.TargetDataRequest(
        name=name,
        require_approval=False,
        ticket_requests_disabled=False,
        ticket_require_approval=False,
        options=sdk.TargetOptions(
            sdk.TargetOptionsTargetHTTPOptions(
                kind="Http",
                headers={"Authorization": HTTP_HEADER_SECRET},
                url=f"https://u:{HTTP_URL_PASSWORD}@upstream.example/",
                tls=sdk.Tls(mode=sdk.TlsMode.PREFERRED, verify=True),
            )
        ),
    )


def test_http_target_credentials_are_redacted_for_admins_without_targets_edit(
    pg_wg: WarpgateProcess, admin_client: sdk.DefaultApi
):
    url = f"https://localhost:{pg_wg.http_port}"
    target = admin_client.create_target(_http_target_request(f"http-{uuid4()}"))
    role = admin_client.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
    admin_client.add_target_role(target.id, role.id)

    lesser_role = _create_admin_role(
        admin_client, make_limited_admin_role_payload(recordings_view=True)
    )
    lesser = _create_user_with_role(admin_client, lesser_role.id)
    token = _create_user_api_token(url, lesser.username, "123")

    s = requests.Session()
    s.verify = False
    s.headers["X-Warpgate-Token"] = token
    api = f"{url}/@warpgate/admin/api"
    bodies = {}
    for path in ["/targets", f"/targets/{target.id}", f"/role/{role.id}/targets"]:
        resp = s.get(f"{api}{path}")
        assert resp.status_code == 200, (path, resp.status_code)
        # The target must be in the response, or the absence checks prove nothing.
        assert "upstream.example" in resp.text, path
        bodies[path] = resp.text
    leaks = {
        path: [v for v in (HTTP_HEADER_SECRET, HTTP_URL_PASSWORD) if v in body]
        for path, body in bodies.items()
    }
    assert not any(leaks.values()), f"credentials visible to a RecordingsView admin: {leaks}"

    # Redacted values must not be writable back through this admin.
    resp = s.put(
        f"{api}/targets/{target.id}",
        json=s.get(f"{api}/targets/{target.id}").json()
        | {"ticket_requests_disabled": False, "ticket_require_approval": False},
    )
    assert resp.status_code in {401, 403}, resp.status_code

    # A TargetsEdit admin still sees the values and an edit round-trips them.
    full = admin_client.get_target(target.id)
    http = full.options.actual_instance
    assert http.headers == {"Authorization": HTTP_HEADER_SECRET}
    assert http.url == f"https://u:{HTTP_URL_PASSWORD}@upstream.example/"
    admin_client.update_target(
        target.id,
        sdk.TargetDataRequest(
            name=full.name,
            options=full.options,
            require_approval=False,
            ticket_requests_disabled=False,
            ticket_require_approval=False,
        ),
    )
    after = admin_client.get_target(target.id).options.actual_instance
    assert after.headers == http.headers
    assert after.url == http.url

"""Shared helpers for the administrator (JIT) session-approval tests.

Several protocols exercise the same gate, so the fixtures for it live here
rather than in whichever test file happened to need them first.
"""

import os
import subprocess
import time
from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import ProcessManager
from .test_ticket_requests import _default_params as default_params  # noqa: F401
from .util import wait_port

# Every admin-role permission, all off. Tests switch on only what they are
# asserting about, so a role can't accidentally pass a check via a permission
# the test never meant to grant.
NO_ADMIN_PERMISSIONS = dict(
    targets_create=False,
    targets_edit=False,
    targets_delete=False,
    users_create=False,
    users_edit=False,
    users_delete=False,
    access_roles_create=False,
    access_roles_edit=False,
    access_roles_delete=False,
    access_roles_assign=False,
    sessions_view=False,
    sessions_terminate=False,
    approve_sessions=False,
    recordings_view=False,
    tickets_create=False,
    tickets_delete=False,
    config_edit=False,
    admin_roles_manage=False,
    ticket_requests_manage=False,
)


def create_password_user(api, password="123"):
    """A user with a password credential and a fresh role granting it access."""
    role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
    user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
    api.create_password_credential(user.id, sdk.NewPasswordCredential(password=password))
    api.add_user_role(user.id, role.id)
    return user, role


def create_postgres_target(api, role, db_port, require_approval=True):
    target = api.create_target(
        sdk.TargetDataRequest(
            name=f"postgres-{uuid4()}",
            require_approval=require_approval,
            options=sdk.TargetOptions(
                sdk.TargetOptionsTargetPostgresOptions(
                    kind="Postgres",
                    host="localhost",
                    port=db_port,
                    username="user",
                    auth=sdk.DatabaseTargetAuth(
                        sdk.DatabaseTargetAuthDatabaseTargetPasswordAuth(
                            kind="Password",
                            password="123",
                        )
                    ),
                    tls=sdk.Tls(mode=sdk.TlsMode.PREFERRED, verify=False),
                )
            ),
        )
    )
    api.add_target_role(target.id, role.id)
    return target


def create_mysql_target(api, role, db_port, require_approval=True):
    target = api.create_target(
        sdk.TargetDataRequest(
            name=f"mysql-{uuid4()}",
            require_approval=require_approval,
            options=sdk.TargetOptions(
                sdk.TargetOptionsTargetMySqlOptions(
                    kind="MySql",
                    host="localhost",
                    port=db_port,
                    username="root",
                    auth=sdk.DatabaseTargetAuth(
                        sdk.DatabaseTargetAuthDatabaseTargetPasswordAuth(
                            kind="Password",
                            password="123",
                        )
                    ),
                    tls=sdk.Tls(mode=sdk.TlsMode.PREFERRED, verify=False),
                )
            ),
        )
    )
    api.add_target_role(target.id, role.id)
    return target


def create_http_target(api, role, echo_server_port, require_approval=True):
    target = api.create_target(
        sdk.TargetDataRequest(
            name=f"http-{uuid4()}",
            require_approval=require_approval,
            options=sdk.TargetOptions(
                sdk.TargetOptionsTargetHTTPOptions(
                    kind="Http",
                    url=f"http://localhost:{echo_server_port}",
                    tls=sdk.Tls(mode=sdk.TlsMode.DISABLED, verify=False),
                )
            ),
        )
    )
    api.add_target_role(target.id, role.id)
    return target


def create_user_and_postgres_target(url, db_port, require_approval=True):
    """A password user and a Postgres target, gated by default."""
    with admin_client(url) as api:
        user, role = create_password_user(api)
        target = create_postgres_target(api, role, db_port, require_approval)
    return user, target


def create_approver(url, **perms):
    """A password user holding an admin role with only `perms` switched on, for
    testing who is allowed to resolve someone else's held session."""
    with admin_client(url) as api:
        user, _ = create_password_user(api)
    grant_admin_role(url, user.id, **perms)
    return user


def grant_admin_role(url, user_id, **perms):
    """Give a user an admin role carrying only the named permissions."""
    payload = dict(
        name=f"requests-admin-{uuid4()}",
        description="scoped for the requests inbox",
        **NO_ADMIN_PERMISSIONS,
    )
    payload.update(perms)
    with admin_client(url) as api:
        role = api.create_admin_role(sdk.AdminRoleDataRequest(**payload))
        api.add_user_admin_role(user_id, role.id)
    return role


def wait_for_pending_approval(api, target_name, username, deadline=15):
    """Poll the admin API until the held session shows up. The owning node
    creates the request record when it starts waiting for the approval, and
    any node can list it from the shared database."""
    for _ in range(deadline * 4):
        for approval in api.get_session_approvals():
            if approval.target == target_name and approval.username == username:
                return approval
        time.sleep(0.25)
    raise AssertionError("session did not appear in the pending-approval list")


def assert_no_pending_approval(api, target_name, username, settle=3):
    """The opposite assertion: nothing is ever held for this target/user.

    Waits out `settle` seconds so a request that merely arrives late still
    fails the test, rather than passing because we looked too early.
    """
    for _ in range(settle * 4):
        for approval in api.get_session_approvals():
            assert not (
                approval.target == target_name and approval.username == username
            ), "session was held for approval when it should not have been"
        time.sleep(0.25)


def psql_held(processes: ProcessManager, gateway_postgres_port, user, target):
    """Start psql; it blocks after password auth until the session is approved."""
    wait_port(gateway_postgres_port, recv=False)
    return processes.start(
        [
            "psql",
            "--user",
            f"{user.username}#{target.name}",
            "--host",
            "127.0.0.1",
            "--port",
            str(gateway_postgres_port),
            "db",
        ],
        env={"PGPASSWORD": "123", **os.environ},
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )

import os
import subprocess
import time
from uuid import uuid4

import aiohttp
import pytest
import requests

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .test_ticket_requests import _default_params
from .util import wait_port


def _create_user_and_target(url, db_port):
    """A password user and a Postgres target gated by JIT admin approval."""
    with admin_client(url) as api:
        role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
        user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
        api.create_password_credential(
            user.id, sdk.NewPasswordCredential(password="123")
        )
        api.add_user_role(user.id, role.id)
        target = api.create_target(
            sdk.TargetDataRequest(
                name=f"postgres-{uuid4()}",
                # The JIT gate: every connection is held until an admin approves.
                require_approval=True,
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
    return user, target


def _grant_admin_role(url, user_id, **perms):
    """Give a user an admin role carrying only the named permissions. The
    requests indicator counts each kind behind its own permission."""
    payload = dict(
        name=f"requests-admin-{uuid4()}",
        description="scoped for the requests inbox",
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
        recordings_view=False,
        tickets_create=False,
        tickets_delete=False,
        config_edit=False,
        admin_roles_manage=False,
        ticket_requests_manage=False,
    )
    payload.update(perms)
    with admin_client(url) as api:
        role = api.create_admin_role(sdk.AdminRoleDataRequest(**payload))
        api.add_user_admin_role(user_id, role.id)


def _wait_for_pending_approval(api, target_name, username, deadline=15):
    """Poll the admin API until the held session shows up. The owning node
    creates the request record when it starts waiting for the approval, and
    any node can list it from the shared database."""
    for _ in range(deadline * 4):
        for approval in api.get_session_approvals():
            if approval.target == target_name and approval.username == username:
                return approval
        time.sleep(0.25)
    raise AssertionError("session did not appear in the pending-approval list")


def _psql_held(processes: ProcessManager, gateway_postgres_port, user, target):
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


class Test:
    def test_approved(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        db_port = processes.start_postgres_server()
        url = f"https://localhost:{shared_wg.http_port}"
        user, target = _create_user_and_target(url, db_port)
        wait_port(db_port, recv=False)

        client = _psql_held(processes, shared_wg.postgres_port, user, target)

        with admin_client(url) as api:
            approval = _wait_for_pending_approval(api, target.name, user.username)
            assert approval.protocol == "PostgreSQL"
            api.approve_session(approval.id, sdk.SessionApprovalScope.ONCE)

        # Once approved the session proceeds and the query runs.
        assert b"tbl" in client.communicate(b"\\dt\n", timeout=timeout)[0]
        assert client.returncode == 0

        # The hold and its resolution land in the persisted audit log.
        with admin_client(url) as api:
            entries = [
                entry.values or {}
                for entry in api.get_logs(sdk.GetLogsRequest(limit=500))
            ]
        events = {e.get("_type") for e in entries}
        assert "SessionApprovalRequested1" in events
        assert "SessionApprovalResolved1" in events

        # The resolution records who decided and what they decided.
        resolved = next(e for e in entries if e.get("_type") == "SessionApprovalResolved1")
        assert resolved["approved"] == "true"
        assert resolved["resolved_by"]

    def test_rejected(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        db_port = processes.start_postgres_server()
        url = f"https://localhost:{shared_wg.http_port}"
        user, target = _create_user_and_target(url, db_port)
        wait_port(db_port, recv=False)

        client = _psql_held(processes, shared_wg.postgres_port, user, target)

        with admin_client(url) as api:
            approval = _wait_for_pending_approval(api, target.name, user.username)
            api.reject_session(approval.id)

        # A rejected session is denied: psql exits non-zero without connecting.
        client.communicate(timeout=timeout)
        assert client.returncode != 0

    @pytest.mark.asyncio
    async def test_web_then_admin_approval(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        # A policy requiring in-browser approval AND a target requiring admin
        # approval: the session is held twice, sequentially.
        db_port = processes.start_postgres_server()
        url = f"https://localhost:{shared_wg.http_port}"
        user, target = _create_user_and_target(url, db_port)
        with admin_client(url) as api:
            api.update_user(
                user.id,
                sdk.UserDataRequest(
                    username=user.username,
                    credential_policy=sdk.UserRequireCredentialsPolicy(
                        postgres=[
                            sdk.CredentialKind.PASSWORD,
                            sdk.CredentialKind.WEBUSERAPPROVAL,
                        ],
                    ),
                ),
            )
        wait_port(db_port, recv=False)

        session = aiohttp.ClientSession()
        headers = {"Host": f"localhost:{shared_wg.http_port}"}
        await session.post(
            f"{url}/@warpgate/api/auth/login",
            json={"username": user.username, "password": "123"},
            headers=headers,
            ssl=False,
        )
        ws = await session.ws_connect(
            url.replace("https:", "wss:")
            + "/@warpgate/api/auth/web-auth-requests/stream",
            ssl=False,
        )

        client = _psql_held(processes, shared_wg.postgres_port, user, target)

        msg = await ws.receive(15)
        auth_id = msg.data
        r = await session.post(
            f"{url}/@warpgate/api/auth/state/{auth_id}/approve",
            params={"scope": "Once"},
            ssl=False,
        )
        assert r.status == 200

        # The web approval is granted, but the session is now held again, for
        # an administrator.
        with admin_client(url) as api:
            approval = _wait_for_pending_approval(api, target.name, user.username)
            api.approve_session(approval.id, sdk.SessionApprovalScope.ONCE)

        assert b"tbl" in client.communicate(b"\\dt\n", timeout=timeout)[0]
        assert client.returncode == 0
        await ws.close()
        await session.close()

    @pytest.mark.asyncio
    async def test_pending_count_readable_with_session_cookie(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        # The approvals indicator in both app shells counts the admin API's
        # pending list using the browser session cookie, so an admin logged
        # into the gateway must be able to read it cross-app.
        db_port = processes.start_postgres_server()
        url = f"https://localhost:{shared_wg.http_port}"
        user, target = _create_user_and_target(url, db_port)
        _grant_admin_role(url, user.id, sessions_view=True)
        wait_port(db_port, recv=False)

        session = aiohttp.ClientSession()
        headers = {"Host": f"localhost:{shared_wg.http_port}"}
        await session.post(
            f"{url}/@warpgate/api/auth/login",
            json={"username": user.username, "password": "123"},
            headers=headers,
            ssl=False,
        )

        # The permission is what the indicator gates its visibility on.
        info = await (
            await session.get(f"{url}/@warpgate/api/info", ssl=False)
        ).json()
        assert info["admin_permissions"]["sessions_view"] is True

        client = _psql_held(processes, shared_wg.postgres_port, user, target)

        pending = []
        for _ in range(60):
            response = await session.get(
                f"{url}/@warpgate/admin/api/session-approvals", ssl=False
            )
            assert response.status == 200, "session cookie must reach the admin API"
            pending = await response.json()
            if pending:
                break
            time.sleep(0.25)
        assert len(pending) == 1, "indicator would show no outstanding requests"

        with admin_client(url) as api:
            api.approve_session(pending[0]["id"], sdk.SessionApprovalScope.ONCE)

        # Resolved requests drop out of the count.
        client.communicate(b"\\dt\n", timeout=timeout)
        response = await session.get(
            f"{url}/@warpgate/admin/api/session-approvals", ssl=False
        )
        assert await response.json() == []
        await session.close()

    def test_inbox_counts_sessions_and_tickets(
        self,
        processes: ProcessManager,
        timeout,
    ):
        # The requests inbox (and the indicator that links to it) merges held
        # sessions with pending ticket requests. Uses its own node because it
        # flips the self-service parameters.
        wg = processes.start_wg()
        wait_port(wg.http_port, recv=False)
        url = f"https://localhost:{wg.http_port}"

        db_port = processes.start_postgres_server()
        user, target = _create_user_and_target(url, db_port)
        _grant_admin_role(
            url, user.id, sessions_view=True, ticket_requests_manage=True
        )
        with admin_client(url) as api:
            api.update_parameters(
                _default_params(
                    ticket_self_service_enabled=True,
                    ticket_auto_approve_existing_access=False,
                )
            )
        wait_port(db_port, recv=False)

        session = requests.Session()
        session.verify = False
        session.post(
            f"{url}/@warpgate/api/auth/login",
            json={"username": user.username, "password": "123"},
        )

        # One pending ticket request...
        created = session.post(
            f"{url}/@warpgate/api/ticket-requests",
            json={"target_name": target.name, "description": "inbox test"},
        )
        assert created.status_code == 201

        # ...and one held session.
        client = _psql_held(processes, wg.postgres_port, user, target)

        def counts():
            held = session.get(f"{url}/@warpgate/admin/api/session-approvals")
            pending = session.get(
                f"{url}/@warpgate/admin/api/ticket-requests?status=Pending"
            )
            assert held.status_code == 200 and pending.status_code == 200
            return len(held.json()), len(pending.json())

        sessions_n, tickets_n = 0, 0
        for _ in range(60):
            sessions_n, tickets_n = counts()
            if sessions_n and tickets_n:
                break
            time.sleep(0.25)
        assert (sessions_n, tickets_n) == (1, 1), "indicator should total 2"

        # Names are projected into the request, so the inbox renders one
        # without looking up every referenced id.
        pending = session.get(
            f"{url}/@warpgate/admin/api/ticket-requests?status=Pending"
        ).json()
        assert pending[0]["username"] == user.username
        assert pending[0]["target_name"] == target.name
        assert pending[0]["resolved_by_username"] is None

        # Resolving one kind leaves the other counted.
        with admin_client(url) as api:
            approval = _wait_for_pending_approval(api, target.name, user.username)
            api.approve_session(approval.id, sdk.SessionApprovalScope.ONCE)
        client.communicate(b"\\dt\n", timeout=timeout)
        assert counts() == (0, 1)

    def test_ticket_is_held_for_approval(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        # A ticket carries its own authorization, but a target requiring
        # approval must still hold it — otherwise `require_approval` is
        # bypassable by anyone holding a ticket.
        db_port = processes.start_postgres_server()
        url = f"https://localhost:{shared_wg.http_port}"
        user, target = _create_user_and_target(url, db_port)
        wait_port(db_port, recv=False)

        with admin_client(url) as api:
            secret = api.create_ticket(
                sdk.CreateTicketRequest(
                    target_name=target.name,
                    username=user.username,
                )
            ).secret

        wait_port(shared_wg.postgres_port, recv=False)
        client = processes.start(
            [
                "psql",
                "--user",
                f"ticket-{secret}",
                "--host",
                "127.0.0.1",
                "--port",
                str(shared_wg.postgres_port),
                "db",
            ],
            env={"PGPASSWORD": "x", **os.environ},
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )

        # The ticket connection is held, and appears in the approval queue.
        with admin_client(url) as api:
            approval = _wait_for_pending_approval(api, target.name, user.username)
            api.approve_session(approval.id, sdk.SessionApprovalScope.ONCE)

        assert b"tbl" in client.communicate(b"\\dt\n", timeout=timeout)[0]
        assert client.returncode == 0

    def test_cross_node_approval(
        self,
        processes: ProcessManager,
        timeout,
    ):
        # Two nodes on one database. The session is held on node A; the admin
        # approves from node B, which lists the request from the shared DB and
        # delivers the decision to node A over the internal cluster RPC.
        node_a = processes.start_wg()
        wait_port(node_a.http_port, recv=False)
        node_b = processes.start_wg(share_with=node_a)
        wait_port(node_b.http_port, recv=False)

        db_port = processes.start_postgres_server()
        user, target = _create_user_and_target(
            f"https://localhost:{node_a.http_port}", db_port
        )
        wait_port(db_port, recv=False)

        # Held on node A.
        client = _psql_held(processes, node_a.postgres_port, user, target)

        # Approved from node B.
        with admin_client(f"https://localhost:{node_b.http_port}") as api:
            approval = _wait_for_pending_approval(api, target.name, user.username)
            api.approve_session(approval.id, sdk.SessionApprovalScope.ONCE)

        assert b"tbl" in client.communicate(b"\\dt\n", timeout=timeout)[0]
        assert client.returncode == 0

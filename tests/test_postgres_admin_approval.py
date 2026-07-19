import asyncio
import os
import time
import subprocess

import aiohttp
import pytest
import requests

from .api_client import admin_client, sdk
from .approval_util import (
    create_user_and_postgres_target,
    default_params,
    grant_admin_role,
    psql_held,
    wait_for_pending_approval,
)
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port


class Test:
    def test_approved(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        db_port = processes.start_postgres_server()
        url = f"https://localhost:{shared_wg.http_port}"
        user, target = create_user_and_postgres_target(url, db_port)
        wait_port(db_port, recv=False)

        client = psql_held(processes, shared_wg.postgres_port, user, target)

        with admin_client(url) as api:
            approval = wait_for_pending_approval(api, target.name, user.username)
            assert approval.protocol == "PostgreSQL"
            api.approve_session(approval.id, sdk.ApprovalScope.ONCE)

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
        user, target = create_user_and_postgres_target(url, db_port)
        wait_port(db_port, recv=False)

        client = psql_held(processes, shared_wg.postgres_port, user, target)

        with admin_client(url) as api:
            approval = wait_for_pending_approval(api, target.name, user.username)
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
        user, target = create_user_and_postgres_target(url, db_port)
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

        client = psql_held(processes, shared_wg.postgres_port, user, target)

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
            approval = wait_for_pending_approval(api, target.name, user.username)
            api.approve_session(approval.id, sdk.ApprovalScope.ONCE)

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
        user, target = create_user_and_postgres_target(url, db_port)
        grant_admin_role(url, user.id, approve_sessions=True)
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
        assert info["admin_permissions"]["approve_sessions"] is True

        client = psql_held(processes, shared_wg.postgres_port, user, target)

        # Filtered to this test's target: `shared_wg` is shared, so a sibling
        # test's held session would otherwise make a bare count flaky.
        ours = []
        for _ in range(60):
            response = await session.get(
                f"{url}/@warpgate/admin/api/session-approvals", ssl=False
            )
            assert response.status == 200, "session cookie must reach the admin API"
            ours = [r for r in await response.json() if r["target"] == target.name]
            if ours:
                break
            await asyncio.sleep(0.25)
        assert len(ours) == 1, "indicator would show no outstanding requests"

        with admin_client(url) as api:
            api.approve_session(ours[0]["id"], sdk.ApprovalScope.ONCE)

        # Resolved requests drop out of the count.
        client.communicate(b"\\dt\n", timeout=timeout)
        response = await session.get(
            f"{url}/@warpgate/admin/api/session-approvals", ssl=False
        )
        assert [r for r in await response.json() if r["target"] == target.name] == []
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
        user, target = create_user_and_postgres_target(url, db_port)
        grant_admin_role(
            url, user.id, approve_sessions=True, ticket_requests_manage=True
        )
        with admin_client(url) as api:
            api.update_parameters(
                default_params(
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
        client = psql_held(processes, wg.postgres_port, user, target)

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
            time.sleep(0.25)  # sync test, own node
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
            approval = wait_for_pending_approval(api, target.name, user.username)
            api.approve_session(approval.id, sdk.ApprovalScope.ONCE)
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
        user, target = create_user_and_postgres_target(url, db_port)
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
            approval = wait_for_pending_approval(api, target.name, user.username)
            api.approve_session(approval.id, sdk.ApprovalScope.ONCE)

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
        user, target = create_user_and_postgres_target(
            f"https://localhost:{node_a.http_port}", db_port
        )
        wait_port(db_port, recv=False)

        # Held on node A.
        client = psql_held(processes, node_a.postgres_port, user, target)

        # Approved from node B.
        with admin_client(f"https://localhost:{node_b.http_port}") as api:
            approval = wait_for_pending_approval(api, target.name, user.username)
            api.approve_session(approval.id, sdk.ApprovalScope.ONCE)

        assert b"tbl" in client.communicate(b"\\dt\n", timeout=timeout)[0]
        assert client.returncode == 0

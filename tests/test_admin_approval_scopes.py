"""Approval scopes, the remembered-approval cache, and the hold timeout.

These decide when a session skips the gate entirely, so a key that matches too
widely is a silent bypass rather than a visible failure. Each test uses its own
node: the grace cache is per-node in-memory state keyed partly on the
parameters, and the timeout is a global parameter.
"""

import os
import subprocess

from .api_client import admin_client, sdk
from .approval_util import (
    assert_no_pending_approval,
    create_password_user,
    create_postgres_target,
    default_params,
    psql_held,
    wait_for_pending_approval,
)
from .conftest import ProcessManager
from .util import wait_port


def _run_query(client, timeout):
    out = client.communicate(b"\\dt\n", timeout=timeout)[0]
    return client.returncode == 0 and b"tbl" in out


class Test:
    def test_target_scope_skips_the_gate_for_the_same_target(
        self,
        processes: ProcessManager,
        timeout,
    ):
        wg = processes.start_wg()
        wait_port(wg.http_port, recv=False)
        url = f"https://localhost:{wg.http_port}"
        db_port = processes.start_postgres_server()
        wait_port(db_port, recv=False)

        with admin_client(url) as api:
            api.update_parameters(default_params(admin_approval_grace_period_seconds=300))
            user, role = create_password_user(api)
            target = create_postgres_target(api, role, db_port)
            other = create_postgres_target(api, role, db_port)

        # First connection is held and approved for the target.
        first = psql_held(processes, wg.postgres_port, user, target)
        with admin_client(url) as api:
            approval = wait_for_pending_approval(api, target.name, user.username)
            api.approve_session(approval.id, sdk.ApprovalScope.TARGET)
        assert _run_query(first, timeout)

        # Same user, same IP, same credentials, same target: remembered.
        second = psql_held(processes, wg.postgres_port, user, target)
        with admin_client(url) as api:
            assert_no_pending_approval(api, target.name, user.username)
        assert _run_query(second, timeout)

        # A *different* target is not covered by a Target-scoped approval.
        third = psql_held(processes, wg.postgres_port, user, other)
        with admin_client(url) as api:
            approval = wait_for_pending_approval(api, other.name, user.username)
            api.approve_session(approval.id, sdk.ApprovalScope.ONCE)
        assert _run_query(third, timeout)

    def test_all_targets_scope_covers_other_targets(
        self,
        processes: ProcessManager,
        timeout,
    ):
        wg = processes.start_wg()
        wait_port(wg.http_port, recv=False)
        url = f"https://localhost:{wg.http_port}"
        db_port = processes.start_postgres_server()
        wait_port(db_port, recv=False)

        with admin_client(url) as api:
            api.update_parameters(default_params(admin_approval_grace_period_seconds=300))
            user, role = create_password_user(api)
            target = create_postgres_target(api, role, db_port)
            other = create_postgres_target(api, role, db_port)

        first = psql_held(processes, wg.postgres_port, user, target)
        with admin_client(url) as api:
            approval = wait_for_pending_approval(api, target.name, user.username)
            api.approve_session(approval.id, sdk.ApprovalScope.ALLTARGETS)
        assert _run_query(first, timeout)

        # The grant deliberately spans targets, so the second one is not held.
        second = psql_held(processes, wg.postgres_port, user, other)
        with admin_client(url) as api:
            assert_no_pending_approval(api, other.name, user.username)
        assert _run_query(second, timeout)

    def test_once_scope_is_not_remembered(
        self,
        processes: ProcessManager,
        timeout,
    ):
        wg = processes.start_wg()
        wait_port(wg.http_port, recv=False)
        url = f"https://localhost:{wg.http_port}"
        db_port = processes.start_postgres_server()
        wait_port(db_port, recv=False)

        with admin_client(url) as api:
            api.update_parameters(default_params(admin_approval_grace_period_seconds=300))
            user, role = create_password_user(api)
            target = create_postgres_target(api, role, db_port)

        first = psql_held(processes, wg.postgres_port, user, target)
        with admin_client(url) as api:
            approval = wait_for_pending_approval(api, target.name, user.username)
            api.approve_session(approval.id, sdk.ApprovalScope.ONCE)
        assert _run_query(first, timeout)

        # Once means once, even with caching enabled.
        second = psql_held(processes, wg.postgres_port, user, target)
        with admin_client(url) as api:
            approval = wait_for_pending_approval(api, target.name, user.username)
            api.approve_session(approval.id, sdk.ApprovalScope.ONCE)
        assert _run_query(second, timeout)

    def test_no_grace_period_means_no_bypass(
        self,
        processes: ProcessManager,
        timeout,
    ):
        # With caching disabled a Target-scoped approval must not carry over —
        # the scope says "remember", the parameter says "don't".
        wg = processes.start_wg()
        wait_port(wg.http_port, recv=False)
        url = f"https://localhost:{wg.http_port}"
        db_port = processes.start_postgres_server()
        wait_port(db_port, recv=False)

        with admin_client(url) as api:
            api.update_parameters(default_params(admin_approval_grace_period_seconds=None))
            user, role = create_password_user(api)
            target = create_postgres_target(api, role, db_port)

        first = psql_held(processes, wg.postgres_port, user, target)
        with admin_client(url) as api:
            approval = wait_for_pending_approval(api, target.name, user.username)
            api.approve_session(approval.id, sdk.ApprovalScope.TARGET)
        assert _run_query(first, timeout)

        second = psql_held(processes, wg.postgres_port, user, target)
        with admin_client(url) as api:
            approval = wait_for_pending_approval(api, target.name, user.username)
            api.approve_session(approval.id, sdk.ApprovalScope.ONCE)
        assert _run_query(second, timeout)

    def test_ticket_session_does_not_consume_a_remembered_approval(
        self,
        processes: ProcessManager,
        timeout,
    ):
        # A ticket has no stable credential fingerprint, so it must not inherit
        # an approval granted to a password session — otherwise approving one
        # login silently blesses a different authentication path.
        wg = processes.start_wg()
        wait_port(wg.http_port, recv=False)
        url = f"https://localhost:{wg.http_port}"
        db_port = processes.start_postgres_server()
        wait_port(db_port, recv=False)

        with admin_client(url) as api:
            api.update_parameters(default_params(admin_approval_grace_period_seconds=300))
            user, role = create_password_user(api)
            target = create_postgres_target(api, role, db_port)

        first = psql_held(processes, wg.postgres_port, user, target)
        with admin_client(url) as api:
            approval = wait_for_pending_approval(api, target.name, user.username)
            api.approve_session(approval.id, sdk.ApprovalScope.ALLTARGETS)
        assert _run_query(first, timeout)

        with admin_client(url) as api:
            secret = api.create_ticket(
                sdk.CreateTicketRequest(
                    target_name=target.name, username=user.username
                )
            ).secret

        ticket_client = processes.start(
            [
                "psql",
                "--user",
                f"ticket-{secret}",
                "--host",
                "127.0.0.1",
                "--port",
                str(wg.postgres_port),
                "db",
            ],
            env={"PGPASSWORD": "x", **os.environ},
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )

        # Still held, despite the AllTargets grant sitting in the cache.
        with admin_client(url) as api:
            approval = wait_for_pending_approval(api, target.name, user.username)
            api.approve_session(approval.id, sdk.ApprovalScope.ONCE)
        assert _run_query(ticket_client, timeout)

    def test_hold_times_out_and_denies(
        self,
        processes: ProcessManager,
        timeout,
    ):
        # Nobody approves. The session must be dropped once the configured
        # window elapses rather than hanging until the client gives up.
        wg = processes.start_wg()
        wait_port(wg.http_port, recv=False)
        url = f"https://localhost:{wg.http_port}"
        db_port = processes.start_postgres_server()
        wait_port(db_port, recv=False)

        with admin_client(url) as api:
            api.update_parameters(default_params(admin_approval_timeout_seconds=5))
            user, role = create_password_user(api)
            target = create_postgres_target(api, role, db_port)

        client = psql_held(processes, wg.postgres_port, user, target)
        with admin_client(url) as api:
            wait_for_pending_approval(api, target.name, user.username)

        client.communicate(timeout=timeout)
        assert client.returncode != 0, "an unapproved session must not connect"

        # The expiry is audited, and the request stops being listed.
        with admin_client(url) as api:
            assert not [
                a
                for a in api.get_session_approvals()
                if a.target == target.name
            ], "a timed-out request must not stay in the queue"
            events = {
                (entry.values or {}).get("_type")
                for entry in api.get_logs(sdk.GetLogsRequest(limit=500))
            }
        assert "SessionApprovalTimedOut1" in events

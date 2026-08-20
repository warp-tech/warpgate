"""Who may resolve a held session.

Approving grants access to a target explicitly marked as needing approval, so
it sits behind its own permission and refuses to be used on the approver's own
session. Both rules are only observable through the API, and a regression in
either is a silent privilege escalation.
"""

import requests

from .api_client import admin_client, sdk
from .approval_util import (
    create_approver,
    create_user_and_postgres_target,
    grant_admin_role,
    psql_held,
    wait_for_pending_approval,
)
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port


def _logged_in(url, username, password="123"):
    session = requests.Session()
    session.verify = False
    response = session.post(
        f"{url}/@warpgate/api/auth/login",
        json={"username": username, "password": password},
    )
    assert response.status_code // 100 == 2
    return session


class Test:
    def test_session_permissions_alone_grant_no_access(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        # The approval queue is gated entirely on `approve_sessions`: seeing who
        # is held is itself approver-only, and before that permission existed
        # this was reachable by every role with `sessions_terminate`.
        url = f"https://localhost:{shared_wg.http_port}"
        db_port = processes.start_postgres_server()
        wait_port(db_port, recv=False)
        user, target = create_user_and_postgres_target(url, db_port)

        admin = create_approver(url, sessions_view=True, sessions_terminate=True)

        client = psql_held(processes, shared_wg.postgres_port, user, target)
        with admin_client(url) as api:
            approval = wait_for_pending_approval(api, target.name, user.username)

        session = _logged_in(url, admin.username)
        listed = session.get(f"{url}/@warpgate/admin/api/session-approvals")
        assert listed.status_code == 403, "listing the queue needs approve_sessions"

        denied = session.post(
            f"{url}/@warpgate/admin/api/session-approvals/{approval.id}/approve",
            params={"scope": "Once"},
        )
        assert denied.status_code == 403, "approving needs approve_sessions"

        rejected = session.post(
            f"{url}/@warpgate/admin/api/session-approvals/{approval.id}/reject"
        )
        assert rejected.status_code == 403

        # Clean up the held session so it doesn't outlive the test.
        with admin_client(url) as api:
            api.reject_session(approval.id)
        client.communicate(timeout=timeout)

    def test_approve_sessions_permission_allows_approval(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        url = f"https://localhost:{shared_wg.http_port}"
        db_port = processes.start_postgres_server()
        wait_port(db_port, recv=False)
        user, target = create_user_and_postgres_target(url, db_port)

        admin = create_approver(url, sessions_view=True, approve_sessions=True)

        client = psql_held(processes, shared_wg.postgres_port, user, target)
        with admin_client(url) as api:
            approval = wait_for_pending_approval(api, target.name, user.username)

        session = _logged_in(url, admin.username)
        approved = session.post(
            f"{url}/@warpgate/admin/api/session-approvals/{approval.id}/approve",
            params={"scope": "Once"},
        )
        assert approved.status_code == 200

        assert b"tbl" in client.communicate(b"\\dt\n", timeout=timeout)[0]
        assert client.returncode == 0

    def test_cannot_approve_own_session(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        # Four-eyes is the point of the gate: an approver who could open their
        # own held session and wave it through has defeated it.
        url = f"https://localhost:{shared_wg.http_port}"
        db_port = processes.start_postgres_server()
        wait_port(db_port, recv=False)
        user, target = create_user_and_postgres_target(url, db_port)
        grant_admin_role(url, user.id, sessions_view=True, approve_sessions=True)

        client = psql_held(processes, shared_wg.postgres_port, user, target)
        with admin_client(url) as api:
            approval = wait_for_pending_approval(api, target.name, user.username)

        session = _logged_in(url, user.username)
        denied = session.post(
            f"{url}/@warpgate/admin/api/session-approvals/{approval.id}/approve",
            params={"scope": "Once"},
        )
        assert denied.status_code == 403, "self-approval must be refused"

        # Rejecting your own session grants nothing, so it stays allowed.
        rejected = session.post(
            f"{url}/@warpgate/admin/api/session-approvals/{approval.id}/reject"
        )
        assert rejected.status_code == 200

        client.communicate(timeout=timeout)
        assert client.returncode != 0

    def test_target_editor_may_approve_own_session(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        # Someone who can edit targets could just clear `require_approval`, so
        # refusing their self-approval would only cost a round trip.
        url = f"https://localhost:{shared_wg.http_port}"
        db_port = processes.start_postgres_server()
        wait_port(db_port, recv=False)
        user, target = create_user_and_postgres_target(url, db_port)
        grant_admin_role(
            url,
            user.id,
            sessions_view=True,
            approve_sessions=True,
            targets_edit=True,
        )

        client = psql_held(processes, shared_wg.postgres_port, user, target)
        with admin_client(url) as api:
            approval = wait_for_pending_approval(api, target.name, user.username)

        session = _logged_in(url, user.username)
        approved = session.post(
            f"{url}/@warpgate/admin/api/session-approvals/{approval.id}/approve",
            params={"scope": "Once"},
        )
        assert approved.status_code == 200

        assert b"tbl" in client.communicate(b"\\dt\n", timeout=timeout)[0]
        assert client.returncode == 0

    def test_audit_records_the_resolver(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        url = f"https://localhost:{shared_wg.http_port}"
        db_port = processes.start_postgres_server()
        wait_port(db_port, recv=False)
        user, target = create_user_and_postgres_target(url, db_port)

        admin = create_approver(url, sessions_view=True, approve_sessions=True)

        client = psql_held(processes, shared_wg.postgres_port, user, target)
        with admin_client(url) as api:
            approval = wait_for_pending_approval(api, target.name, user.username)

        session = _logged_in(url, admin.username)
        session.post(
            f"{url}/@warpgate/admin/api/session-approvals/{approval.id}/approve",
            params={"scope": "Once"},
        )
        client.communicate(b"\\dt\n", timeout=timeout)

        with admin_client(url) as api:
            resolved = [
                entry.values or {}
                for entry in api.get_logs(sdk.GetLogsRequest(limit=500))
                if (entry.values or {}).get("_type") == "SessionApprovalResolved1"
                and (entry.values or {}).get("target") == target.name
            ]
        assert resolved, "the decision must be audited"
        assert resolved[0]["resolved_by"] == admin.username

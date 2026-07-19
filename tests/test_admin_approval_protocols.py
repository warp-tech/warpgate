"""The administrator gate across the protocols that were never covered.

`require_approval` is a property of the target, not of one protocol, so a
protocol that forgets to call the gate makes the setting silently useless for
every target of that kind. HTTP and Kubernetes answer per request rather than
holding a connection, so they refuse with a retryable response instead.
"""

import subprocess
import threading
import uuid

import requests

from .api_client import admin_client, sdk
from .approval_util import (
    create_http_target,
    create_mysql_target,
    create_password_user,
    psql_held,
    wait_for_pending_approval,
)
from .conftest import VNC_BACKEND_SIZE, ProcessManager, WarpgateProcess
from .util import mysql_client_opts, mysql_client_ssl_opt, wait_mysql_port, wait_port
from .vnc_client import VncClient


class Test:
    def test_mysql_session_is_held(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        # MySQL has no in-band channel for a "waiting" notice, so the handshake
        # simply blocks — the gate still has to run, and the held session still
        # has to reach the approval queue.
        #
        # Only the hold and the denial are asserted: proxying a MySQL session
        # through to the target does not currently work in the e2e environment
        # (an ungated target fails the same way, which is why
        # `test_mysql_user_auth_password.py` is commented out), so a
        # post-approval query would fail for reasons unrelated to approval.
        db_port = processes.start_mysql_server()
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, role = create_password_user(api)
            target = create_mysql_target(api, role, db_port)
        wait_mysql_port(db_port)
        wait_port(shared_wg.mysql_port, recv=False)

        client = processes.start(
            [
                "mysql",
                "--user",
                f"{user.username}#{target.name}",
                "--password=123",
                "--host",
                "127.0.0.1",
                "--port",
                str(shared_wg.mysql_port),
                mysql_client_ssl_opt,
                *mysql_client_opts,
                "db",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )

        with admin_client(url) as api:
            approval = wait_for_pending_approval(api, target.name, user.username)
            assert approval.protocol == "MySQL"
            api.reject_session(approval.id)

        client.communicate(b"show tables;\n", timeout=timeout)
        assert client.returncode != 0

    def test_http_request_is_refused_until_approved(
        self,
        echo_server_port,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        # HTTP can't park a request on the gate, so a held session gets a
        # retryable 202 and only reaches the target once approved.
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, role = create_password_user(api)
            target = create_http_target(api, role, echo_server_port)

        session = requests.Session()
        session.verify = False
        session.post(
            f"{url}/@warpgate/api/auth/login",
            json={"username": user.username, "password": "123"},
        )

        held = session.get(f"{url}/?warpgate-target={target.name}")
        assert held.status_code == 202, "a held session must not reach the target"
        assert held.headers.get("retry-after")

        with admin_client(url) as api:
            approval = wait_for_pending_approval(api, target.name, user.username)
            assert approval.protocol == "HTTP"
            api.approve_session(approval.id, sdk.ApprovalScope.ONCE)

        # The client's own retry now goes through to the echo server.
        for _ in range(40):
            response = session.get(f"{url}/?warpgate-target={target.name}")
            if response.status_code == 200:
                break
        assert response.status_code == 200, "approved session should reach the target"

    def test_http_request_is_forbidden_after_rejection(
        self,
        echo_server_port,
        processes: ProcessManager,
        shared_wg: WarpgateProcess,
    ):
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, role = create_password_user(api)
            target = create_http_target(api, role, echo_server_port)

        session = requests.Session()
        session.verify = False
        session.post(
            f"{url}/@warpgate/api/auth/login",
            json={"username": user.username, "password": "123"},
        )

        assert session.get(f"{url}/?warpgate-target={target.name}").status_code == 202

        with admin_client(url) as api:
            approval = wait_for_pending_approval(api, target.name, user.username)
            api.reject_session(approval.id)

        for _ in range(40):
            response = session.get(f"{url}/?warpgate-target={target.name}")
            if response.status_code == 403:
                break
        assert response.status_code == 403, "a denied session must stay denied"

    def test_http_target_without_approval_is_untouched(
        self,
        echo_server_port,
        shared_wg: WarpgateProcess,
    ):
        # The gate must cost nothing for the targets that don't ask for it.
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, role = create_password_user(api)
            target = create_http_target(
                api, role, echo_server_port, require_approval=False
            )

        session = requests.Session()
        session.verify = False
        session.post(
            f"{url}/@warpgate/api/auth/login",
            json={"username": user.username, "password": "123"},
        )
        assert session.get(f"{url}/?warpgate-target={target.name}").status_code == 200

    def test_cross_node_rejection(
        self,
        processes: ProcessManager,
        timeout,
    ):
        # The approval RPC is exercised cross-node elsewhere; a denial travels
        # the same path and must actually end the session on the owning node.
        node_a = processes.start_wg()
        wait_port(node_a.http_port, recv=False)
        node_b = processes.start_wg(share_with=node_a)
        wait_port(node_b.http_port, recv=False)

        db_port = processes.start_postgres_server()
        wait_port(db_port, recv=False)
        with admin_client(f"https://localhost:{node_a.http_port}") as api:
            user, role = create_password_user(api)
            target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"postgres-{uuid.uuid4()}",
                    require_approval=True,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetPostgresOptions(
                            kind="Postgres",
                            host="localhost",
                            port=db_port,
                            username="user",
                            auth=sdk.DatabaseTargetAuth(
                                sdk.DatabaseTargetAuthDatabaseTargetPasswordAuth(
                                    kind="Password", password="123"
                                )
                            ),
                            tls=sdk.Tls(mode=sdk.TlsMode.PREFERRED, verify=False),
                        )
                    ),
                )
            )
            api.add_target_role(target.id, role.id)

        client = psql_held(processes, node_a.postgres_port, user, target)

        with admin_client(f"https://localhost:{node_b.http_port}") as api:
            approval = wait_for_pending_approval(api, target.name, user.username)
            api.reject_session(approval.id)

        client.communicate(timeout=timeout)
        assert client.returncode != 0

    def test_vnc_session_is_held_under_the_hold_screen(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        # The desktop protocols gate under their holding screen, so the viewer
        # sees a spinner rather than a frozen frame. The viewer connects, then
        # blocks waiting for the backend until an administrator approves.
        vnc_port = processes.start_vnc_server()
        wait_port(vnc_port)
        wait_port(shared_wg.vnc_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, role = create_password_user(api)
            target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"vnc-{uuid.uuid4()}",
                    require_approval=True,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetVncOptions(
                            kind="Vnc",
                            host="localhost",
                            port=vnc_port,
                            auth=sdk.VncTargetAuth(
                                sdk.VncTargetAuthVncTargetPasswordAuth(
                                    kind="Password", password="123"
                                )
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(target.id, role.id)

        result = {}

        def run_vnc():
            client = VncClient(
                "localhost",
                shared_wg.vnc_port,
                f"{user.username}:{target.name}",
                "123",
                timeout=timeout,
            )
            try:
                client.connect()
                result["size"] = client.wait_for_resize()
            except Exception as error:  # noqa: BLE001
                result["error"] = error
            finally:
                client.close()

        viewer = threading.Thread(target=run_vnc, daemon=True)
        viewer.start()

        with admin_client(url) as api:
            approval = wait_for_pending_approval(api, target.name, user.username)
            assert approval.protocol == "VNC"
            api.approve_session(approval.id, sdk.ApprovalScope.ONCE)

        viewer.join(timeout=timeout)
        assert "error" not in result, result.get("error")
        # Relaying to the backend only starts once approved.
        assert result.get("size") == VNC_BACKEND_SIZE

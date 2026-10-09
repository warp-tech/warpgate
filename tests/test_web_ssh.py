import base64
import json
import ssl
import time
from pathlib import Path
from uuid import uuid4

import psutil
import pytest
import requests
from websocket import WebSocketBadStatusException, create_connection

from .api_client import admin_client, sdk
from .approval_util import wait_for_pending_approval
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port


def _web_ssh_login(processes, wg_c_ed25519_pubkey, shared_wg, require_approval=False):
    """A password user logged in to the gateway, and an SSH target they may reach."""
    ssh_port = processes.start_ssh_server(
        trusted_keys=[wg_c_ed25519_pubkey.read_text()]
    )
    wait_port(ssh_port)

    url = f"https://localhost:{shared_wg.http_port}"
    with admin_client(url) as api:
        role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
        user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
        api.create_password_credential(
            user.id, sdk.NewPasswordCredential(password="123")
        )
        api.add_user_role(user.id, role.id)
        ssh_target = api.create_target(
            sdk.TargetDataRequest(
                name=f"ssh-{uuid4()}",
                require_approval=require_approval,
                ticket_requests_disabled=False,
                ticket_require_approval=False,
                options=sdk.TargetOptions(
                    sdk.TargetOptionsTargetSSHOptions(
                        kind="Ssh",
                        allow_insecure_algos=False,
                        host="127.0.0.1",
                        port=ssh_port,
                        username="root",
                        auth=sdk.SSHTargetAuth(
                            sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                        ),
                    )
                ),
            )
        )
        api.add_target_role(ssh_target.id, role.id)

    http = requests.Session()
    http.verify = False
    resp = http.post(
        f"{url}/@warpgate/api/auth/login",
        json={"username": user.username, "password": "123"},
    )
    assert resp.status_code // 100 == 2
    return url, http, user, ssh_target


def _create_session(url, http, target):
    resp = http.post(
        f"{url}/@warpgate/api/web-ssh/sessions",
        json={"target_id": str(target.id)},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["session_id"]


def _open_stream(shared_wg, http, session_id):
    cookie = "; ".join(f"{k}={v}" for k, v in http.cookies.get_dict().items())
    return create_connection(
        f"wss://localhost:{shared_wg.http_port}/@warpgate/api/web-ssh/sessions/{session_id}/stream",
        cookie=cookie,
        sslopt={"cert_reqs": ssl.CERT_NONE},
    )


def _wait_for_phase(ws, phase, deadline):
    """Read stream messages until the session reports `phase`. A `closed` phase
    arriving instead fails the test with its reason."""
    while time.time() < deadline:
        msg = json.loads(ws.recv())
        if msg["type"] != "state":
            continue
        if msg["phase"] == phase:
            return msg
        if msg["phase"] == "closed":
            raise AssertionError(f"session closed: {msg}")
    raise TimeoutError(f"did not reach phase {phase!r} in time")


def _wait_for_close(ws, deadline):
    """Read stream messages until the session reports `closed`; returns that message."""
    while time.time() < deadline:
        msg = json.loads(ws.recv())
        if msg["type"] == "state" and msg["phase"] == "closed":
            return msg
    raise TimeoutError("session was not closed in time")


def _run_shell_roundtrip(ws, deadline):
    ws.send(json.dumps({"type": "open_channel", "cols": 80, "rows": 24}))

    channel_id = None
    while time.time() < deadline:
        msg = json.loads(ws.recv())
        if msg["type"] == "channel_opened":
            channel_id = msg["channel_id"]
            break
        if msg["type"] == "state" and msg["phase"] == "closed":
            raise AssertionError(f"session closed: {msg}")
    else:
        raise TimeoutError("Did not receive channel_opened message in time")

    cmd = "echo webssh_test\n"
    ws.send(
        json.dumps(
            {
                "type": "input",
                "channel_id": channel_id,
                "data": base64.b64encode(cmd.encode()).decode(),
            }
        )
    )

    output = ""
    while time.time() < deadline:
        msg = json.loads(ws.recv())
        if msg["type"] == "output" and msg["channel_id"] == channel_id:
            output += base64.b64decode(msg["data"]).decode(errors="replace")
            if "webssh_test" in output:
                break
        elif msg["type"] == "state" and msg["phase"] == "closed":
            raise AssertionError(f"session closed: {msg}")
    else:
        raise TimeoutError("Did not receive expected output in time")

    ws.send(json.dumps({"type": "close_channel", "channel_id": channel_id}))


class TestWebSsh:
    def test_session_lifecycle(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        url, http, _, ssh_target = _web_ssh_login(
            processes, wg_c_ed25519_pubkey, shared_wg
        )
        session_id = _create_session(url, http, ssh_target)

        resp = http.get(f"{url}/@warpgate/api/web-ssh/sessions/{session_id}")
        assert resp.status_code == 200
        assert resp.json()["target_name"] == ssh_target.name

        ws = _open_stream(shared_wg, http, session_id)
        try:
            deadline = time.time() + timeout
            # The session id comes back before the target is dialled; the stream
            # says when the shell can be opened.
            _wait_for_phase(ws, "connected", deadline)
            _run_shell_roundtrip(ws, deadline)

            resp = http.delete(f"{url}/@warpgate/api/web-ssh/sessions/{session_id}")
            assert resp.status_code == 204
            # An attached viewer is told the session ended before its stream drops.
            assert _wait_for_close(ws, deadline)["reason"] == "disconnected"
        finally:
            ws.close()

        resp = http.get(f"{url}/@warpgate/api/web-ssh/sessions/{session_id}")
        assert resp.status_code == 404

    def test_admin_approval_approved(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        url, http, user, ssh_target = _web_ssh_login(
            processes, wg_c_ed25519_pubkey, shared_wg, require_approval=True
        )
        # Returns at once: the wait for an administrator happens behind the stream.
        session_id = _create_session(url, http, ssh_target)

        ws = _open_stream(shared_wg, http, session_id)
        try:
            deadline = time.time() + timeout
            _wait_for_phase(ws, "awaiting_approval", deadline)

            with admin_client(url) as api:
                approval = wait_for_pending_approval(
                    api, ssh_target.name, user.username
                )
                api.approve_session(
                    approval.id,
                    sdk.ApproveSessionRequest(
                        scope=sdk.ApprovalScope.ONCE, target=approval.target
                    ),
                )

            _wait_for_phase(ws, "connected", deadline)
            _run_shell_roundtrip(ws, deadline)
        finally:
            ws.close()

        resp = http.delete(f"{url}/@warpgate/api/web-ssh/sessions/{session_id}")
        assert resp.status_code == 204

    def test_admin_approval_rejected(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        url, http, user, ssh_target = _web_ssh_login(
            processes, wg_c_ed25519_pubkey, shared_wg, require_approval=True
        )
        session_id = _create_session(url, http, ssh_target)

        ws = _open_stream(shared_wg, http, session_id)
        try:
            deadline = time.time() + timeout
            _wait_for_phase(ws, "awaiting_approval", deadline)

            with admin_client(url) as api:
                approval = wait_for_pending_approval(
                    api, ssh_target.name, user.username
                )
                api.reject_session(
                    approval.id, sdk.RejectSessionRequest(target=approval.target)
                )

            assert _wait_for_close(ws, deadline)["reason"] == "approval_rejected"
        finally:
            ws.close()

        # A refused attempt leaves no session behind.
        for _ in range(timeout * 4):
            resp = http.get(f"{url}/@warpgate/api/web-ssh/sessions/{session_id}")
            if resp.status_code == 404:
                break
            time.sleep(0.25)
        assert resp.status_code == 404

    def test_admin_close_ends_the_backend_connection(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        url, http, _, ssh_target = _web_ssh_login(
            processes, wg_c_ed25519_pubkey, shared_wg
        )
        session_id = _create_session(url, http, ssh_target)
        ws = _open_stream(shared_wg, http, session_id)
        try:
            deadline = time.time() + timeout
            _wait_for_phase(ws, "connected", deadline)
            _run_shell_roundtrip(ws, deadline)
        finally:
            ws.close()

        # Check the target connection independently of websocket cleanup.
        ssh_port = ssh_target.options.actual_instance.port

        def backend_connected():
            return any(
                connection.status == psutil.CONN_ESTABLISHED
                and connection.raddr
                and connection.raddr.port == ssh_port
                for connection in psutil.Process(shared_wg.process.pid).net_connections(
                    kind="tcp"
                )
            )

        assert backend_connected(), "warpgate never connected to the SSH target"
        with admin_client(url) as api:
            api.close_session(session_id)

        # Disconnect before the 60-second reconnect grace period expires.
        deadline = time.time() + min(timeout, 20)
        while time.time() < deadline and backend_connected():
            time.sleep(0.25)
        assert not backend_connected(), "admin close left the SSH backend connected"

        with pytest.raises(WebSocketBadStatusException) as rejected:
            _open_stream(shared_wg, http, session_id)
        assert rejected.value.status_code == 404

        resp = http.get(f"{url}/@warpgate/api/web-ssh/sessions/{session_id}")
        assert resp.status_code == 404

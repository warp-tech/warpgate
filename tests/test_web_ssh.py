import base64
import json
import ssl
import time
from pathlib import Path
from uuid import uuid4

import psutil
import requests
from websocket import WebSocketBadStatusException, create_connection

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port


class TestWebSsh:
    def test_session_lifecycle(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
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
                    require_approval=False,
                    ticket_requests_disabled=False,
                    ticket_require_approval=False,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetSSHOptions(
                            kind="Ssh",
                            allow_insecure_algos=False,
                            host="localhost",
                            port=ssh_port,
                            username="root",
                            auth=sdk.SSHTargetAuth(
                                sdk.SSHTargetAuthSshTargetPublicKeyAuth(
                                    kind="PublicKey"
                                )
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(ssh_target.id, role.id)

        # Log in as the user
        http = requests.Session()
        http.verify = False
        resp = http.post(
            f"{url}/@warpgate/api/auth/login",
            json={"username": user.username, "password": "123"},
        )
        assert resp.status_code // 100 == 2

        # Create a web SSH session
        resp = http.post(
            f"{url}/@warpgate/api/web-ssh/sessions",
            json={"target_id": str(ssh_target.id)},
        )
        assert resp.status_code == 201, resp.text
        session_id = resp.json()["session_id"]

        # Verify session info is retrievable
        resp = http.get(f"{url}/@warpgate/api/web-ssh/sessions/{session_id}")
        assert resp.status_code == 200
        assert resp.json()["target_name"] == ssh_target.name

        # Connect via WebSocket
        cookie = "; ".join(f"{k}={v}" for k, v in http.cookies.get_dict().items())
        ws = create_connection(
            f"wss://localhost:{shared_wg.http_port}/@warpgate/api/web-ssh/sessions/{session_id}/stream",
            cookie=cookie,
            sslopt={"cert_reqs": ssl.CERT_NONE},
        )
        try:
            # Request a shell channel
            ws.send(json.dumps({"type": "open_channel", "cols": 80, "rows": 24}))

            deadline = time.time() + timeout
            channel_id = None
            while time.time() < deadline:
                msg = json.loads(ws.recv())
                if msg["type"] == "channel_opened":
                    channel_id = msg["channel_id"]
                    break
                if msg["type"] == "error":
                    raise AssertionError(f"SSH error: {msg['message']}")
            else:
                raise TimeoutError("Did not receive channel_opened message in time")

            assert channel_id is not None, "Did not receive channel_opened"

            # Send a command and collect output until the marker appears
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
                elif msg["type"] == "error":
                    raise AssertionError(f"SSH error: {msg['message']}")
            else:
                raise TimeoutError("Did not receive expected output in time")

            # Close the channel
            ws.send(json.dumps({"type": "close_channel", "channel_id": channel_id}))
        finally:
            ws.close()

        # Delete the session
        resp = http.delete(f"{url}/@warpgate/api/web-ssh/sessions/{session_id}")
        assert resp.status_code == 204

        # Session should be gone
        resp = http.get(f"{url}/@warpgate/api/web-ssh/sessions/{session_id}")
        assert resp.status_code == 404

    def test_admin_close_ends_the_backend_connection(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        # Admin "close session" must actually end the session: abort the SSH
        # connection to the target (not just mark the websocket dead), and
        # refuse to let a client reattach to what's now a dead session.
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
                    require_approval=False,
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
                                sdk.SSHTargetAuthSshTargetPublicKeyAuth(
                                    kind="PublicKey"
                                )
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(ssh_target.id, role.id)

        # Log in as the user
        http = requests.Session()
        http.verify = False
        resp = http.post(
            f"{url}/@warpgate/api/auth/login",
            json={"username": user.username, "password": "123"},
        )
        assert resp.status_code // 100 == 2

        # Create a web SSH session
        resp = http.post(
            f"{url}/@warpgate/api/web-ssh/sessions",
            json={"target_id": str(ssh_target.id)},
        )
        assert resp.status_code == 201, resp.text
        session_id = resp.json()["session_id"]

        cookie = "; ".join(f"{k}={v}" for k, v in http.cookies.get_dict().items())
        stream_url = (
            f"wss://localhost:{shared_wg.http_port}"
            f"/@warpgate/api/web-ssh/sessions/{session_id}/stream"
        )

        # Connect via WebSocket and prove the backend is really up (not just
        # the websocket) by round-tripping a command through it.
        ws = create_connection(
            stream_url, cookie=cookie, sslopt={"cert_reqs": ssl.CERT_NONE}
        )
        deadline = time.time() + timeout
        try:
            ws.send(json.dumps({"type": "open_channel", "cols": 80, "rows": 24}))
            channel_id = None
            while time.time() < deadline:
                msg = json.loads(ws.recv())
                if msg["type"] == "channel_opened":
                    channel_id = msg["channel_id"]
                    break
                if msg["type"] == "error":
                    raise AssertionError(f"SSH error: {msg['message']}")
            else:
                raise TimeoutError("Did not receive channel_opened message in time")
            assert channel_id is not None, "Did not receive channel_opened"

            cmd = "echo webssh_close_test\n"
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
                    if "webssh_close_test" in output:
                        break
                elif msg["type"] == "error":
                    raise AssertionError(f"SSH error: {msg['message']}")
            else:
                raise TimeoutError("Did not receive expected output in time")
        finally:
            try:
                ws.close()
            except Exception:
                pass

        # The backend is a real TCP socket from the warpgate process to the
        # target -- visible on the host independently of the websocket, and
        # of when the manager gets around to reaping the session.
        # Per-process, so it works without root (system-wide
        # `psutil.net_connections` is denied on macOS).
        def backend_connected():
            return any(
                c.status == psutil.CONN_ESTABLISHED
                and c.raddr
                and c.raddr.port == ssh_port
                for c in psutil.Process(shared_wg.process.pid).net_connections(
                    kind="tcp"
                )
            )

        assert backend_connected(), "warpgate never connected to the SSH target"

        # Admin closes the session.
        with admin_client(url) as api:
            api.close_session(session_id)

        # The backend must disconnect promptly. The wait is capped well under
        # the 60s reattach grace period: before the fix, admin close only
        # marked the websocket dead and left the backend connected until that
        # timer swept it, so waiting longer would pass without the fix.
        deadline = time.time() + min(timeout, 20)
        while time.time() < deadline and backend_connected():
            time.sleep(0.25)
        assert not backend_connected(), (
            "admin close did not abort the SSH backend connection"
        )

        # A closed session must refuse a websocket reattach -- specifically with a
        # 404, matching the "not found" response an unrelated/nonexistent session
        # gets, not merely *some* error. Admin close is delivered to the manager
        # asynchronously, so this doesn't land the instant the admin request
        # returns; it's the disconnect-triggered 404 that matters here, whichever
        # of the two guards (dead-but-registered, or already reaped) produces it.
        # The dead-but-registered case specifically -- the new `is_dead()` guard --
        # isn't reproducible deterministically from here (by the time this checks,
        # the session may already be fully removed) and is covered instead by a
        # Rust unit test in warpgate-web-clients-common.
        def attach_rejected():
            try:
                probe = create_connection(
                    stream_url, cookie=cookie, sslopt={"cert_reqs": ssl.CERT_NONE}
                )
                probe.close()
                return False
            except WebSocketBadStatusException as e:
                assert e.status_code == 404, (
                    "a closed web-SSH session should be rejected with 404, "
                    f"got HTTP {e.status_code}"
                )
                return True

        deadline = time.time() + timeout
        while time.time() < deadline and not attach_rejected():
            time.sleep(0.25)
        assert attach_rejected(), "a closed web-SSH session could still be reattached"

        # And once the manager finishes reaping it, the REST endpoint agrees.
        deadline = time.time() + timeout
        resp = None
        while time.time() < deadline:
            resp = http.get(f"{url}/@warpgate/api/web-ssh/sessions/{session_id}")
            if resp.status_code == 404:
                break
            time.sleep(0.25)
        assert resp is not None and resp.status_code == 404

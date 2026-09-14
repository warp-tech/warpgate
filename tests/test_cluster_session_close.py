import time
from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import ProcessManager
from .test_recordings_s3 import _read_until
from .test_ssh_proto import common_args, setup_user_and_target
from .util import wait_port


def _live_ssh_session_id(url, username):
    with admin_client(url) as api:
        for s in api.get_sessions().items:
            if s.ended is None and s.protocol == "SSH" and s.username == username:
                return s.id
    return None


def _poll(fn, deadline_s=15):
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        value = fn()
        if value:
            return value
        time.sleep(0.5)
    return None


class Test:
    def test_cross_node_session_close(
        self,
        processes: ProcessManager,
        timeout,
        wg_c_ed25519_pubkey,
    ):
        # Two nodes on one database. The live session handle exists only on the
        # node that owns the connection (A); closing it from node B must proxy
        # the request to A.
        node_a = processes.start_wg()
        wait_port(node_a.http_port, recv=False)
        node_b = processes.start_wg(share_with=node_a)
        wait_port(node_b.http_port, recv=False)

        url_b = f"https://localhost:{node_b.http_port}"

        user, ssh_target = setup_user_and_target(processes, node_a, wg_c_ed25519_pubkey)

        # Session on node A that stays open far longer than the test, so only an
        # explicit close (not the command finishing) can end it in-window.
        marker = f"cluster-{uuid4().hex}"
        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(node_a.ssh_port),
            "-tt",
            *common_args,
            f"echo {marker}; sleep 3600",
            password="123",
        )
        output = _read_until(
            ssh_client.stdout, marker.encode(), time.monotonic() + timeout
        )
        assert marker.encode() in output, "marker never appeared in session output"

        # Discover the live session via node B (shared DB projection).
        session_id = _poll(lambda: _live_ssh_session_id(url_b, user.username))
        assert session_id is not None, "live session not visible from node B"

        # Close it FROM NODE B — B holds no handle for it, so it must proxy to A.
        with admin_client(url_b) as api:
            api.close_session(session_id)

        # The closed handle drops the client connection quickly (well before the
        # 3600s sleep would end it); a timeout here means the close did not land.
        assert ssh_client.wait(timeout=30) is not None, "session was not closed"

        # And the session is marked ended in the shared DB.
        def ended():
            with admin_client(url_b) as api:
                return api.get_session(session_id).ended is not None

        assert _poll(ended), "session never marked ended after close"

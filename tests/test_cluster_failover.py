import time
from uuid import uuid4

import psutil
import requests

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .test_recordings_s3 import _read_until
from .test_ssh_proto import common_args, setup_user_and_target
from .util import open_wg_sqlite_db as _db
from .util import wait_port


def _find_in_progress_terminal_recording_id(api):
    for session in sorted(
        api.get_sessions().items, key=lambda s: s.started, reverse=True
    ):
        for rec in api.get_session_recordings(session.id):
            if rec.kind == sdk.RecordingKind.TERMINAL and rec.ended is None:
                return rec.id
    return None


def _live_session_node(config_path):
    """(session_id, node_id) of the most recent still-open session, or None."""
    with _db(config_path) as db:
        row = db.execute(
            "SELECT id, node_id FROM sessions"
            " WHERE ended IS NULL ORDER BY started DESC LIMIT 1"
        ).fetchone()
    return row


def _node_exists(config_path, node_id):
    with _db(config_path) as db:
        return (
            db.execute("SELECT 1 FROM nodes WHERE id = ?", (node_id,)).fetchone()
            is not None
        )


def _session_ended(config_path, session_id):
    with _db(config_path) as db:
        row = db.execute(
            "SELECT ended FROM sessions WHERE id = ?", (session_id,)
        ).fetchone()
    return row is not None and row[0] is not None


def _hard_kill(node: WarpgateProcess):
    """SIGKILL the node and its children: an uncatchable crash, so the node
    never runs its graceful shutdown and the surviving node's reaper is what
    must clean up after it."""
    try:
        p = psutil.Process(node.process.pid)
    except psutil.NoSuchProcess:
        return
    for sp in p.children(recursive=True):
        try:
            sp.kill()
        except psutil.NoSuchProcess:
            pass
    p.kill()
    try:
        p.wait(timeout=10)
    except psutil.TimeoutExpired:
        pass


def _open_session_on_a(processes, node_a, pubkey, timeout):
    """Start a long-lived SSH session on node A and return its (id, node_id)."""
    user, ssh_target = setup_user_and_target(processes, node_a, pubkey)
    marker = f"cluster-{uuid4().hex}"
    ssh_client = processes.start_ssh_client(
        f"{user.username}:{ssh_target.name}@localhost",
        "-p",
        str(node_a.ssh_port),
        "-tt",
        *common_args,
        f"echo {marker}; sleep 60",
        password="123",
    )
    output = _read_until(ssh_client.stdout, marker.encode(), time.monotonic() + timeout)
    assert marker.encode() in output, "marker never appeared in session output"

    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        row = _live_session_node(node_a.config_path)
        if row is not None:
            return row
        time.sleep(0.5)
    raise AssertionError("session did not register in the cluster database")


class Test:
    def test_dead_node_is_reaped(
        self,
        processes: ProcessManager,
        timeout,
        wg_c_ed25519_pubkey,
    ):
        # Two nodes on one database. A owns a live session; when A crashes
        # without a chance to deregister, B's reaper must mark A's sessions
        # ended and drop A's node row.
        node_a = processes.start_wg(config_patch={"recordings": {"enable": True}})
        wait_port(node_a.http_port, recv=False)
        node_b = processes.start_wg(share_with=node_a)
        wait_port(node_b.http_port, recv=False)

        session_id, node_a_id = _open_session_on_a(
            processes, node_a, wg_c_ed25519_pubkey, timeout
        )
        assert _node_exists(node_b.config_path, node_a_id), "node A never registered"

        _hard_kill(node_a)

        # Reaper: heartbeat timeout (30s) + reap interval (15s), plus margin.
        deadline = time.monotonic() + 70
        while time.monotonic() < deadline:
            if not _node_exists(node_b.config_path, node_a_id) and _session_ended(
                node_b.config_path, session_id
            ):
                break
            time.sleep(1)
        assert not _node_exists(
            node_b.config_path, node_a_id
        ), "dead node A was not reaped from the registry"
        assert _session_ended(
            node_b.config_path, session_id
        ), "dead node's session was not marked ended"

    def test_proxy_fails_cleanly_when_owner_dies(
        self,
        processes: ProcessManager,
        timeout,
        wg_c_ed25519_pubkey,
    ):
        # A cross-node recording read must fail with a gateway error, not hang
        # or wrongly succeed, once the owning node is unreachable but still
        # registered (before the reaper runs).
        node_a = processes.start_wg(config_patch={"recordings": {"enable": True}})
        wait_port(node_a.http_port, recv=False)
        node_b = processes.start_wg(share_with=node_a)
        wait_port(node_b.http_port, recv=False)
        url_b = f"https://localhost:{node_b.http_port}"

        _open_session_on_a(processes, node_a, wg_c_ed25519_pubkey, timeout)

        # The in-progress recording exists only on A; discover it via the admin
        # API (through B) so the id is a normal string, not a raw DB value.
        recording_id = None
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and recording_id is None:
            with admin_client(url_b) as api:
                recording_id = _find_in_progress_terminal_recording_id(api)
            if recording_id is None:
                time.sleep(0.5)
        assert recording_id is not None, "no in-progress recording found"

        # Sanity: B proxies the live read to A while A is up.
        ok = requests.get(
            f"{url_b}/@warpgate/admin/api/recordings/{recording_id}/data",
            headers={"X-Warpgate-Token": "token-value"},
            verify=False,
            timeout=timeout,
        )
        assert ok.status_code == 200, f"pre-kill proxy read failed: {ok.status_code}"

        _hard_kill(node_a)

        # A is still in the registry, so B routes to it and the connection is
        # refused: a gateway error, promptly, not a hang or a false 200.
        dead = requests.get(
            f"{url_b}/@warpgate/admin/api/recordings/{recording_id}/data",
            headers={"X-Warpgate-Token": "token-value"},
            verify=False,
            timeout=timeout,
        )
        assert dead.status_code == 502, (
            f"expected 502 proxying to a dead node, got {dead.status_code}"
        )

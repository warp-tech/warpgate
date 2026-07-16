import base64
import json
import time
from uuid import uuid4

import requests

from .api_client import admin_client, sdk
from .conftest import ProcessManager
from .test_recordings_s3 import _read_until
from .test_ssh_proto import common_args, setup_user_and_target
from .util import wait_port

CLUSTER_TOKEN = "cluster-secret"


def _find_in_progress_terminal_recording_id(api):
    for session in sorted(
        api.get_sessions().items, key=lambda s: s.started, reverse=True
    ):
        for rec in api.get_session_recordings(session.id):
            if rec.kind == sdk.RecordingKind.TERMINAL and rec.ended is None:
                return rec.id
    return None


class Test:
    def test_cross_node_recording_proxy(
        self,
        processes: ProcessManager,
        timeout,
        wg_c_ed25519_pubkey,
    ):
        cluster_env = {"WARPGATE_CLUSTER_TOKEN": CLUSTER_TOKEN}

        # Two nodes on one database. Node A owns the session and alone holds the
        # in-progress recording file; node B must proxy live reads to A.
        node_a = processes.start_wg(
            config_patch={"recordings": {"enable": True}}, env=cluster_env
        )
        wait_port(node_a.http_port, recv=False)
        node_b = processes.start_wg(share_with=node_a, env=cluster_env)
        wait_port(node_b.http_port, recv=False)

        url_b = f"https://localhost:{node_b.http_port}"

        user, ssh_target = setup_user_and_target(processes, node_a, wg_c_ed25519_pubkey)

        # A session on node A that emits a marker and then stays open, so the
        # recording is still in progress when we read it from node B.
        marker = f"cluster-{uuid4().hex}"
        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(node_a.ssh_port),
            "-tt",
            *common_args,
            f"echo {marker}; sleep 30",
            password="123",
        )
        output = _read_until(
            ssh_client.stdout, marker.encode(), time.monotonic() + timeout
        )
        assert marker.encode() in output, "marker never appeared in session output"

        # The recording lives in the shared DB; find it while still in progress.
        recording_id = None
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and recording_id is None:
            with admin_client(url_b) as api:
                recording_id = _find_in_progress_terminal_recording_id(api)
            if recording_id is None:
                time.sleep(0.5)
        assert recording_id is not None, "no in-progress terminal recording found"

        # Fetch the in-progress recording FROM NODE B. B holds no file for it, so a
        # 200 carrying the marker proves B proxied the read to node A.
        resp = requests.get(
            f"{url_b}/@warpgate/admin/api/recordings/{recording_id}/data",
            headers={"X-Warpgate-Token": "token-value"},
            verify=False,
            timeout=timeout,
        )
        assert resp.status_code == 200, f"cross-node fetch failed: {resp.status_code}"
        recorded = b""
        for line in resp.text.splitlines():
            if not line:
                continue
            item = json.loads(line)
            if "data" in item:
                recorded += base64.b64decode(item["data"])
        assert marker.encode() in recorded, "proxied recording is missing the marker"

        # The cluster token is scoped to recordings: it must NOT reach general
        # admin endpoints, while the admin token still does.
        scoped = requests.get(
            f"{url_b}/@warpgate/admin/api/sessions",
            headers={"X-Warpgate-Cluster-Token": CLUSTER_TOKEN},
            verify=False,
            timeout=timeout,
        )
        assert (
            scoped.status_code != 200
        ), f"cluster token must not reach /sessions: {scoped.status_code}"
        admin = requests.get(
            f"{url_b}/@warpgate/admin/api/sessions",
            headers={"X-Warpgate-Token": "token-value"},
            verify=False,
            timeout=timeout,
        )
        assert (
            admin.status_code == 200
        ), f"admin token should reach /sessions: {admin.status_code}"

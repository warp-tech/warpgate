import base64
import json
import os
import shlex
import subprocess
import time
from pathlib import Path
from uuid import uuid4

import pytest
import requests

from .api_client import admin_client, sdk
from .conftest import ProcessManager
from .test_ssh_proto import setup_user_and_target
from .util import wait_port


def _completed_recordings(api, username, count, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        sessions = api.get_sessions(username=username).items
        if len(sessions) == count and all(
            s.ended is not None and all(t.ended is not None for t in s.target_sessions)
            for s in sessions
        ):
            return sessions, [
                rec for s in sessions for rec in api.get_session_recordings(s.id)
            ]
        time.sleep(0.1)
    raise AssertionError("SSH sessions did not finish")


def _recorded_data(url, recording):
    response = requests.get(
        f"{url}/@warpgate/admin/api/recordings/{recording.id}/data",
        headers={"X-Warpgate-Token": "token-value"},
        verify=False,
    )
    response.raise_for_status()
    return b"".join(
        base64.b64decode(item["data"])
        for line in response.text.splitlines()
        if "data" in (item := json.loads(line))
    )


@pytest.mark.parametrize("record_rsync", [False, True])
@pytest.mark.parametrize("direction", ["upload", "download"])
def test_rsync_recording(
    processes: ProcessManager, timeout, wg_c_ed25519_pubkey, record_rsync, direction
):
    wg = processes.start_wg()
    wait_port(wg.http_port, recv=False)
    url = f"https://localhost:{wg.http_port}"
    with admin_client(url) as api:
        assert api.get_parameters().record_rsync is True
        api.update_parameters(
            sdk.ParameterUpdate(recordings_enable=True, record_rsync=record_rsync)
        )
        # Updating the existing SCP switch must not reset the new setting.
        api.update_parameters(sdk.ParameterUpdate(record_scp=not record_rsync))
        assert api.get_parameters().record_rsync is record_rsync

    backend_port = processes.start_ssh_server(
        trusted_keys=[wg_c_ed25519_pubkey.read_text()]
    )
    wait_port(backend_port)
    user, target = setup_user_and_target(
        processes, wg, wg_c_ed25519_pubkey, ssh_port=backend_port
    )
    container = processes.ssh_containers[backend_port]
    local_path = processes.ctx.tmpdir / f"rsync-{uuid4().hex}"
    remote_path = f"/tmp/rsync-{uuid4().hex}"
    marker = b"warpgate-rsync-recording-test"
    payload = marker + os.urandom(65536) + marker
    if direction == "upload":
        local_path.write_bytes(payload)
    else:
        subprocess.run(
            ["docker", "exec", "-i", container, "sh", "-c", f"cat > {remote_path}"],
            input=payload,
            check=True,
        )

    ssh = [
        "ssh",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "IdentitiesOnly=yes",
        "-i",
        str(Path("ssh-keys/id_ed25519").resolve()),
        "-p",
        str(wg.ssh_port),
        "-l",
        f"{user.username}:{target.name}",
    ]
    endpoints = [str(local_path), f"localhost:{remote_path}"]
    if direction == "download":
        endpoints.reverse()
    transfer = processes.start(
        ["rsync", "-a", "--whole-file", "-e", shlex.join(ssh), *endpoints],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _, stderr = transfer.communicate(timeout=timeout)
    assert transfer.returncode == 0, stderr.decode()
    received = (
        subprocess.check_output(["docker", "exec", container, "cat", remote_path])
        if direction == "upload"
        else local_path.read_bytes()
    )
    assert received == payload

    with admin_client(url) as api:
        sessions, recordings = _completed_recordings(api, user.username, 1, timeout)
        assert sessions[0].target_sessions[0].target_id == target.id
        assert len(recordings) == int(record_rsync)
        if record_rsync:
            assert marker in _recorded_data(url, recordings[0])

    # Disabling file-transfer recordings must not disable ordinary exec output.
    control_marker = "ordinary-command-still-recorded"
    control = processes.start(
        [*ssh, "localhost", f"printf {control_marker}"], stdout=subprocess.PIPE
    )
    assert control.communicate(timeout=timeout)[0] == control_marker.encode()
    assert control.returncode == 0
    with admin_client(url) as api:
        _, recordings = _completed_recordings(api, user.username, 2, timeout)
        assert len(recordings) == int(record_rsync) + 1
        assert any(
            control_marker.encode() in _recorded_data(url, r) for r in recordings
        )

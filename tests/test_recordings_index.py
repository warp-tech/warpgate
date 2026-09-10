import base64
import json
import time

import requests

from .api_client import admin_client, sdk
from .conftest import ProcessManager
from .test_recordings_s3 import _find_completed_terminal_recording
from .test_ssh_proto import common_args, setup_user_and_target
from .util import wait_port

ADMIN_HEADERS = {"X-Warpgate-Token": "token-value"}


def _get(url, path, headers=None):
    return requests.get(
        f"{url}/@warpgate/admin/api{path}",
        headers={**ADMIN_HEADERS, **(headers or {})},
        verify=False,
    )


class Test:
    def test_terminal_recording_index(
        self,
        processes: ProcessManager,
        timeout,
        wg_c_ed25519_pubkey,
    ):
        wg = processes.start_wg(config_patch={"recordings": {"enable": True}})
        wait_port(wg.http_port, recv=False)
        url = f"https://localhost:{wg.http_port}"

        with admin_client(url) as api:
            api.update_parameters(sdk.ParameterUpdate(recordings_enable=True))

        user, ssh_target = setup_user_and_target(processes, wg, wg_c_ed25519_pubkey)

        # Enough output to cross the recorder's keyframe byte threshold several times,
        # so the index gets more than its initial anchor.
        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(wg.ssh_port),
            "-tt",
            *common_args,
            "seq 1 200000",
            password="123",
        )
        ssh_client.communicate(timeout=timeout)

        recording = None
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            with admin_client(url) as api:
                recording = _find_completed_terminal_recording(api)
            if recording is not None:
                break
            time.sleep(0.5)
        assert recording is not None, "no completed terminal recording found"
        assert recording.generation >= 3, "recording written without an index"

        resp = _get(url, f"/recordings/{recording.id}/index")
        assert resp.status_code == 200, f"index fetch failed: {resp.status_code}"
        entries = [json.loads(line) for line in resp.text.splitlines() if line]

        keyframes = [e for e in entries if e["type"] == "keyframe"]
        # ~600KB of output over a 256KB keyframe interval: several anchors, spread out.
        assert len(keyframes) >= 3, f"no periodic keyframes in the index: {entries[:5]}"
        assert keyframes[-1]["offset"] > 100_000, "keyframes are bunched at the start"
        assert [e for e in entries if e["type"] == "end"], "index has no duration marker"

        # Times must be monotonic, and the anchors must be usable: a Range request at a
        # keyframe's offset has to land exactly on the start of that keyframe's line.
        assert entries == sorted(entries, key=lambda e: e["time"])
        for kf in keyframes:
            if kf["offset"] == 0:
                continue
            resp = _get(
                url,
                f"/recordings/{recording.id}/data",
                headers={"Range": f"bytes={kf['offset']}-"},
            )
            assert resp.status_code == 206, (
                f"range request at {kf['offset']} was not served partially: "
                f"{resp.status_code}"
            )
            first = json.loads(resp.text.split("\n", 1)[0])
            assert "snapshot" in first, (
                f"offset {kf['offset']} does not point at a keyframe: {first.keys()}"
            )
            assert first["time"] == kf["time"]
            # The dump has to be replayable terminal bytes, not an empty screen.
            assert base64.b64decode(first["snapshot"])

import base64
import json
import time

import requests

from .api_client import admin_client, sdk
from .conftest import ProcessManager
from .test_recordings_s3 import _find_completed_terminal_recording, _read_until
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
        assert not [e for e in entries if e["type"] == "input_only"]

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

    def test_terminal_recording_input_only(
        self,
        processes: ProcessManager,
        timeout,
        wg_c_ed25519_pubkey,
    ):
        wg = processes.start_wg(config_patch={"recordings": {"enable": True}})
        wait_port(wg.http_port, recv=False)
        url = f"https://localhost:{wg.http_port}"

        with admin_client(url) as api:
            api.update_parameters(
                sdk.ParameterUpdate(
                    recordings_enable=True, record_terminal_output=False
                )
            )

        user, ssh_target = setup_user_and_target(processes, wg, wg_c_ed25519_pubkey)

        # An interactive shell, so the command travels over the Input stream and its
        # output (~600KB) over the Output stream the recorder is expected to drop.
        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(wg.ssh_port),
            "-tt",
            *common_args,
            password="123",
        )
        _read_until(ssh_client.stdout, b"#", time.monotonic() + timeout)
        stdout, _ = ssh_client.communicate(b"seq 1 200000\nexit\n", timeout=timeout)
        assert b"200000" in stdout, "the target did not produce the output"

        recording = None
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            with admin_client(url) as api:
                recording = _find_completed_terminal_recording(api)
            if recording is not None:
                break
            time.sleep(0.5)
        assert recording is not None, "no completed terminal recording found"

        resp = _get(url, f"/recordings/{recording.id}/data")
        assert resp.status_code == 200, f"data fetch failed: {resp.status_code}"
        items = [json.loads(line) for line in resp.text.splitlines() if line]
        data_items = [item for item in items if "data" in item]
        assert data_items, "nothing was recorded"
        assert {item["stream"] for item in data_items} == {"Input"}, (
            f"target output made it into the recording: {data_items[:3]}"
        )
        typed = b"".join(base64.b64decode(item["data"]) for item in data_items)
        assert b"seq 1 200000" in typed, "the typed command is missing"
        # Only keystrokes, resizes and blank snapshots are left of a ~600KB session.
        assert len(resp.content) < 20_000, f"recording is {len(resp.content)} bytes"

        resp = _get(url, f"/recordings/{recording.id}/index")
        assert resp.status_code == 200, f"index fetch failed: {resp.status_code}"
        entries = [json.loads(line) for line in resp.text.splitlines() if line]
        assert [e for e in entries if e["type"] == "end"], "index has no duration marker"
        # The player renders the keystrokes only when the index says so, and replays
        # from the start: no periodic anchors are written without output.
        assert [e for e in entries if e["type"] == "input_only"], "index lacks the marker"
        assert len([e for e in entries if e["type"] == "keyframe"]) == 1

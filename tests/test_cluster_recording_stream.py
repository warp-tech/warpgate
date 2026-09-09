"""Cross-node proxying of the live-recording WebSocket.

The HTTP proxy path is covered by `test_cluster_recordings.py`; this is the
WebSocket one, which forwards through a completely separate code path in
`warpgate-cluster`. It went unnoticed that that path was not sending the
cluster actor header — the peer rejects an unattributable cluster-token
request, so every cross-node upgrade failed.
"""

import time
from uuid import uuid4

import aiohttp
import pytest

from .api_client import admin_client
from .conftest import ProcessManager
from .test_cluster_recordings import _find_in_progress_terminal_recording_id
from .test_recordings_s3 import _read_until
from .test_ssh_proto import common_args, setup_user_and_target
from .util import wait_port


class Test:
    @pytest.mark.asyncio
    async def test_live_stream_is_proxied_to_the_owning_node(
        self,
        processes: ProcessManager,
        timeout,
        wg_c_ed25519_pubkey,
    ):
        node_a = processes.start_wg(config_patch={"recordings": {"enable": True}})
        wait_port(node_a.http_port, recv=False)
        node_b = processes.start_wg(share_with=node_a)
        wait_port(node_b.http_port, recv=False)
        url_b = f"https://localhost:{node_b.http_port}"

        user, ssh_target = setup_user_and_target(processes, node_a, wg_c_ed25519_pubkey)

        # A session on node A, still open so its recording is in progress.
        marker = f"cluster-{uuid4().hex}"
        client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(node_a.ssh_port),
            "-tt",
            *common_args,
            f"echo {marker}; sleep 30",
            password="123",
        )
        _read_until(client.stdout, marker.encode(), time.monotonic() + timeout)

        recording_id = None
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and recording_id is None:
            with admin_client(url_b) as api:
                recording_id = _find_in_progress_terminal_recording_id(api)
            if recording_id is None:
                time.sleep(0.5)
        assert recording_id is not None, "no in-progress terminal recording found"

        # Node B holds no file for this recording and no live subscription for
        # it, so an upgrade that completes and yields the owner's stream preamble
        # proves the socket was proxied through to node A. (What the live tail
        # then replays is the stream endpoint's own concern, not the proxy's.)
        stream_url = (
            f"{url_b}/@warpgate/admin/api/recordings/{recording_id}/stream"
        ).replace("https:", "wss:")
        async with aiohttp.ClientSession() as session:
            ws = await session.ws_connect(
                stream_url,
                headers={"X-Warpgate-Token": "token-value"},
                ssl=False,
            )
            try:
                message = await ws.receive(timeout=timeout)
                assert message.type is aiohttp.WSMsgType.TEXT, (
                    f"expected a stream frame from the owner, got {message.type}"
                )
                assert '"type":"start"' in message.data, message.data
                # `live` is the owner's answer: only node A has a subscription
                # for an in-progress recording, so this could not come from B.
                assert '"live":true' in message.data, message.data
            finally:
                await ws.close()

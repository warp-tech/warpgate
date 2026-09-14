"""Cluster-wide push notifications.

The admin session list stream is fed by the node's own session registry;
without a cluster relay, a browser attached to node B never hears about a
session that started on node A until its poll timer fires.
"""

import time
from uuid import uuid4

import aiohttp
import pytest

from .conftest import ProcessManager
from .test_recordings_s3 import _read_until
from .test_ssh_proto import common_args, setup_user_and_target
from .util import wait_port


class Test:
    @pytest.mark.asyncio
    async def test_session_change_on_one_node_wakes_stream_on_another(
        self,
        processes: ProcessManager,
        timeout,
        wg_c_ed25519_pubkey,
    ):
        node_a = processes.start_wg()
        wait_port(node_a.http_port, recv=False)
        node_b = processes.start_wg(share_with=node_a)
        wait_port(node_b.http_port, recv=False)

        user, ssh_target = setup_user_and_target(processes, node_a, wg_c_ed25519_pubkey)

        # Node B serves no sessions of its own, so any frame on its stream is
        # one relayed from node A.
        stream_url = f"wss://localhost:{node_b.http_port}/@warpgate/admin/api/sessions/changes"
        async with aiohttp.ClientSession() as session:
            ws = await session.ws_connect(
                stream_url,
                headers={"X-Warpgate-Token": "token-value"},
                ssl=False,
            )
            try:
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
                assert marker.encode() in output, "session never started on node A"

                message = await ws.receive(timeout=15)
                assert message.type is aiohttp.WSMsgType.TEXT, (
                    f"expected a change frame relayed from node A, got {message.type}"
                )
            finally:
                await ws.close()

import asyncio
import time

import aiohttp
import pytest

from .api_client import admin_client, sdk
from .conftest import ProcessManager
from .test_ssh_proto import setup_user_and_target
from .util import wait_port


class Test:
    @pytest.mark.asyncio
    async def test_cross_node_web_approval(
        self,
        processes: ProcessManager,
        timeout,
        wg_c_ed25519_pubkey,
    ):
        # Two nodes on one database. The SSH connection — and thus the
        # in-memory auth state awaiting web approval — lives on node A, while
        # the user is logged into node B. B holds no auth state for it, so
        # both the status read and the approval must be routed to A.
        node_a = processes.start_wg()
        wait_port(node_a.http_port, recv=False)
        node_b = processes.start_wg(share_with=node_a)
        wait_port(node_b.http_port, recv=False)

        url_a = f"https://localhost:{node_a.http_port}"
        url_b = f"https://localhost:{node_b.http_port}"

        user, ssh_target = setup_user_and_target(processes, node_a, wg_c_ed25519_pubkey)
        with admin_client(url_a) as api:
            api.update_user(
                user.id,
                sdk.UserDataRequest(
                    username=user.username,
                    credential_policy=sdk.UserRequireCredentialsPolicy(
                        ssh=[sdk.CredentialKind.WEBUSERAPPROVAL],
                    ),
                ),
            )

        async with aiohttp.ClientSession() as session:
            response = await session.post(
                f"{url_b}/@warpgate/api/auth/login",
                json={"username": user.username, "password": "123"},
                ssl=False,
            )
            assert response.status // 100 == 2

            ssh_client = processes.start_ssh_client(
                f"{user.username}:{ssh_target.name}@localhost",
                "-p",
                str(node_a.ssh_port),
                "-o",
                "IdentityFile=ssh-keys/id_ed25519",
                "ls",
                "/bin/sh",
            )

            # The auth state is keyed by the SSH session id, so it can be
            # looked up from the shared sessions table.
            auth_id = None
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline and auth_id is None:
                with admin_client(url_b) as api:
                    for s in api.get_sessions().items:
                        if s.protocol == "SSH" and s.ended is None:
                            auth_id = s.id
                if auth_id is None:
                    await asyncio.sleep(0.5)
            assert auth_id, "SSH session never appeared"

            state = None
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                response = await session.get(
                    f"{url_b}/@warpgate/api/auth/state/{auth_id}", ssl=False
                )
                if response.status == 200:
                    state = await response.json()
                    break
                await asyncio.sleep(0.5)
            assert state, "auth state never became visible via node B"
            assert state["protocol"] == "SSH"
            assert state["state"] == "WebUserApprovalNeeded"

            response = await session.post(
                f"{url_b}/@warpgate/api/auth/state/{auth_id}/approve",
                json={"scope": "Once"},
                ssl=False,
            )
            assert response.status == 200

        ssh_client.stdin.write(b"\r\n")
        assert ssh_client.communicate(timeout=timeout)[0] == b"/bin/sh\n"
        assert ssh_client.returncode == 0

import asyncio
import threading
from uuid import uuid4

import aiohttp
import pytest

from .api_client import admin_client, sdk
from .conftest import VNC_BACKEND_SIZE, ProcessManager, WarpgateProcess
from .util import wait_port
from .vnc_client import VncClient


class Test:
    @pytest.mark.asyncio
    async def test_web_approval(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        vnc_port = processes.start_vnc_server()
        wait_port(vnc_port)
        wait_port(shared_wg.vnc_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.update_user(
                user.id,
                sdk.UserDataRequest(
                    username=user.username,
                    credential_policy=sdk.UserRequireCredentialsPolicy(
                        vnc=[
                            sdk.CredentialKind.PASSWORD,
                            sdk.CredentialKind.WEBUSERAPPROVAL,
                        ],
                    ),
                ),
            )
            api.add_user_role(user.id, role.id)
            target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"vnc-{uuid4()}",
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetVncOptions(
                            kind="Vnc",
                            host="localhost",
                            port=vnc_port,
                            auth=sdk.VncTargetAuth(
                                sdk.VncTargetAuthVncTargetPasswordAuth(
                                    kind="Password", password="123"
                                )
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(target.id, role.id)

        selector = f"{user.username}:{target.name}"
        result = {}

        def run_vnc():
            client = VncClient(
                "localhost", shared_wg.vnc_port, selector, "123", timeout=timeout
            )
            try:
                client.connect()
                result["size"] = client.wait_for_resize()
            except Exception as error:  # noqa: BLE001
                result["error"] = error
            finally:
                client.close()

        session = aiohttp.ClientSession()
        try:
            headers = {"Host": f"localhost:{shared_wg.http_port}"}
            await session.post(
                f"{url}/@warpgate/api/auth/login",
                json={"username": user.username, "password": "123"},
                headers=headers,
                ssl=False,
            )
            ws = await session.ws_connect(
                url.replace("https:", "wss:")
                + "/@warpgate/api/auth/web-auth-requests/stream",
                ssl=False,
            )

            t = threading.Thread(target=run_vnc, daemon=True)
            t.start()

            # The VNC client's password auth creates the pending web-approval request.
            msg = await ws.receive(timeout)
            auth_id = msg.data

            # The signal can fire at auth-state creation, before the VeNCrypt password
            # is registered (when the state still reports PasswordNeeded); wait until web
            # approval is the only remaining factor.
            state = None
            for _ in range(int(timeout * 10)):
                state = await (
                    await session.get(
                        f"{url}/@warpgate/api/auth/state/{auth_id}", ssl=False
                    )
                ).json()
                assert state["protocol"] == "VNC"
                if state["state"] == "WebUserApprovalNeeded":
                    break
                await asyncio.sleep(0.1)
            else:
                raise AssertionError(f"web approval never became the only factor: {state}")

            r = await session.post(
                f"{url}/@warpgate/api/auth/state/{auth_id}/approve", json={"scope": "Once"}, ssl=False
            )
            assert r.status == 200

            t.join(timeout=timeout)
            assert not t.is_alive(), "VNC client did not complete after approval"
            assert "error" not in result, result.get("error")
            assert result["size"] == VNC_BACKEND_SIZE
        finally:
            await session.close()

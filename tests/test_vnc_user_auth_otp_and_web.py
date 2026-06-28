import asyncio
import threading
from base64 import b64decode
from uuid import uuid4

import aiohttp
import pyotp
import pytest

from .api_client import admin_client, sdk
from .conftest import VNC_BACKEND_SIZE, ProcessManager, WarpgateProcess
from .util import wait_port
from .vnc_client import VncClient


class Test:
    @pytest.mark.asyncio
    async def test_otp_and_web_auth(
        self,
        processes: ProcessManager,
        otp_key_base32: str,
        otp_key_base64: str,
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
            api.create_otp_credential(
                user.id, sdk.NewOtpCredential(secret_key=list(b64decode(otp_key_base64)))
            )
            api.update_user(
                user.id,
                sdk.UserDataRequest(
                    username=user.username,
                    credential_policy=sdk.UserRequireCredentialsPolicy(
                        vnc=[
                            sdk.CredentialKind.PASSWORD,
                            sdk.CredentialKind.TOTP,
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
        totp = pyotp.TOTP(otp_key_base32)
        otp_sent = threading.Event()
        result = {}

        def run_vnc():
            client = VncClient(
                "localhost", shared_wg.vnc_port, selector, "123", timeout=timeout
            )
            try:
                client.connect()
                # The OTP field is shown first; type it, then wait for web approval.
                client.type_text(totp.now())
                otp_sent.set()
                result["size"] = client.wait_for_resize()
            except Exception as error:  # noqa: BLE001
                result["error"] = error
                otp_sent.set()
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

            msg = await ws.receive(timeout)
            auth_id = msg.data

            # Wait until the OTP has been entered, then for only web approval to remain.
            assert otp_sent.wait(timeout)
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
                raise AssertionError("web approval was never the only remaining factor")

            r = await session.post(
                f"{url}/@warpgate/api/auth/state/{auth_id}/approve", ssl=False
            )
            assert r.status == 200

            t.join(timeout=timeout)
            assert not t.is_alive(), "VNC client did not complete after approval"
            assert "error" not in result, result.get("error")
            assert result["size"] == VNC_BACKEND_SIZE
        finally:
            await session.close()

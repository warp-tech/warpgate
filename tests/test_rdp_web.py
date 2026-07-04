import asyncio
import json
import time
from uuid import uuid4

import aiohttp
import pytest
import requests

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port

# How long to wait for the first framebuffer to arrive: an RDP relay spins up a helper
# subprocess and does a full NLA handshake against xrdp, so it's slower than the VNC path.
FRAME_TIMEOUT = 40


class Test:
    @pytest.mark.asyncio
    async def test_web_desktop_relay(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        # Real RDP backend (xrdp). Warpgate's helper connects to it over NLA and relays
        # framebuffer updates to the browser desktop client.
        rdp_backend_port = processes.start_rdp_server()
        wait_port(rdp_backend_port, recv=False)
        # xrdp accepts TCP before sesman is ready to start a session; give it a moment.
        time.sleep(3)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.add_user_role(user.id, role.id)
            target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"rdp-{uuid4()}",
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetRdpOptions(
                            kind="Rdp",
                            host="localhost",
                            port=rdp_backend_port,
                            username="user",  # the xrdp login baked into the image
                            auth=sdk.RdpTargetAuth(
                                sdk.RdpTargetAuthRdpTargetPasswordAuth(
                                    kind="Password", password="123"
                                )
                            ),
                            verify_tls=False,
                        )
                    ),
                )
            )
            api.add_target_role(target.id, role.id)

        headers = {"Host": f"localhost:{shared_wg.http_port}"}
        session = aiohttp.ClientSession()
        try:
            login = await session.post(
                f"{url}/@warpgate/api/auth/login",
                json={"username": user.username, "password": "123"},
                headers=headers,
                ssl=False,
            )
            assert login.status // 100 == 2, f"login failed: {login.status}"

            created = await session.post(
                f"{url}/@warpgate/api/web-desktop/sessions",
                json={"target_id": str(target.id)},
                headers=headers,
                ssl=False,
            )
            assert created.status == 201, (
                f"session create failed: {created.status} {await created.text()}"
            )
            session_id = (await created.json())["session_id"]

            ws = await session.ws_connect(
                url.replace("https:", "wss:")
                + f"/@warpgate/api/web-desktop/sessions/{session_id}/stream",
                ssl=False,
            )

            # Wait for the backend to connect and relay: a resize carries the negotiated
            # geometry, a binary message is an actual framebuffer update.
            got_image = False
            got_resize = False
            messages = []
            deadline = time.monotonic() + FRAME_TIMEOUT
            while time.monotonic() < deadline and not (got_image or got_resize):
                try:
                    msg = await ws.receive(timeout=deadline - time.monotonic())
                except asyncio.TimeoutError:
                    break
                if msg.type == aiohttp.WSMsgType.BINARY:
                    got_image = True
                elif msg.type == aiohttp.WSMsgType.TEXT:
                    parsed = json.loads(msg.data)
                    messages.append(parsed)
                    if parsed.get("type") == "resize":
                        got_resize = True
                    if parsed.get("type") == "error":
                        break
                else:  # CLOSED / CLOSING / ERROR
                    break

            assert got_image or got_resize, (
                f"backend never relayed a framebuffer; server messages: {messages}"
            )

            # Send viewer input; Warpgate records it (for audit) before forwarding to the
            # target, so it must show up in the recording alongside the framebuffer.
            await ws.send_str(
                json.dumps({"type": "pointer_event", "x": 120, "y": 90, "buttons": 0})
            )
            await ws.send_str(json.dumps({"type": "key_event", "keysym": 0x41, "down": True}))
            await ws.send_str(json.dumps({"type": "key_event", "keysym": 0x41, "down": False}))
            await asyncio.sleep(0.5)  # let the input be recorded before we finalise

            # Close the session so the recorder finalises and flushes its buffered writer
            # (it otherwise only flushes every 5s), then confirm the recording's contents.
            await session.delete(
                f"{url}/@warpgate/api/web-desktop/sessions/{session_id}",
                headers=headers,
                ssl=False,
            )
        finally:
            await session.close()

        # Recordings are enabled in the shared config, and the web-desktop session id is
        # the Warpgate session id, so the session has a Desktop recording.
        with admin_client(url) as api:
            recordings = api.get_session_recordings(session_id)
        desktop = [r for r in recordings if r.kind == sdk.RecordingKind.DESKTOP]
        assert desktop, (
            f"no desktop recording for session {session_id}: "
            f"{[str(r.kind) for r in recordings]}"
        )

        # Fetch the recording's ndjson and confirm it actually captured the desktop —
        # it must parse and contain at least one framebuffer item, not just be an empty file.
        rec_url = f"{url}/@warpgate/admin/api/recordings/{desktop[0].id}/desktop"
        items = []
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and not items:
            resp = requests.get(
                rec_url, headers={"X-Warpgate-Token": "token-value"}, verify=False
            )
            assert resp.status_code == 200, f"recording fetch failed: {resp.status_code}"
            items = [json.loads(line) for line in resp.text.splitlines() if line.strip()]
            if not items:
                time.sleep(0.3)

        assert items, "desktop recording is empty"
        recorded = {item.get("type") for item in items}
        framebuffer_types = {"resize", "png_image", "jpeg_image", "raw_image", "copy_rect"}
        input_types = {"key_input", "scancode_input", "pointer_input", "wheel_input"}
        assert recorded & framebuffer_types, (
            f"recording captured no framebuffer items, only: {recorded}"
        )
        assert recorded & input_types, (
            f"recording captured no viewer input, only: {recorded}"
        )

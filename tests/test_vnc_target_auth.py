from uuid import uuid4

import pytest

from .api_client import admin_client, sdk
from .conftest import VNC_BACKEND_SIZE, ProcessManager, WarpgateProcess
from .util import wait_port
from .vnc_client import VncClient, VncError


def _provision(api, vnc_port, target_password):
    role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
    user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
    api.create_password_credential(user.id, sdk.NewPasswordCredential(password="123"))
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
                            kind="Password", password=target_password
                        )
                    ),
                )
            ),
        )
    )
    api.add_target_role(target.id, role.id)
    return user, target


class Test:
    def test_target_password_auth(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        # Backend requires VncAuth; Warpgate authenticates to it with the target password.
        vnc_port = processes.start_vnc_server(require_password=True)
        wait_port(vnc_port)
        wait_port(shared_wg.vnc_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, target = _provision(api, vnc_port, target_password="123")

        client = VncClient(
            "localhost",
            shared_wg.vnc_port,
            f"{user.username}:{target.name}",
            "123",
            timeout=timeout,
        )
        try:
            client.connect()
            # Reaching the resize means the relay authenticated to the backend.
            assert client.wait_for_resize() == VNC_BACKEND_SIZE
        finally:
            client.close()

    def test_target_wrong_password_fails(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        # Target configured with the wrong backend password: the viewer authenticates,
        # but the relay can't authenticate to the backend, so the session never relays.
        vnc_port = processes.start_vnc_server(require_password=True)
        wait_port(vnc_port)
        wait_port(shared_wg.vnc_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, target = _provision(api, vnc_port, target_password="not-the-backend-password")

        client = VncClient(
            "localhost",
            shared_wg.vnc_port,
            f"{user.username}:{target.name}",
            "123",
            timeout=timeout,
        )
        try:
            # Viewer auth + our ServerInit succeed...
            client.connect()
            # ...but the backend VncAuth fails, so the connection drops without a resize.
            with pytest.raises((VncError, OSError)):
                client.wait_for_resize()
        finally:
            client.close()

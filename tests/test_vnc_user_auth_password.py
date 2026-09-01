from uuid import uuid4

import pytest

from .api_client import admin_client, sdk
from .conftest import VNC_BACKEND_SIZE, ProcessManager, WarpgateProcess
from .util import wait_port
from .vnc_client import VncClient, VncError


class Test:
    def test_password(
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

        client = VncClient(
            "localhost",
            shared_wg.vnc_port,
            f"{user.username}:{target.name}",
            "123",
            timeout=timeout,
        )
        try:
            client.connect()
            # A successful login relays through to the backend, resizing the viewer.
            assert client.wait_for_resize() == VNC_BACKEND_SIZE
        finally:
            client.close()

    def test_wrong_password_rejected(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        vnc_port = processes.start_vnc_server()
        wait_port(shared_wg.vnc_port)

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

        client = VncClient(
            "localhost",
            shared_wg.vnc_port,
            f"{user.username}:{target.name}",
            "wrong",
            timeout=timeout,
        )
        try:
            with pytest.raises(VncError):
                client.connect()
        finally:
            client.close()

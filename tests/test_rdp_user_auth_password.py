from uuid import uuid4

import pytest

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .rdp_client import auth_only, have_xfreerdp
from .util import wait_port

pytestmark = pytest.mark.skipif(
    not have_xfreerdp(), reason="FreeRDP (xfreerdp) is not installed"
)


def _provision(api, viewer_password="123"):
    role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
    user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
    api.create_password_credential(
        user.id, sdk.NewPasswordCredential(password=viewer_password)
    )
    api.add_user_role(user.id, role.id)
    target = api.create_target(
        sdk.TargetDataRequest(
            name=f"rdp-{uuid4()}",
            options=sdk.TargetOptions(
                sdk.TargetOptionsTargetRdpOptions(
                    kind="Rdp",
                    # +auth-only never dials the target (Warpgate accepts the viewer
                    # before connecting), so this address only needs to be well-formed.
                    host="localhost",
                    port=3389,
                    username="user",
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
    return user, target


class Test:
    def test_password(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        # RDP is client-initiated: the listener sends nothing until the client speaks,
        # so don't wait for a server greeting (like the HTTP/Kubernetes checks).
        wait_port(shared_wg.rdp_port, recv=False)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, target = _provision(api)

        code, output = auth_only(
            "localhost",
            shared_wg.rdp_port,
            f"{user.username}:{target.name}",
            "123",
            timeout,
        )
        assert code == 0, f"xfreerdp auth-only failed (exit {code}):\n{output}"

    def test_wrong_password_rejected(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        # RDP is client-initiated: the listener sends nothing until the client speaks,
        # so don't wait for a server greeting (like the HTTP/Kubernetes checks).
        wait_port(shared_wg.rdp_port, recv=False)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, target = _provision(api)

        code, output = auth_only(
            "localhost",
            shared_wg.rdp_port,
            f"{user.username}:{target.name}",
            "wrong",
            timeout,
        )
        assert code != 0, (
            f"xfreerdp auth-only unexpectedly succeeded with a wrong password:\n{output}"
        )

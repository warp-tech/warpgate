import time
from uuid import uuid4

import pytest

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .rdp_client import full_connect, have_xfreerdp
from .util import wait_port

pytestmark = pytest.mark.skipif(
    not have_xfreerdp(), reason="FreeRDP (xfreerdp) is not installed"
)


class Test:
    def test_target_cursor_reaches_the_viewer(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        rdp_backend_port = processes.start_rdp_server()
        wait_port(rdp_backend_port, recv=False)
        # xrdp accepts TCP before sesman is ready to start a session; give it a moment.
        time.sleep(3)
        wait_port(shared_wg.rdp_port, recv=False)

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
                    require_approval=False,
                    ticket_requests_disabled=False,
                    ticket_require_approval=False,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetRdpOptions(
                            kind="Rdp",
                            compression=sdk.RdpTargetCompression.REMOTEFX,
                            tls_security=sdk.RdpTlsSecurity.TLS12,
                            host="localhost",
                            port=rdp_backend_port,
                            username="user",  # the xrdp login baked into the image
                            auth=sdk.RdpTargetAuth(
                                sdk.RdpTargetAuthRdpTargetPasswordAuth(
                                    kind="Password", password="123"
                                )
                            ),
                            verify_tls=False,
                            interactive_logon=False,
                        )
                    ),
                )
            )
            api.add_target_role(target.id, role.id)

            # xfreerdp logs each cursor the server hands it (`[xf_Pointer_New]`) and each
            # time it applies one (`[xf_Pointer_Set]`; the bracket keeps out the
            # `xf_Pointer_SetNull` / `SetPosition` lines). xrdp sets the X cursor as soon as
            # its session starts, so the viewer must see them if Warpgate relays the target's
            # cursor, and none if it doesn't.
            output = full_connect(
                "localhost",
                shared_wg.rdp_port,
                f"{user.username}:{target.name}",
                "123",
                timeout * 2,
                extra_args=["/log-filters:com.freerdp.client.x11:DEBUG"],
            )
            # The keymap dump drowns out the rest of the log.
            log = "\n".join(
                line for line in output.splitlines() if "try_add" not in line
            )
            assert "[xf_Pointer_New]" in output, (
                f"the target's cursor never reached the viewer:\n{log}"
            )
            assert "[xf_Pointer_Set]" in output, (
                f"the viewer never applied the target's cursor:\n{log}"
            )

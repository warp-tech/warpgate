from uuid import uuid4

import pytest

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess, wait_rdp_session_authorized
from .rdp_client import full_connect, have_xfreerdp
from .util import wait_port

pytestmark = pytest.mark.skipif(
    not have_xfreerdp(), reason="FreeRDP (xfreerdp) is not installed"
)


class Test:
    def test_ticket(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        wait_port(shared_wg.rdp_port, recv=False)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.add_user_role(user.id, role.id)
            target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"rdp-{uuid4()}",
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetRdpOptions(
                            kind="Rdp",
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

            secret = api.create_ticket(
                sdk.CreateTicketRequest(
                    target_name=target.name,
                    username=user.username,
                )
            ).secret

            # A ticket is presented as the RDP username; the password is unused.
            full_connect(
                "localhost",
                shared_wg.rdp_port,
                f"ticket-{secret}",
                "x",
                timeout,
            )
            assert wait_rdp_session_authorized(api, user.username, timeout), (
                "ticket auth did not produce an authorized session"
            )

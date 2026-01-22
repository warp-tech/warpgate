import requests
from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import WarpgateProcess
from .test_http_common import *  # noqa


class TestHTTPUserAuthTicket:
    def test_auth_password_success(
        self,
        echo_server_port,
        shared_wg: WarpgateProcess,
    ):
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.add_user_role(user.id, role.id, sdk.AddUserRoleRequest(expires_at=None))
            echo_target = api.create_target(sdk.TargetDataRequest(
                name=f"echo-{uuid4()}",
                options=sdk.TargetOptions(sdk.TargetOptionsTargetHTTPOptions(
                    kind="Http",
                    url=f"http://localhost:{echo_server_port}",
                    tls=sdk.Tls(
                        mode=sdk.TlsMode.DISABLED,
                        verify=False,
                    ),
                )),
            ))
            api.add_target_role(echo_target.id, role.id)

            other_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"other-{uuid4()}",
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetHTTPOptions(
                            kind="Http",
                            url="http://badhost",
                            tls=sdk.Tls(
                                mode=sdk.TlsMode.DISABLED,
                                verify=False,
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(other_target.id, role.id)
            secret = api.create_ticket(sdk.CreateTicketRequest(
                target_name=echo_target.name,
                username=user.username,
            )).secret

        # ---

        session = requests.Session()
        session.verify = False

        response = session.get(
            f"{url}/some/path?warpgate-target={echo_target.name}",
            allow_redirects=False,
        )
        assert response.status_code // 100 != 2

        # Ticket as a header
        response = session.get(
            f"{url}/some/path?warpgate-target={echo_target.name}",
            allow_redirects=False,
            headers={
                "Authorization": f"Warpgate {secret}",
            },
        )
        assert response.status_code // 100 == 2
        assert response.json()["path"] == "/some/path"

        # Bad ticket
        response = session.get(
            f"{url}/some/path?warpgate-target={echo_target.name}",
            allow_redirects=False,
            headers={
                "Authorization": f"Warpgate bad{secret}",
            },
        )
        assert response.status_code // 100 != 2

        # Ticket as a GET param
        session = requests.Session()
        session.verify = False
        response = session.get(
            f"{url}/some/path?warpgate-ticket={secret}",
            allow_redirects=False,
        )
        assert response.status_code // 100 == 2
        assert response.json()["path"] == "/some/path"

        # Ensure no access to other targets
        session = requests.Session()
        session.verify = False
        response = session.get(
            f"{url}/some/path?warpgate-ticket={secret}&warpgate-target=admin",
            allow_redirects=False,
        )
        assert response.status_code // 100 == 2

        assert response.json()["path"] == "/some/path"
        response = session.get(
            f"{url}/some/path?warpgate-ticket={secret}&warpgate-target={other_target.name}",
            allow_redirects=False,
        )
        assert response.status_code // 100 == 2
        assert response.json()["path"] == "/some/path"

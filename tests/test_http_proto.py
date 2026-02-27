import requests
from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import WarpgateProcess
from .test_http_common import *  # noqa


class TestHTTPProto:
    @pytest.fixture(scope="session")
    def setup(self, echo_server_port, shared_wg):
        url = f"https://localhost:{shared_wg.http_port}"

        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.add_user_role(user.id, role.id, sdk.AddUserRoleRequest(expires_at=None))
            echo_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"echo-{uuid4()}",
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetHTTPOptions(
                            kind="Http",
                            url=f"http://localhost:{echo_server_port}",
                            tls=sdk.Tls(
                                mode=sdk.TlsMode.DISABLED,
                                verify=False,
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(echo_target.id, role.id)

        yield url, user, echo_target

    def test_cookies(
        self,
        setup,
        shared_wg: WarpgateProcess,
    ):
        url, user, echo_target = setup

        session = requests.Session()
        session.verify = False
        headers = {"Host": f"localhost:{shared_wg.http_port}"}

        session.post(
            f"{url}/@warpgate/api/auth/login",
            json={
                "username": user.username,
                "password": "123",
            },
            headers=headers,
        )

        session.get(
            f"{url}/set-cookie?warpgate-target={echo_target.name}", headers=headers
        )

        cookies = session.cookies.get_dict()
        assert cookies["cookie"] == "value"

    def test_gzip(
        self,
        setup,
        shared_wg: WarpgateProcess,
    ):
        url, user, echo_target = setup

        session = requests.Session()
        session.verify = False
        headers = {"Host": f"localhost:{shared_wg.http_port}"}

        session.post(
            f"{url}/@warpgate/api/auth/login",
            json={
                "username": user.username,
                "password": "123",
            },
            headers=headers,
        )

        response = session.get(
            f"{url}/gzip-response?warpgate-target={echo_target.name}", headers=headers
        )

        assert response.text == 'response', response.text

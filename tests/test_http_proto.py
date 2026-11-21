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
            api.add_user_role(user.id, role.id)
            echo_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"echo-{uuid4()}",
                    require_approval=False,
                    ticket_requests_disabled=False,
                    ticket_require_approval=False,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetHTTPOptions(
                            kind="Http",
                            headers={},
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
        assert response.headers.get("content-encoding") == "gzip"

    def test_embedded_ui_only_in_pages_held_in_memory(
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

        small = session.get(
            f"{url}/page/1000?warpgate-target={echo_target.name}", headers=headers
        )
        assert small.status_code == 200
        assert b'src="/@warpgate/' in small.content

        # Over the 2 MiB embed limit.
        size = 3 * 1024 * 1024
        large = session.get(
            f"{url}/page/{size}?warpgate-target={echo_target.name}", headers=headers
        )
        assert large.status_code == 200
        assert large.headers["content-type"] == "text/html"
        assert large.content == b"<html><head></head><body>" + b"x" * (size - 25)

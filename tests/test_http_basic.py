from urllib.parse import unquote
from uuid import uuid4
import requests

from tests.conftest import WarpgateProcess

from .api_client import admin_client, sdk
from .test_http_common import *  # noqa


class Test:
    def test_basic(
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
            target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"echo-{uuid4()}",
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetHTTPOptions(
                            kind="Http",
                            url=f"http://user:pass@localhost:{echo_server_port}",
                            tls=sdk.Tls(
                                mode=sdk.TlsMode.DISABLED,
                                verify=False,
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(target.id, role.id)

        session = requests.Session()
        session.verify = False

        response = session.get(
            f"{url}/?warpgate-target={target.name}", allow_redirects=False
        )
        assert response.status_code == 307
        redirect = response.headers["location"]
        print(unquote(redirect))
        assert (
            unquote(redirect)
            == f"/@warpgate#/login?next=/?warpgate-target={target.name}"
        )

        response = session.get(f"{url}/@warpgate/api/info").json()
        assert response["username"] is None

        response = session.post(
            f"{url}/@warpgate/api/auth/login",
            json={
                "username": user.username,
                "password": "123",
            },
        )
        assert response.status_code == 201

        response = session.get(f"{url}/@warpgate/api/info").json()
        assert response["username"] == user.username

        response = session.get(
            f"{url}/some/path?a=b&warpgate-target={target.name}&c=d",
            allow_redirects=False,
        )
        assert response.status_code == 200
        assert response.json()["method"] == "GET"
        assert response.json()["path"] == "/some/path"
        assert response.json()["args"]["a"] == "b"
        assert response.json()["args"]["c"] == "d"
        assert ['Authorization', 'Basic dXNlcjpwYXNz'] in response.json()["headers"]

import requests
from uuid import uuid4

from tests.conftest import WarpgateProcess

from .api_client import admin_client, sdk
from .test_http_common import *  # noqa


class Test:
    def test_tls(
        self,
        echo_server_port_https,
        shared_wg: WarpgateProcess,
    ):
        url = f"https://localhost:{shared_wg.http_port}"

        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username="user"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.add_user_role(user.id, role.id)

            target_data = sdk.TargetDataRequest(
                name=f"echo-{uuid4()}",
                options=sdk.TargetOptions(
                    sdk.TargetOptionsTargetHTTPOptions(
                        kind="Http",
                        url=f"https://localhost:{echo_server_port_https}",
                        tls=sdk.Tls(
                            mode=sdk.TlsMode.PREFERRED,
                            verify=False,
                        ),
                    )
                ),
            )
            target = api.create_target(target_data)
            api.add_target_role(target.id, role.id)

            session = requests.Session()
            session.verify = False

            response = session.post(
                f"{url}/@warpgate/api/auth/login",
                json={
                    "username": user.username,
                    "password": "123",
                },
            )
            assert response.status_code == 201

            response = session.get(
                f"{url}/some/path?warpgate-target={target.name}",
                allow_redirects=False,
            )
            assert response.status_code == 200
            assert response.json()["method"] == "GET"

            # -----

            target_data.options.actual_instance.tls.mode = sdk.TlsMode.REQUIRED
            target_data.options.actual_instance.tls.verify = True
            target = api.update_target(target.id, target_data)

            response = session.get(
                f"{url}/some/path?warpgate-target={target.name}",
                allow_redirects=False,
            )
            assert response.status_code == 502  # Should fail

            # -----

            target_data.options.actual_instance.tls.mode = sdk.TlsMode.REQUIRED
            target_data.options.actual_instance.tls.verify = False
            target = api.update_target(target.id, target_data)

            response = session.get(
                f"{url}/some/path?warpgate-target={target.name}",
                allow_redirects=False,
            )
            assert response.status_code == 200

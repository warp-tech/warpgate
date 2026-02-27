import ssl
import requests
from websocket import create_connection
from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import WarpgateProcess
from .test_http_common import *  # noqa


class TestHTTPWebsocket:
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

        session = requests.Session()
        session.verify = False

        session.post(
            f"{url}/@warpgate/api/auth/login",
            json={
                "username": user.username,
                "password": "123",
            },
        )

        cookies = session.cookies.get_dict()
        cookie = "; ".join([f"{k}={v}" for k, v in cookies.items()])
        ws = create_connection(
            f"wss://localhost:{shared_wg.http_port}/socket?warpgate-target={echo_target.name}",
            cookie=cookie,
            sslopt={"cert_reqs": ssl.CERT_NONE},
        )
        ws.send("test")
        assert ws.recv() == "test"
        ws.send_binary(b"test")
        assert ws.recv() == b"test"
        ws.ping()
        ws.close()

import ssl
import requests
from websocket import create_connection
from uuid import uuid4

from .api_client import (
    api_admin_session,
    api_create_target,
    api_create_user,
    api_create_role,
    api_add_role_to_user,
    api_add_role_to_target,
)
from .conftest import WarpgateProcess
from .test_http_common import *  # noqa


class TestHTTPWebsocket:
    def test_basic(
        self,
        echo_server_port,
        shared_wg: WarpgateProcess,
    ):
        url = f"https://localhost:{shared_wg.http_port}"
        with api_admin_session(url) as session:
            role = api_create_role(url, session, {"name": f"role-{uuid4()}"})
            user = api_create_user(
                url,
                session,
                {
                    "username": f"user-{uuid4()}",
                    "credentials": [
                        {
                            "kind": "Password",
                            "hash": "123",
                        },
                    ],
                },
            )
            api_add_role_to_user(url, session, user["id"], role["id"])
            echo_target = api_create_target(
                url,
                session,
                {
                    "name": f"echo-{uuid4()}",
                    "options": {
                        "kind": "Http",
                        "url": f"http://localhost:{echo_server_port}",
                        "tls": {
                            "mode": "Disabled",
                            "verify": False,
                        },
                    },
                },
            )
            api_add_role_to_target(url, session, echo_target["id"], role["id"])

        session = requests.Session()
        session.verify = False

        session.post(
            f"{url}/@warpgate/api/auth/login",
            json={
                "username": user['username'],
                "password": "123",
            },
        )

        cookies = session.cookies.get_dict()
        cookie = "; ".join([f"{k}={v}" for k, v in cookies.items()])
        ws = create_connection(
            f"wss://localhost:{shared_wg.http_port}/socket?warpgate-target={echo_target['name']}",
            cookie=cookie,
            sslopt={"cert_reqs": ssl.CERT_NONE},
        )
        ws.send("test")
        assert ws.recv() == "test"
        ws.send_binary(b"test")
        assert ws.recv() == b"test"
        ws.ping()
        ws.close()

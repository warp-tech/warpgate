from urllib.parse import unquote
from uuid import uuid4
import requests

from tests.conftest import WarpgateProcess

from .api_client import (
    api_admin_session,
    api_create_target,
    api_create_user,
    api_create_role,
    api_add_role_to_user,
    api_add_role_to_target,
)
from .test_http_common import *  # noqa


class Test:
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
                    "username": "user",
                    "credentials": [
                        {
                            "kind": "Password",
                            "hash": "123",
                        }
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

        response = session.get(
            f"{url}/?warpgate-target={echo_target['name']}", allow_redirects=False
        )
        assert response.status_code == 307
        redirect = response.headers["location"]
        print(unquote(redirect))
        assert (
            unquote(redirect)
            == f"/@warpgate#/login?next=/?warpgate-target={echo_target['name']}"
        )

        response = session.get(f"{url}/@warpgate/api/info").json()
        assert response["username"] is None

        response = session.post(
            f"{url}/@warpgate/api/auth/login",
            json={
                "username": user["username"],
                "password": "123",
            },
        )
        assert response.status_code == 201

        response = session.get(f"{url}/@warpgate/api/info").json()
        assert response["username"] == user["username"]

        response = session.get(
            f"{url}/some/path?a=b&warpgate-target={echo_target['name']}&c=d",
            allow_redirects=False,
        )
        assert response.status_code == 200
        assert response.json()["method"] == "GET"
        assert response.json()["path"] == "/some/path"
        assert response.json()["args"]["a"] == "b"
        assert response.json()["args"]["c"] == "d"

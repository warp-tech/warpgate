from base64 import b64decode
from uuid import uuid4
import pytest
import threading

from .api_client import (
    api_add_role_to_target,
    api_add_role_to_user,
    api_admin_session,
    api_create_role,
    api_create_target,
    api_create_user,
)
from .util import alloc_port


@pytest.fixture(scope="session")
def setup_common_definitions(
    echo_server_port,
    otp_key_base64,
):
    def inner(url):
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
            otpuser = api_create_user(
                url,
                session,
                {
                    "username": "userwithotp",
                    "credentials": [
                        {"kind": "Password", "hash": "123"},
                        {"kind": "Totp", "key": list(b64decode(otp_key_base64))},
                    ],
                    "credential_policy": {
                        "http": ["Password", "Totp"],
                    },
                },
            )
            api_add_role_to_user(url, session, user["id"], role["id"])
            api_add_role_to_user(url, session, otpuser["id"], role["id"])
            target = api_create_target(
                url,
                session,
                {
                    "name": "echo",
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
            api_add_role_to_target(url, session, target["id"], role["id"])

    return inner


@pytest.fixture(scope="session")
def echo_server_port():
    from flask import Flask, request, jsonify, redirect
    from flask_sock import Sock

    app = Flask(__name__)
    sock = Sock(app)

    @app.route("/set-cookie")
    def set_cookie():
        response = jsonify({})
        response.set_cookie("cookie", "value")
        return response

    @app.route("/redirect/<path:url>")
    def r(url):
        return redirect(url)

    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def echo(path):
        return jsonify(
            {
                "method": request.method,
                "args": request.args,
                "path": request.path,
            }
        )

    @sock.route("/socket")
    def ws_echo(ws):
        while True:
            data = ws.receive()
            ws.send(data)

    port = alloc_port()

    def runner():
        app.run(port=port, load_dotenv=False)

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()

    yield port

import pytest
import threading

from .util import alloc_port


@pytest.fixture(scope="session")
def echo_server_ports():
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

    port = alloc_port('echoserver http')
    port_https = alloc_port('echoserver https')

    def runner():
        app.run(port=port, load_dotenv=False)
        app.run

    def runner_https():
        app.run(
            port=port_https,
            load_dotenv=False,
            ssl_context=(
                "certs/tls.certificate.pem",
                "certs/tls.key.pem",
            ),
        )
        app.run

    threading.Thread(target=runner, daemon=True).start()
    threading.Thread(target=runner_https, daemon=True).start()

    yield port, port_https


@pytest.fixture(scope="session")
def echo_server_port(echo_server_ports):
    yield echo_server_ports[0]


@pytest.fixture(scope="session")
def echo_server_port_https(echo_server_ports):
    yield echo_server_ports[1]

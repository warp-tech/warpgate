import pytest
import threading

from .util import alloc_port


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
                "headers": request.headers.to_wsgi_list(),
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

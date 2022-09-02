import pytest
import threading
from textwrap import dedent

from .util import alloc_port


@pytest.fixture(scope='session')
def http_common_wg_port(processes, echo_server_port, password_123_hash, otp_key_base64):
    _, wg_ports = processes.start_wg(
        dedent(
            f'''\
            targets:
            -   name: echo
                allow_roles: [role]
                http:
                    url: http://localhost:{echo_server_port}
            -   name: baddomain
                allow_roles: [role]
                http:
                    url: http://localhostfoobar
            -   name: warpgate:admin
                allow_roles: [admin]
                web_admin: {{}}
            users:
            -   username: admin
                roles: [admin, warpgate:admin]
                credentials:
                -   type: password
                    hash: '{password_123_hash}'
            -   username: user
                roles: [role]
                credentials:
                -   type: password
                    hash: '{password_123_hash}'
            -   username: userwithotp
                roles: [role]
                credentials:
                -   type: password
                    hash: '{password_123_hash}'
                -   type: otp
                    key: {otp_key_base64}
                require:
                    http: [password, otp]
            '''
        ),
    )
    yield wg_ports['http']


@pytest.fixture(scope='session')
def echo_server_port():
    from flask import Flask, request, jsonify, redirect
    from flask_sock import Sock
    app = Flask(__name__)
    sock = Sock(app)

    @app.route('/set-cookie')
    def set_cookie():
        response = jsonify({})
        response.set_cookie('cookie', 'value')
        return response

    @app.route('/redirect/<path:url>')
    def r(url):
        return redirect(url)

    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>')
    def echo(path):
        return jsonify({
            'method': request.method,
            'args': request.args,
            'path': request.path,
        })

    @sock.route('/socket')
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

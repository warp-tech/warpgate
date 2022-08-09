import ssl
from textwrap import dedent
import pytest
import requests
import pyotp
from websocket import create_connection

from .util import wait_port


@pytest.fixture(scope='module')
def wg_port(processes, echo_server_port, password_123_hash, otp_key_base64):
    _, wg_ports = processes.start_wg(
        dedent(
            f'''\
            targets:
            -   name: echo
                allow_roles: [role]
                http:
                    url: http://localhost:{echo_server_port}
            users:
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


class TestHTTPProto:
    def test_basic(
        self,
        wg_port,
    ):
        wait_port(wg_port, recv=False)
        session = requests.Session()
        session.verify = False
        url = f'https://localhost:{wg_port}'

        response = session.get(f'{url}/?warpgate-target=echo', allow_redirects=False)
        assert response.status_code == 307
        assert (
            response.headers['location']
            == '/@warpgate#/login?next=%2F%3Fwarpgate%2Dtarget%3Decho'
        )

        response = session.get(f'{url}/@warpgate/api/info').json()
        assert response['username'] is None

        response = session.post(
            f'{url}/@warpgate/api/auth/login',
            json={
                'username': 'user',
                'password': '123',
            },
        )
        assert response.status_code == 201

        response = session.get(f'{url}/@warpgate/api/info').json()
        assert response['username'] == 'user'

        response = session.get(
            f'{url}/some/path?a=b&warpgate-target=echo&c=d', allow_redirects=False
        )
        print(response)
        print(response.text)
        assert response.status_code == 200
        assert response.json()['method'] == 'GET'
        assert response.json()['path'] == '/some/path'
        assert response.json()['args']['a'] == 'b'
        assert response.json()['args']['c'] == 'd'


class TestHTTPUserAuthPassword:
    def test_auth_password_success(
        self,
        wg_port,
    ):
        wait_port(wg_port, recv=False)
        session = requests.Session()
        session.verify = False
        url = f'https://localhost:{wg_port}'

        response = session.get(f'{url}/?warpgate-target=echo', allow_redirects=False)
        assert response.status_code // 100 != 2

        response = session.post(
            f'{url}/@warpgate/api/auth/login',
            json={
                'username': 'user',
                'password': '123',
            },
        )
        assert response.status_code // 100 == 2

        response = session.get(
            f'{url}/some/path?a=b&warpgate-target=echo&c=d', allow_redirects=False
        )
        assert response.status_code // 100 == 2
        assert response.json()['path'] == '/some/path'

    def test_auth_password_fail(
        self,
        wg_port,
    ):
        wait_port(wg_port, recv=False)
        session = requests.Session()
        session.verify = False
        url = f'https://localhost:{wg_port}'

        response = session.post(
            f'{url}/@warpgate/api/auth/login',
            json={
                'username': 'user',
                'password': '321321',
            },
        )
        assert response.status_code // 100 != 2

        response = session.get(
            f'{url}/some/path?a=b&warpgate-target=echo&c=d', allow_redirects=False
        )
        assert response.status_code // 100 != 2


class TestHTTPUserAuthOTP:
    def test_auth_otp_success(
        self,
        wg_port,
        otp_key_base32,
    ):
        wait_port(wg_port, recv=False)
        session = requests.Session()
        session.verify = False
        url = f'https://localhost:{wg_port}'

        totp = pyotp.TOTP(otp_key_base32)

        response = session.post(
            f'{url}/@warpgate/api/auth/login',
            json={
                'username': 'userwithotp',
                'password': '123',
            },
        )
        assert response.status_code // 100 != 2

        response = session.get(
            f'{url}/some/path?a=b&warpgate-target=echo&c=d', allow_redirects=False
        )
        assert response.status_code // 100 != 2

        response = session.post(
            f'{url}/@warpgate/api/auth/otp',
            json={
                'otp': totp.now(),
            },
        )
        assert response.status_code // 100 == 2

        response = session.get(
            f'{url}/some/path?a=b&warpgate-target=echo&c=d', allow_redirects=False
        )
        assert response.status_code // 100 == 2
        assert response.json()['path'] == '/some/path'

    def test_auth_otp_fail(
        self,
        wg_port,
    ):
        wait_port(wg_port, recv=False)
        session = requests.Session()
        session.verify = False
        url = f'https://localhost:{wg_port}'

        response = session.post(
            f'{url}/@warpgate/api/auth/login',
            json={
                'username': 'userwithotp',
                'password': '123',
            },
        )
        assert response.status_code // 100 != 2

        response = session.post(
            f'{url}/@warpgate/api/auth/otp',
            json={
                'otp': '00000000',
            },
        )
        assert response.status_code // 100 != 2

        response = session.get(
            f'{url}/some/path?a=b&warpgate-target=echo&c=d', allow_redirects=False
        )
        assert response.status_code // 100 != 2


class TestHTTPWebsocket:
    def test_basic(
        self,
        wg_port,
    ):
        wait_port(wg_port, recv=False)
        session = requests.Session()
        session.verify = False
        url = f'https://localhost:{wg_port}'

        session.post(
            f'{url}/@warpgate/api/auth/login',
            json={
                'username': 'user',
                'password': '123',
            },
        )

        cookies = session.cookies.get_dict()
        cookie = '; '.join([f'{k}={v}' for k, v in cookies.items()])
        ws = create_connection(
            f'wss://localhost:{wg_port}/socket?warpgate-target=echo',
            cookie=cookie,
            sslopt={"cert_reqs": ssl.CERT_NONE},
        )
        ws.send('test')
        assert ws.recv() == 'test'
        ws.send_binary(b'test')
        assert ws.recv() == b'test'
        ws.ping()
        ws.close()

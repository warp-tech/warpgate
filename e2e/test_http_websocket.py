import ssl
import requests
from websocket import create_connection


from .util import wait_port


class TestHTTPWebsocket:
    def test_basic(
        self,
        http_common_wg_port,
    ):
        wait_port(http_common_wg_port, recv=False)
        session = requests.Session()
        session.verify = False
        url = f'https://localhost:{http_common_wg_port}'

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
            f'wss://localhost:{http_common_wg_port}/socket?warpgate-target=echo',
            cookie=cookie,
            sslopt={"cert_reqs": ssl.CERT_NONE},
        )
        ws.send('test')
        assert ws.recv() == 'test'
        ws.send_binary(b'test')
        assert ws.recv() == b'test'
        ws.ping()
        ws.close()

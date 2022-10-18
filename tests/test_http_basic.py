import requests

from .test_http_common import *  # noqa
from .util import wait_port


class Test:
    def test_basic(
        self,
        http_common_wg_port_api_based,
    ):
        wait_port(http_common_wg_port_api_based, recv=False)
        url = f'https://localhost:{http_common_wg_port_api_based}'

        session = requests.Session()
        session.verify = False

        response = session.get(f'{url}/?warpgate-target=echo', allow_redirects=False)
        assert response.status_code == 307
        redirect = response.headers['location']
        assert redirect == '/@warpgate#/login?next=%2F%3Fwarpgate%2Dtarget%3Decho'

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
        assert response.status_code == 200
        assert response.json()['method'] == 'GET'
        assert response.json()['path'] == '/some/path'
        assert response.json()['args']['a'] == 'b'
        assert response.json()['args']['c'] == 'd'

import requests

from .test_http_common import *  # noqa
from .util import wait_port


class TestHTTPRedirects:
    def test(
        self,
        http_common_wg_port_api_based,
        echo_server_port,
    ):
        wait_port(http_common_wg_port_api_based, recv=False)
        session = requests.Session()
        session.verify = False
        url = f'https://localhost:{http_common_wg_port_api_based}'
        headers = {'Host': f'localhost:{http_common_wg_port_api_based}'}

        session.post(
            f'{url}/@warpgate/api/auth/login',
            json={
                'username': 'user',
                'password': '123',
            },
            headers=headers,
        )

        response = session.get(f'{url}/redirect/http://localhost:{echo_server_port}/test?warpgate-target=echo', headers=headers, allow_redirects=False)
        print(response.headers)

        assert response.headers['location'] == '/test'

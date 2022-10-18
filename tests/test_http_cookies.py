import requests

from .test_http_common import *  # noqa
from .util import wait_port


class TestHTTPCookies:
    def test(
        self,
        http_common_wg_port_api_based,
    ):
        wait_port(http_common_wg_port_api_based, recv=False)
        url = f'https://localhost:{http_common_wg_port_api_based}'

        session = requests.Session()
        session.verify = False
        headers = {'Host': f'localhost:{http_common_wg_port_api_based}'}

        session.post(
            f'{url}/@warpgate/api/auth/login',
            json={
                'username': 'user',
                'password': '123',
            },
            headers=headers,
        )

        response = session.get(
            f'{url}/set-cookie?warpgate-target=echo', headers=headers
        )
        print(response.headers)

        cookies = session.cookies.get_dict()
        assert cookies['cookie'] == 'value'

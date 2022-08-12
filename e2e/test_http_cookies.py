import requests


from .util import wait_port


class TestHTTPCookies:
    def test(
        self,
        http_common_wg_port,
    ):
        wait_port(http_common_wg_port, recv=False)
        session = requests.Session()
        session.verify = False
        url = f'https://localhost:{http_common_wg_port}'
        headers = {'Host': f'localhost:{http_common_wg_port}'}

        session.post(
            f'{url}/@warpgate/api/auth/login',
            json={
                'username': 'user',
                'password': '123',
            },
            headers=headers,
        )

        response = session.get(f'{url}/set-cookie?warpgate-target=echo', headers=headers)
        print(response.headers)

        cookies = session.cookies.get_dict()
        assert cookies['cookie'] == 'value'

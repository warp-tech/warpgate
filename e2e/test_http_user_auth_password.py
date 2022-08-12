import requests


from .util import wait_port


class TestHTTPUserAuthPassword:
    def test_auth_password_success(
        self,
        http_common_wg_port,
    ):
        wait_port(http_common_wg_port, recv=False)
        session = requests.Session()
        session.verify = False
        url = f'https://localhost:{http_common_wg_port}'

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
        http_common_wg_port,
    ):
        wait_port(http_common_wg_port, recv=False)
        session = requests.Session()
        session.verify = False
        url = f'https://localhost:{http_common_wg_port}'

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

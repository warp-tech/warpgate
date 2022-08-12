import requests


from .util import wait_port


class TestHTTPUserAuthTicket:
    def test_auth_password_success(
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
                'username': 'admin',
                'password': '123',
            },
        )
        assert response.status_code // 100 == 2
        response = session.post(
            f'{url}/@warpgate/admin/api/tickets',
            json={
                'username': 'user',
                'target_name': 'echo',
            },
        )
        assert response.status_code == 201
        secret = response.json()['secret']

        # ---

        session = requests.Session()
        session.verify = False

        response = session.get(
            f'{url}/some/path?warpgate-target=echo',
            allow_redirects=False,
        )
        assert response.status_code // 100 != 2

        # Ticket as a header
        response = session.get(
            f'{url}/some/path?warpgate-target=echo',
            allow_redirects=False,
            headers={
                'Authorization': f'Warpgate {secret}',
            },
        )
        assert response.status_code // 100 == 2
        assert response.json()['path'] == '/some/path'

        # Ticket as a GET param
        session = requests.Session()
        session.verify = False
        response = session.get(
            f'{url}/some/path?warpgate-ticket={secret}',
            allow_redirects=False,
        )
        assert response.status_code // 100 == 2
        assert response.json()['path'] == '/some/path'

        # Ensure no access to other targets
        session = requests.Session()
        session.verify = False
        response = session.get(
            f'{url}/some/path?warpgate-ticket={secret}&warpgate-target=admin',
            allow_redirects=False,
        )
        assert response.status_code // 100 == 2
        assert response.json()['path'] == '/some/path'

import requests

from .util import create_ticket, wait_port


class TestHTTPUserAuthTicket:
    def test_auth_password_success(
        self,
        http_common_wg_port,
    ):
        wait_port(http_common_wg_port, recv=False)
        url = f'https://localhost:{http_common_wg_port}'

        secret = create_ticket(url, 'user', 'echo')

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

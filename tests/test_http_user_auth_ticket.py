import requests

from .api_client import api_admin_session, api_create_ticket
from .test_http_common import *  # noqa
from .util import wait_port


class TestHTTPUserAuthTicket:
    def test_auth_password_success(
        self,
        http_common_wg_port_api_based,
    ):
        wait_port(http_common_wg_port_api_based, recv=False)
        url = f'https://localhost:{http_common_wg_port_api_based}'

        with api_admin_session(url) as session:
            secret = api_create_ticket(url, session, 'user', 'echo')

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

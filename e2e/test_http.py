from textwrap import dedent
import pytest
import requests
from .util import wait_port


@pytest.fixture(scope='class')
def wg_port(processes, echo_server_port, password_123_hash):
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
            '''
        ),
    )
    yield wg_ports['http']


class Test:
    def test(
        self, wg_port,
    ):
        wait_port(wg_port, recv=False)
        session = requests.Session()
        session.verify = False
        url = f'https://localhost:{wg_port}'

        response = session.get(f'{url}/?warpgate-target=echo', allow_redirects=False)
        assert response.status_code == 307
        assert response.headers['location'] == '/@warpgate#/login?next=%2F%3Fwarpgate%2Dtarget%3Decho'

        response = session.get(f'{url}/@warpgate/api/info').json()
        assert response['username'] is None

        response = session.post(f'{url}/@warpgate/api/auth/login', json={
            'username': 'user',
            'password': '123',
        })
        assert response.status_code == 201

        response = session.get(f'{url}/@warpgate/api/info').json()
        assert response['username'] == 'user'

        response = session.get(f'{url}/some/path?a=b&warpgate-target=echo&c=d', allow_redirects=False)
        assert response.json()['method'] == 'GET'
        assert response.json()['path'] == '/some/path'
        assert response.json()['args']['a'] == 'b'
        assert response.json()['args']['c'] == 'd'

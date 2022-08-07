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
            -   name: http
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
        response = session.get(f'{url}/?warpgate_target=http', allow_redirects=False)
        assert response.status_code == 307
        assert response.headers['location'] == '/@warpgate#/login?next=%2F%3Fwarpgate%5Ftarget%3Dhttp'

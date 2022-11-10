import subprocess
from textwrap import dedent

from .conftest import ProcessManager
from .util import wait_port, wait_mysql_port, mysql_client_ssl_opt, mysql_client_opts


class Test:
    def test(self, processes: ProcessManager, password_123_hash, timeout):
        db_port = processes.start_mysql_server()

        with processes.start_wg(
            dedent(
                f'''\
                targets:
                -   name: db
                    allow_roles: [role]
                    mysql:
                        host: localhost
                        port: {db_port}
                        user: root
                        password: '123'
                users:
                -   username: user
                    roles: [role]
                    credentials:
                    -   type: password
                        hash: '{password_123_hash}'
                '''
            ),
        ) as (_, wg_ports):
            wait_mysql_port(db_port)
            wait_port(wg_ports['mysql'])

            client = processes.start(
                [
                    'mysql',
                    '--user',
                    'user#db',
                    '-p123',
                    '--host',
                    '127.0.0.1',
                    '--port',
                    str(wg_ports["mysql"]),
                    *mysql_client_opts,
                    mysql_client_ssl_opt,
                    'db',
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
            )
            assert b'\ndb\n' in client.communicate(b'show schemas;', timeout=timeout)[0]
            assert client.returncode == 0

            client = processes.start(
                [
                    'mysql',
                    '--user',
                    'user:db',
                    '-pwrong',
                    '--host',
                    '127.0.0.1',
                    '--port',
                    str(wg_ports["mysql"]),
                    *mysql_client_opts,
                    mysql_client_ssl_opt,
                    'db',
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
            )
            client.communicate(b'show schemas;', timeout=timeout)
            assert client.returncode != 0

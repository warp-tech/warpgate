from pathlib import Path
from textwrap import dedent

from .conftest import ProcessManager
from .util import create_ticket, wait_port


class Test:
    def test(
        self, processes: ProcessManager, wg_c_ed25519_pubkey: Path, password_123_hash, timeout
    ):
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )

        with processes.start_wg(
            dedent(
                f'''\
                targets:
                -   name: ssh
                    allow_roles: [role]
                    ssh:
                        host: localhost
                        port: {ssh_port}
                -   name: warpgate:admin
                    allow_roles: [admin]
                    web_admin: {{}}
                users:
                -   username: user
                    roles: [role]
                    credentials:
                    -   type: password
                        hash: '{password_123_hash}'
                -   username: admin
                    roles: [warpgate:admin]
                    credentials:
                    -   type: password
                        hash: '{password_123_hash}'
                '''
            ),
        ) as (_, wg_ports):
            wait_port(ssh_port)
            wait_port(wg_ports['ssh'])
            wait_port(wg_ports['http'], recv=False)

            url = f'https://localhost:{wg_ports["http"]}'
            secret = create_ticket(url, 'user', 'ssh')

            ssh_client = processes.start_ssh_client(
                f'ticket-{secret}@localhost',
                '-p',
                str(wg_ports['ssh']),
                '-i',
                '/dev/null',
                '-o',
                'PreferredAuthentications=password',
                'ls',
                '/bin/sh',
                password='123',
            )
            assert ssh_client.communicate(timeout=timeout)[0] == b'/bin/sh\n'
            assert ssh_client.returncode == 0

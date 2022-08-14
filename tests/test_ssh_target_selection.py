from pathlib import Path
from textwrap import dedent

from .conftest import ProcessManager
from .util import wait_port


class Test:
    def test_bad_target(
        self, processes: ProcessManager, wg_c_ed25519_pubkey: Path, password_123_hash
    ):
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )

        _, wg_ports = processes.start_wg(
            dedent(
                f'''\
                targets:
                -   name: ssh
                    allow_roles: [role]
                    ssh:
                        host: localhost
                        port: {ssh_port}
                users:
                -   username: user
                    roles: [role]
                    credentials:
                    -   type: password
                        hash: '{password_123_hash}'
                '''
            ),
        )

        wait_port(ssh_port)
        wait_port(wg_ports['ssh'])

        ssh_client = processes.start_ssh_client(
            '-t',
            'user:badtarget@localhost',
            '-p',
            str(wg_ports['ssh']),
            '-i',
            '/dev/null',
            '-o',
            'PreferredAuthentications=password',
            'echo',
            'hello',
            password='123',
        )

        assert ssh_client.returncode != 0
